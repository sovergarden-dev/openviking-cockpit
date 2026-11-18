"""Plan-first, stdlib-only OpenViking storage hygiene auditor (`--dry-run` by default).

Audits four strictly bounded scopes without touching protected baselines (`ov.conf`, `backups/pre-*`,
`preferences`, `entities`, `patterns`, `cases`, `experiences`, `profile.md`, or active sessions):
  1. `quarantine`      : Stale items already isolated inside `backups/quarantine/`.
  2. `monitor-scratch` : One-off underscore diagnostic scripts/JSON (`_*.py`, `_*.json`) inside `monitor/`.
  3. `cron-sessions`   : Inactive automated `cron_*` raw session directories older than `--min-age-days`.
  4. `tick-events`     : Automated per-tick / batch-commit receipt `.md` files inside `events/` (API-deleted on apply
                         after archiving a local backup copy so VikingDB vectors stay synchronized).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

VALID_SCOPES = ("quarantine", "monitor-scratch", "cron-sessions", "tick-events")

PROTECTED_BACKUP_PREFIXES = (
    "pre-",
    "cleanup-mem-",
    "live_safe_memories",
    "mem-phase1-",
    "monitor-json-recovery",
)

TICK_NAME_RE = re.compile(
    r"(?i)(?:^sc[-_]?cron[-_]\d+|"
    r"^commit[\s_-]+(?:da|do|de)[\s_-]+(?:cena|liga[cç][aã]o|tradu[cç][aã]o|di[aá]logo|lote)(?:[\s_-]|$)|"
    r"^commit[\s_-]+(?:batch|lote)(?:[\s_-]|$)|"
    r"^confirma[cç][aã]o[\s_-]+do[\s_-]+commit[\s_-]+do[\s_-]+lote|"
    r"^conclus[aã]o[\s_-]+da[\s_-]+tradu[cç][aã]o[\s_-]+do[\s_-]+segmento|"
    r"^tradu[cç][aã]o[\s_-]+mensagem[\s_-]+lucy|^yarn[\s_-]+dialogue[\s_-]+|"
    r"^translation[\s_-]+progress[\s_-]+update(?:[\s_-]|$)|"
    r"(?:^|[\s_-])batch(?:[\s_-]).*\d+[ªa]?\s*execu[cç][aã]o)"
)

MILESTONE_KEEP_RE = re.compile(
    r"(?i)(?:migra[cç][aã]o|cad[eê]ncia|pipeline|handoff|corpus|gloss[aá]rio|"
    r"embedding[\s_-]+model|cleanup[\s_-]+button|role[\s_-]+column|failback|"
    r"OpenViking|decis[aã]o|decision|misread|reporting[\s_-]+policy|"
    r"phase[\s_-]*\d|purged|pruned|atualiza[cç][aã]o|limpeza|manuten[cç][aã]o|"
    r"cockpit[\s_-]*rs|taxonomy[\s_-]*v3|release|installer|instala[cç][aã]o|"
    r"corre[cç][aã]o|fixed|complete|completed|conclus[aã]o[\s_-]+da[\s_-]+(?:localiza[cç][aã]o|tradu[cç][aã]o)|"
    r"approved|paused|resumed|switch|swap|ativa[cç][aã]o|redirecionamento|redu[cç][aã]o)"
)


def is_reparse_point(path: Path) -> bool:
    try:
        st = path.lstat()
    except OSError:
        return True
    if path.is_symlink():
        return True
    return bool(getattr(st, "st_file_attributes", 0) & 0x0400)


def dir_stats_and_latest_mtime(root: Path) -> tuple[int, int, float]:
    files = 0
    total_bytes = 0
    latest_mtime = 0.0
    try:
        latest_mtime = root.lstat().st_mtime
    except OSError:
        return 0, 0, 0.0

    stack = [root]
    while stack:
        cur = stack.pop()
        if is_reparse_point(cur):
            continue
        try:
            with os.scandir(cur) as it:
                for entry in it:
                    p = Path(entry.path)
                    if is_reparse_point(p):
                        continue
                    try:
                        st = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if st.st_mtime > latest_mtime:
                        latest_mtime = st.st_mtime
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(p)
                    elif entry.is_file(follow_symlinks=False):
                        files += 1
                        total_bytes += st.st_size
        except OSError:
            continue
    return files, total_bytes, latest_mtime


def is_tick_event_markdown(rel_posix: str, text: str) -> bool:
    parts = rel_posix.split("/")
    if "events" not in parts:
        return False
    name = parts[-1]
    if name.startswith(".") or name == "profile.md":
        return False
    stem = name[:-3] if name.lower().endswith(".md") else name
    if MILESTONE_KEEP_RE.search(stem) or MILESTONE_KEEP_RE.search(rel_posix):
        return False
    if TICK_NAME_RE.search(stem):
        return True
    if stem.startswith("mem_") and len(text) < 4_000 and re.search(r"(?i)\bsc-cron-\d+\b", text):
        return True
    return False


def compute_plan_digest(candidates_by_scope: dict[str, list[dict]]) -> str:
    canonical = json.dumps(candidates_by_scope, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def scan_hygiene(ov_home: Path, min_age_days: float = 3.0, now_ts: float | None = None) -> dict:
    now = now_ts if now_ts is not None else time.time()
    min_age_s = max(0.0, float(min_age_days)) * 86_400.0

    candidates: dict[str, list[dict]] = {s: [] for s in VALID_SCOPES}
    protected_baselines: list[str] = []

    backups_dir = ov_home / "backups"
    if backups_dir.is_dir() and not is_reparse_point(backups_dir):
        for child in sorted(backups_dir.iterdir(), key=lambda p: p.name):
            if any(child.name.startswith(pref) for pref in PROTECTED_BACKUP_PREFIXES):
                protected_baselines.append(child.name)

    # 1. quarantine
    quar_dir = backups_dir / "quarantine"
    if quar_dir.is_dir() and not is_reparse_point(quar_dir):
        for child in sorted(quar_dir.iterdir(), key=lambda p: p.name):
            if is_reparse_point(child):
                continue
            if any(child.name.startswith(pref) for pref in PROTECTED_BACKUP_PREFIXES):
                continue
            if child.is_dir():
                fc, sz, _ = dir_stats_and_latest_mtime(child)
                candidates["quarantine"].append(
                    {"rel_path": f"backups/quarantine/{child.name}", "kind": "dir", "files": fc, "bytes": sz}
                )
            elif child.is_file():
                sz = child.stat().st_size
                candidates["quarantine"].append(
                    {"rel_path": f"backups/quarantine/{child.name}", "kind": "file", "files": 1, "bytes": sz}
                )

    # 2. monitor-scratch (`monitor/_*.py`, `monitor/_*.json`)
    mon_dir = ov_home / "monitor"
    if mon_dir.is_dir() and not is_reparse_point(mon_dir):
        for child in sorted(mon_dir.iterdir(), key=lambda p: p.name):
            if not child.is_file() or is_reparse_point(child):
                continue
            if child.name.startswith("_") and child.suffix.lower() in (".py", ".json"):
                candidates["monitor-scratch"].append(
                    {
                        "rel_path": f"monitor/{child.name}",
                        "kind": "file",
                        "files": 1,
                        "bytes": child.stat().st_size,
                    }
                )

    # 3 & 4. data-qwen06b cron-sessions and tick-events
    data_dir = ov_home / "data-qwen06b"
    user_default = data_dir / "viking" / "default" / "user" / "default"
    sess_dir = user_default / "sessions"
    if sess_dir.is_dir() and not is_reparse_point(sess_dir):
        for child in sorted(sess_dir.iterdir(), key=lambda p: p.name):
            if not child.is_dir() or is_reparse_point(child):
                continue
            low = child.name.lower()
            if not (low.startswith("cron_") or low.startswith("cron-")):
                continue
            if any(child.glob("*.lock")):
                continue
            fc, sz, latest_mtime = dir_stats_and_latest_mtime(child)
            if (now - latest_mtime) < min_age_s:
                continue
            rel = child.relative_to(ov_home).as_posix()
            candidates["cron-sessions"].append(
                {
                    "rel_path": rel,
                    "session_id": child.name,
                    "kind": "dir",
                    "files": fc,
                    "bytes": sz,
                    "age_days": round((now - latest_mtime) / 86_400.0, 2),
                }
            )

    mem_roots: list[tuple[Path, str]] = [
        (user_default / "memories", "viking://user/default/memories"),
    ]
    peers_dir = user_default / "peers"
    if peers_dir.is_dir() and not is_reparse_point(peers_dir):
        for peer in sorted(peers_dir.iterdir(), key=lambda p: p.name):
            if peer.is_dir() and not is_reparse_point(peer):
                mem_roots.append(
                    (peer / "memories", f"viking://user/default/peers/{peer.name}/memories")
                )

    for mem_root, uri_base in mem_roots:
        ev_dir = mem_root / "events"
        if not ev_dir.is_dir() or is_reparse_point(ev_dir):
            continue
        for md_file in sorted(ev_dir.rglob("*.md")):
            if not md_file.is_file() or is_reparse_point(md_file):
                continue
            rel_to_mem = md_file.relative_to(mem_root).as_posix()
            try:
                txt = md_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if is_tick_event_markdown(rel_to_mem, txt):
                candidates["tick-events"].append(
                    {
                        "rel_path": md_file.relative_to(ov_home).as_posix(),
                        "uri": f"{uri_base}/{rel_to_mem}",
                        "kind": "indexed_memory",
                        "files": 1,
                        "bytes": md_file.stat().st_size,
                    }
                )

    summary_by_scope = {}
    for sc in VALID_SCOPES:
        items = candidates[sc]
        total_b = sum(int(i["bytes"]) for i in items)
        total_f = sum(int(i["files"]) for i in items)
        summary_by_scope[sc] = {
            "items": len(items),
            "files": total_f,
            "bytes": total_b,
            "mib": round(total_b / (1024 * 1024), 2),
        }

    digest = compute_plan_digest(candidates)
    return {
        "schema_version": 1,
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ov_home": str(ov_home),
        "min_age_days": min_age_days,
        "protected_baselines_verified": protected_baselines,
        "plan_sha256": digest,
        "summary": summary_by_scope,
        "candidates": candidates,
    }


def _assert_safe_child(ov_home: Path, rel_path: str) -> Path:
    if not rel_path or ".." in rel_path.replace("\\", "/").split("/"):
        raise ValueError(f"Unsafe relative path in plan: {rel_path!r}")
    norm = rel_path.replace("\\", "/").lstrip("/")
    if norm == "ov.conf" or norm.startswith("backups/pre-"):
        raise PermissionError(f"Refusing to touch protected path: {norm}")
    full = (ov_home / norm).resolve()
    root_resolved = ov_home.resolve()
    if root_resolved not in full.parents:
        raise ValueError(f"Resolved path escapes ov_home: {full}")
    return full


def apply_hygiene_plan(
    ov_home: Path,
    plan_doc: dict,
    scopes: list[str],
    ov_url: str = "http://127.0.0.1:19330",
) -> dict:
    for sc in scopes:
        if sc not in VALID_SCOPES:
            raise ValueError(f"Unknown scope {sc!r}; valid scopes: {VALID_SCOPES}")

    expected_sha = plan_doc.get("plan_sha256")
    candidates = plan_doc.get("candidates") or {}
    actual_sha = compute_plan_digest({s: candidates.get(s, []) for s in VALID_SCOPES})
    if not expected_sha or expected_sha != actual_sha:
        raise ValueError("Plan SHA-256 verification failed; re-run --dry-run to generate a fresh plan")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    results: dict[str, dict] = {}

    if "quarantine" in scopes:
        removed_items = 0
        reclaimed_bytes = 0
        for item in candidates.get("quarantine", []):
            target = _assert_safe_child(ov_home, item["rel_path"])
            if not target.exists() or is_reparse_point(target):
                continue
            reclaimed_bytes += int(item.get("bytes", 0))
            if target.is_dir():
                shutil.rmtree(target)
            else:
                target.unlink()
            removed_items += 1
        results["quarantine"] = {"removed_items": removed_items, "reclaimed_bytes": reclaimed_bytes}

    if "monitor-scratch" in scopes:
        archive_dir = ov_home / "backups" / "monitor-scratch-archive" / stamp
        moved = 0
        for item in candidates.get("monitor-scratch", []):
            target = _assert_safe_child(ov_home, item["rel_path"])
            if not target.is_file() or is_reparse_point(target):
                continue
            archive_dir.mkdir(parents=True, exist_ok=True)
            shutil.move(str(target), str(archive_dir / target.name))
            moved += 1
        results["monitor-scratch"] = {"archived_files": moved, "archive_dir": str(archive_dir)}

    if "cron-sessions" in scopes:
        removed_sessions = 0
        reclaimed_bytes = 0
        for item in candidates.get("cron-sessions", []):
            target = _assert_safe_child(ov_home, item["rel_path"])
            if not target.is_dir() or is_reparse_point(target):
                continue
            if any(target.glob("*.lock")):
                continue
            reclaimed_bytes += int(item.get("bytes", 0))
            shutil.rmtree(target)
            removed_sessions += 1
        results["cron-sessions"] = {
            "removed_sessions": removed_sessions,
            "reclaimed_bytes": reclaimed_bytes,
        }

    if "tick-events" in scopes:
        archive_dir = ov_home / "backups" / "tick-events-archive" / stamp
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        deleted = 0
        errors = 0
        for item in candidates.get("tick-events", []):
            target = _assert_safe_child(ov_home, item["rel_path"])
            uri = str(item.get("uri") or "")
            if not target.is_file() or not uri.startswith("viking://"):
                continue
            archive_dest = archive_dir / item["rel_path"]
            archive_dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, archive_dest)

            q_uri = urllib.parse.quote(uri, safe="")
            hdrs = {}
            if uri.startswith("viking://user/default/peers/"):
                rest = uri[len("viking://user/default/peers/") :]
                peer_id = rest.split("/", 1)[0]
                if peer_id:
                    hdrs["X-OpenViking-Actor-Peer"] = peer_id
            req = urllib.request.Request(
                f"{ov_url.rstrip('/')}/api/v1/fs?uri={q_uri}&wait=true",
                headers=hdrs,
                method="DELETE",
            )
            try:
                with opener.open(req, timeout=10.0) as resp:
                    if 200 <= resp.status < 300:
                        deleted += 1
                    else:
                        errors += 1
            except Exception:
                errors += 1
        results["tick-events"] = {
            "api_deleted": deleted,
            "errors": errors,
            "backup_archive_dir": str(archive_dir),
        }

    return {"applied_utc": stamp, "scopes": scopes, "results": results}


def main(argv: list[str] | None = None) -> int:
    default_home = Path(os.environ.get("USERPROFILE") or Path.home()) / ".openviking"
    parser = argparse.ArgumentParser(description="Audit or clean OpenViking storage safely.")
    parser.add_argument("--ov-home", type=Path, default=default_home)
    parser.add_argument("--min-age-days", type=float, default=3.0)
    parser.add_argument("--plan-file", type=Path, default=None, help="Path to write (dry-run) or read (apply) JSON plan")
    parser.add_argument(
        "--scope",
        default="",
        help="Comma-separated scopes for --apply: quarantine,monitor-scratch,cron-sessions,tick-events",
    )
    parser.add_argument("--ov-url", default="http://127.0.0.1:19330")
    parser.add_argument("--apply", action="store_true", help="Execute planned cleanup for --scope (requires --plan-file)")
    args = parser.parse_args(argv)

    if not args.apply:
        plan = scan_hygiene(args.ov_home, min_age_days=args.min_age_days)
        if args.plan_file:
            args.plan_file.parent.mkdir(parents=True, exist_ok=True)
            args.plan_file.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        compact = {
            "mode": "dry_run",
            "ov_home": plan["ov_home"],
            "min_age_days": plan["min_age_days"],
            "protected_baselines_verified": plan["protected_baselines_verified"],
            "plan_sha256": plan["plan_sha256"],
            "plan_file": str(args.plan_file) if args.plan_file else None,
            "summary": plan["summary"],
        }
        print(json.dumps(compact, ensure_ascii=False, indent=2))
        return 0

    if not args.plan_file or not args.plan_file.is_file():
        parser.error("--apply requires an existing --plan-file produced by --dry-run")
    scopes = [s.strip() for s in args.scope.split(",") if s.strip()]
    if not scopes:
        parser.error("--apply requires at least one --scope")

    plan_doc = json.loads(args.plan_file.read_text(encoding="utf-8"))
    receipt = apply_hygiene_plan(args.ov_home, plan_doc, scopes=scopes, ov_url=args.ov_url)
    print(json.dumps(receipt, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
