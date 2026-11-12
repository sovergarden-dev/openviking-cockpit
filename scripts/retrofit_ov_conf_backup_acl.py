"""Plan-first ACL retrofit for legacy top-level ov.conf-before-* backup files.

When --plan-file is supplied (requires --apply), it acts as a strict drift assertion
against a fresh live scan (with mandatory sddl_sha256 on every row); both plan_file
and its immediate parent are rejected if either is a reparse point, and any added,
removed, or modified target aborts fail-closed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

MONITOR_DIR = Path(__file__).resolve().parents[1] / "monitor"
if str(MONITOR_DIR) not in sys.path:
    sys.path.insert(0, str(MONITOR_DIR))

from safe_write import apply_restricted_file_acl  # noqa: E402

DEFAULT_BACKUP_DIR = Path.home() / ".openviking" / "backups"


def _has_reparse_point(path: Path) -> bool:
    info = path.lstat()
    return path.is_symlink() or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _sddl_digest(sddl: str) -> str:
    return hashlib.sha256(sddl.encode("utf-8")).hexdigest()


def _file_sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _read_acl(paths: list[Path]) -> dict[str, dict]:
    if not paths:
        return {}
    if os.name != "nt":
        raise OSError("ACL inspection requires Windows")
    resolved = [str(p.resolve()) for p in paths]
    ps = r"""
$ErrorActionPreference = 'Stop'
# UTF8 (not UTF-8): hyphen form throws under $ErrorActionPreference='Stop'.
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$paths = ConvertFrom-Json ([Console]::In.ReadToEnd())
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$expected = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;$sid)"
$items = @()
foreach ($p in @($paths)) {
    $acl = Get-Acl -LiteralPath $p
    $sddl = $acl.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access)
    $items += @{
        path = $p
        protected = [bool]$acl.AreAccessRulesProtected
        exact_dacl = (($sddl -replace '^D:PAI', 'D:P') -eq $expected)
        sddl_access = $sddl
    }
}
ConvertTo-Json -Compress -Depth 3 -InputObject @{ items = @($items) }
"""
    res = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps],
        input=json.dumps(resolved),
        capture_output=True, text=True, encoding="utf-8", timeout=30,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if res.returncode != 0:
        # Never include res.stderr: PowerShell error text can expose raw SDDL/SID strings.
        raise RuntimeError(f"PowerShell ACL read failed (exit {res.returncode})")
    raw = json.loads(res.stdout.lstrip("\ufeff"))
    items = raw.get("items") if isinstance(raw, dict) else None
    if not isinstance(items, list) or len(items) != len(resolved):
        raise RuntimeError("Unexpected ACL response length from PowerShell")
    out: dict[str, dict] = {}
    for expected_path, entry in zip(resolved, items):
        if not isinstance(entry, dict) or os.path.normcase(str(entry.get("path") or "")) != os.path.normcase(expected_path):
            raise RuntimeError("ACL response path alignment mismatch from PowerShell")
        out[expected_path] = entry
    return out


def build_plan(backup_dir: Path) -> dict:
    if os.name != "nt":
        raise OSError("ACL retrofit requires Windows")
    if not backup_dir.exists() or _has_reparse_point(backup_dir):
        raise ValueError(f"Unsafe backup directory (reparse or missing): {backup_dir}")
    root = backup_dir.resolve()
    if not root.is_dir() or _has_reparse_point(root):
        raise ValueError(f"Unsafe backup directory: {backup_dir}")
    targets: list[Path] = []
    skipped_protected: list[str] = []
    for entry in sorted(root.iterdir()):
        if not entry.name.startswith("ov.conf-before-"):
            continue
        if _has_reparse_point(entry):
            raise ValueError(f"Unsafe reparse point target: {entry.name}")
        if not entry.is_file():
            continue
        if not entry.resolve().is_relative_to(root):
            raise ValueError(f"Unsafe target outside backup root: {entry.name}")
        if not entry.name.endswith(".json") or ".REJECTED" in entry.name or "CONTAMINATED" in entry.name:
            skipped_protected.append(entry.name)
            continue
        targets.append(entry)
    acls = _read_acl(targets)
    rows = []
    for entry in targets:
        st = entry.stat()
        key = str(entry.resolve())
        acl = acls[key]
        rows.append({
            "name": entry.name,
            "path": key,
            "size": st.st_size,
            "mtime_ns": st.st_mtime_ns,
            "sha256": _file_sha256(entry),
            "protected": acl["protected"],
            "exact_dacl": acl["exact_dacl"],
            "sddl_sha256": _sddl_digest(acl["sddl_access"]),
            "needs_harden": not (acl["protected"] and acl["exact_dacl"]),
        })
    return {
        "mode": "PLAN_ONLY",
        "utc": datetime.now(timezone.utc).isoformat(),
        "backup_dir": str(root),
        "total": len(rows),
        "needs_harden": sum(1 for r in rows if r["needs_harden"]),
        "skipped_protected": skipped_protected,
        "files": rows,
    }


def _load_reviewed_plan(plan_file: Path, backup_dir: Path, meta: dict[str, str] | None = None) -> dict:
    try:
        is_reparse = _has_reparse_point(plan_file) or _has_reparse_point(plan_file.parent)
    except OSError as exc:
        raise ValueError(f"Unreadable plan file: {plan_file.name}") from exc
    if is_reparse:
        raise ValueError(f"Unsafe reparse point plan file: {plan_file.name}")
    if not plan_file.is_file():
        raise ValueError(f"Plan file is not a regular file: {plan_file.name}")
    raw_bytes = plan_file.read_bytes()
    plan_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    if meta is not None:
        meta["plan_sha256"] = plan_sha256
    try:
        data = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Malformed plan JSON: {plan_file.name}") from exc
    if not isinstance(data, dict) or data.get("mode") != "PLAN_ONLY":
        raise ValueError("Reviewed plan must be a JSON object with mode == 'PLAN_ONLY'")
    root = backup_dir.resolve()
    raw_dir = data.get("backup_dir")
    if not isinstance(raw_dir, str) or os.path.normcase(str(Path(raw_dir).resolve())) != os.path.normcase(str(root)):
        raise ValueError("Reviewed plan backup_dir does not match target --backup-dir")
    files = data.get("files")
    if not isinstance(files, list) or data.get("total") != len(files):
        raise ValueError("Reviewed plan files/total metadata is invalid")
    root_norm = Path(os.path.normcase(str(root)))
    for row in files:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str) or not isinstance(row.get("name"), str):
            raise ValueError("Reviewed plan entry is malformed")
        sddl_sha = row.get("sddl_sha256")
        if not isinstance(sddl_sha, str) or len(sddl_sha) != 64:
            raise ValueError(f"Reviewed plan entry missing valid sddl_sha256: {row['name']}")
        candidate = Path(row["path"])
        if not Path(os.path.normcase(str(candidate.resolve()))).is_relative_to(root_norm):
            raise ValueError(f"Reviewed plan entry outside target backup_dir: {row['name']}")
    fresh = build_plan(backup_dir)
    if data.get("skipped_protected") != fresh["skipped_protected"]:
        raise RuntimeError("Plan drift detected in skipped_protected; regenerate plan before --apply")
    def _proj(items: list[dict]) -> list[tuple]:
        return [
            (
                r.get("name"),
                os.path.normcase(str(r.get("path") or "")),
                r.get("size"),
                r.get("mtime_ns"),
                r.get("sha256"),
                r.get("needs_harden"),
                r.get("sddl_sha256"),
            )
            for r in items
        ]
    if _proj(files) != _proj(fresh["files"]):
        raise RuntimeError("Plan drift detected against live backup directory; regenerate plan before --apply")
    return fresh


def _safe_write_receipt(receipt_path: Path | None, payload: dict) -> None:
    if receipt_path is None:
        return
    try:
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"warning: failed to write receipt ({type(exc).__name__})", file=sys.stderr)


def apply_retrofit(
    backup_dir: Path,
    receipt_path: Path | None = None,
    plan_file: Path | None = None,
) -> dict:
    plan_meta: dict[str, str] = {}
    try:
        plan = _load_reviewed_plan(plan_file, backup_dir, plan_meta) if plan_file is not None else build_plan(backup_dir)
    except (Exception, KeyboardInterrupt) as exc:  # Load-bearing re-raise: record APPLY_ABORTED without swallowing errors or interrupts.
        aborted = {
            "mode": "APPLY_ABORTED",
            "utc": datetime.now(timezone.utc).isoformat(),
            "backup_dir": str(backup_dir),
            "hardened_count": 0,
            "hardened_names": [],
            "error_class": type(exc).__name__,
            "error": str(exc),
        }
        if "plan_sha256" in plan_meta:
            aborted["plan_sha256"] = plan_meta["plan_sha256"]
        _safe_write_receipt(receipt_path, aborted)
        raise

    plan_sha256 = plan_meta.get("plan_sha256")

    rows = plan["files"]
    needs = [r for r in rows if r["needs_harden"]]
    applied: list[str] = []
    try:
        for row in needs:
            target = Path(row["path"])
            if _has_reparse_point(target):
                raise ValueError(f"Unsafe reparse point before apply: {target.name}")
            if _file_sha256(target) != row["sha256"]:
                raise RuntimeError(f"Pre-apply hash drift on {target.name}")
            if not apply_restricted_file_acl(target):
                raise PermissionError(f"Failed to restrict ACL on {target.name}")
            st = target.stat()
            if _file_sha256(target) != row["sha256"]:
                raise RuntimeError(f"Post-apply hash mismatch on {target.name}")
            if st.st_size != row["size"] or st.st_mtime_ns != row["mtime_ns"]:
                raise RuntimeError(f"Post-apply size/mtime mismatch on {target.name}")
            applied.append(target.name)

        post_acls = _read_acl([Path(r["path"]) for r in rows])
        for row in rows:
            post = post_acls[row["path"]]
            if not (post["protected"] and post["exact_dacl"]):
                raise RuntimeError(f"Post-apply ACL verification failed on {row['name']}")
            row["protected_after"] = post["protected"]
            row["exact_dacl_after"] = post["exact_dacl"]
            row["sddl_after_sha256"] = _sddl_digest(post["sddl_access"])
    except (Exception, KeyboardInterrupt) as exc:  # Load-bearing re-raise: record APPLY_PARTIAL without swallowing errors or interrupts.
        partial = {
            "mode": "APPLY_PARTIAL",
            "utc": datetime.now(timezone.utc).isoformat(),
            "backup_dir": plan["backup_dir"],
            "total": len(rows),
            "hardened_count": len(applied),
            "hardened_names": applied,
            "skipped_protected": plan["skipped_protected"],
            "error_class": type(exc).__name__,
            "error": str(exc),
            "files": rows,
        }
        if plan_sha256 is not None:
            partial["plan_sha256"] = plan_sha256
        _safe_write_receipt(receipt_path, partial)
        raise

    out = {
        "mode": "APPLIED",
        "utc": datetime.now(timezone.utc).isoformat(),
        "backup_dir": plan["backup_dir"],
        "total": len(rows),
        "hardened_count": len(applied),
        "hardened_names": applied,
        "skipped_protected": plan["skipped_protected"],
        "all_sha256_size_mtime_unchanged": True,
        "all_protected_exact_dacl": True,
        "files": rows,
    }
    if plan_sha256 is not None:
        out["plan_sha256"] = plan_sha256
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup-dir", type=Path, default=DEFAULT_BACKUP_DIR)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--plan-file", type=Path, default=None)
    parser.add_argument("--receipt", type=Path, default=None)
    args = parser.parse_args(argv)
    if args.plan_file is not None and not args.apply:
        parser.error("--plan-file requires --apply")

    result = (
        apply_retrofit(args.backup_dir, receipt_path=args.receipt, plan_file=args.plan_file)
        if args.apply
        else build_plan(args.backup_dir)
    )
    payload = json.dumps(result, ensure_ascii=True, indent=2) + "\n"
    if args.receipt:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(payload, encoding="utf-8")
    summary = {k: v for k, v in result.items() if k != "files"}
    print(json.dumps(summary, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
