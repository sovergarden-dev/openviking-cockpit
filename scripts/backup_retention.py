"""Plan-first, safe backup retention and inventory utility for OpenViking.

Provides:
- Read-only inventory and dry-run by default. Requires --apply to execute.
- Protected pins: Never deletes memory cleanup archives, pre-upgrade cold backups, autostart XMLs, quarantined files, or the most recent N configuration/sync/monitor-state snapshots.
- Non-destructive quarantine: Moves expired snapshots to a quarantine subdirectory instead of unlinking.
- Strict path confinement: Operates strictly within ~/.openviking/backups.
"""
from __future__ import annotations

import argparse
import datetime
import json
import shutil
import sys
from pathlib import Path
from typing import Dict, List

DEFAULT_BACKUP_DIR = Path.home() / ".openviking" / "backups"

PERMANENTLY_PROTECTED_PATTERNS = [
    "pre-",
    "cleanup-mem-",
    "OpenViking-Autostart-",
    "CONTAMINATED",
    ".REJECTED",
    "live_safe_memories_",
    "mem-phase",
    "monitor-json-recovery",
    "quarantine",
]


def is_protected_by_pattern(name: str) -> bool:
    return any(pat in name for pat in PERMANENTLY_PROTECTED_PATTERNS)


def is_sha256_dir_name(name: str) -> bool:
    return len(name) == 64 and all(c in "0123456789abcdefABCDEF" for c in name)


def scan_backups(
    backup_dir: Path, keep_recent: int = 10, keep_monitor_state: int = 30
) -> Dict[str, object]:
    if not backup_dir.is_dir():
        return {"error": f"Directory not found: {backup_dir}", "candidates": [], "protected": []}

    categories: Dict[str, List[Path]] = {
        "ov_conf_snapshots": [],
        "monitor_sync_snapshots": [],
        "protected_archives": [],
        "other": [],
    }

    for item in backup_dir.iterdir():
        name = item.name
        if name == "monitor-state" and item.is_dir():
            continue
        if is_protected_by_pattern(name):
            categories["protected_archives"].append(item)
        elif name.startswith("ov.conf-before-"):
            categories["ov_conf_snapshots"].append(item)
        elif name.startswith("monitor-sync-"):
            categories["monitor_sync_snapshots"].append(item)
        else:
            categories["other"].append(item)

    for key in ["ov_conf_snapshots", "monitor_sync_snapshots", "other"]:
        categories[key].sort(key=lambda p: p.stat().st_mtime, reverse=True)

    kept: List[Path] = list(categories["protected_archives"])
    candidates: List[Path] = []

    for key in ["ov_conf_snapshots", "monitor_sync_snapshots"]:
        snaps = categories[key]
        kept.extend(snaps[:keep_recent])
        candidates.extend(snaps[keep_recent:])

    kept.extend(categories["other"])

    mon_state_root = backup_dir / "monitor-state"
    mon_state_kept: List[Path] = []
    mon_state_candidates: List[Path] = []
    if mon_state_root.is_dir() and not mon_state_root.is_symlink():
        sha_dirs = [
            d
            for d in mon_state_root.iterdir()
            if d.is_dir() and not d.is_symlink() and is_sha256_dir_name(d.name)
        ]
        sha_dirs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        mon_state_kept = sha_dirs[:keep_monitor_state]
        mon_state_candidates = sha_dirs[keep_monitor_state:]

    all_candidates = candidates + mon_state_candidates
    return {
        "backup_dir": str(backup_dir),
        "total_items": sum(len(v) for v in categories.values()),
        "monitor_state_total": len(mon_state_kept) + len(mon_state_candidates),
        "protected_count": len(kept),
        "monitor_state_kept_count": len(mon_state_kept),
        "candidates_count": len(all_candidates),
        "kept": [p.name for p in kept],
        "candidates": [
            {
                "name": p.relative_to(backup_dir).as_posix(),
                "is_dir": p.is_dir(),
                "size_bytes": (
                    sum(f.stat().st_size for f in p.rglob("*") if f.is_file())
                    if p.is_dir()
                    else p.stat().st_size
                ),
                "mtime": datetime.datetime.fromtimestamp(p.stat().st_mtime).isoformat(),
            }
            for p in all_candidates
        ],
    }


def apply_quarantine(backup_dir: Path, rel_candidates: List[str]) -> Dict[str, object]:
    quarantine_dir = backup_dir / "quarantine"
    quarantine_dir.mkdir(parents=True, exist_ok=True)

    moved = []
    errors = []
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    batch_dir = quarantine_dir / f"batch-{stamp}"
    batch_dir.mkdir(parents=True, exist_ok=True)

    resolved_root = backup_dir.resolve()
    for rel in rel_candidates:
        src = (backup_dir / rel).resolve()
        if resolved_root not in src.parents or not src.exists():
            continue
        if is_protected_by_pattern(src.name):
            continue
        dest = batch_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.move(str(src), str(dest))
            moved.append(rel)
        except Exception as exc:
            errors.append({"rel_path": rel, "error": str(exc)})

    manifest = {
        "stamp": stamp,
        "moved_count": len(moved),
        "moved": moved,
        "errors": errors,
    }
    (batch_dir / "quarantine-manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--backup-dir", type=Path, default=DEFAULT_BACKUP_DIR, help="Path to backups directory"
    )
    parser.add_argument(
        "--keep-recent",
        type=int,
        default=10,
        help="Number of recent ov.conf/monitor-sync snapshots to preserve per category",
    )
    parser.add_argument(
        "--keep-monitor-state",
        type=int,
        default=30,
        help="Number of recent monitor-state SHA-256 directories to preserve",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Execute non-destructive quarantine move (default: dry-run plan only)",
    )
    args = parser.parse_args()

    plan = scan_backups(
        args.backup_dir,
        keep_recent=max(1, args.keep_recent),
        keep_monitor_state=max(1, args.keep_monitor_state),
    )
    print(json.dumps(plan, indent=2))

    if args.apply:
        candidates = plan.get("candidates", [])
        rel_paths = [c["name"] for c in candidates if isinstance(c, dict) and "name" in c]
        if not rel_paths:
            print("No candidates to quarantine.")
            return 0
        receipt = apply_quarantine(args.backup_dir, rel_paths)
        print("\n--- QUARANTINE APPLIED ---")
        print(json.dumps(receipt, indent=2))
    else:
        print(
            f"\n[PLAN ONLY] {plan.get('candidates_count', 0)} candidates identified. Pass --apply to quarantine."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
