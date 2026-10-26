"""Plan-first, safe backup retention and inventory utility for OpenViking.

Provides:
- Read-only inventory and dry-run by default. Requires --apply to execute.
- Protected pins: Never deletes memory cleanup archives, autostart XMLs, quarantined files,
  or the most recent N configuration/sync snapshots.
- Non-destructive quarantine: Moves expired snapshots to a quarantine subdirectory instead of unlinking.
- Strict path confinement: Operates strictly within ~/.openviking/backups.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

DEFAULT_BACKUP_DIR = Path.home() / ".openviking" / "backups"

# Patterns that are permanently protected from retention pruning
PERMANENTLY_PROTECTED_PATTERNS = [
    "cleanup-mem-",
    "OpenViking-Autostart-",
    "CONTAMINATED",
    "live_safe_memories_",
    "mem-phase",
    "monitor-json-recovery",
    "quarantine",
]

def is_protected_by_pattern(name: str) -> bool:
    """Check if file or directory name matches permanent retention protection."""
    return any(pat in name for pat in PERMANENTLY_PROTECTED_PATTERNS)


def scan_backups(backup_dir: Path, keep_recent: int = 10) -> Dict[str, list]:
    """Scan backup directory and categorize into protected, active, and purge candidates."""
    if not backup_dir.is_dir():
        return {"error": f"Directory not found: {backup_dir}", "candidates": [], "protected": []}

    categories: Dict[str, List[Path]] = {
        "ov_conf_snapshots": [],
        "monitor_sync_snapshots": [],
        "protected_archives": [],
        "other": []
    }

    for item in backup_dir.iterdir():
        name = item.name
        if is_protected_by_pattern(name):
            categories["protected_archives"].append(item)
        elif name.startswith("ov.conf-before-"):
            categories["ov_conf_snapshots"].append(item)
        elif name.startswith("monitor-sync-"):
            categories["monitor_sync_snapshots"].append(item)
        else:
            categories["other"].append(item)

    # Sort snapshots newest first by modification time
    for key in ["ov_conf_snapshots", "monitor_sync_snapshots", "other"]:
        categories[key].sort(key=lambda p: p.stat().st_mtime, reverse=True)

    kept: List[Path] = list(categories["protected_archives"])
    candidates: List[Path] = []

    # Apply keep_recent quota per snapshot category
    for key in ["ov_conf_snapshots", "monitor_sync_snapshots"]:
        snaps = categories[key]
        kept.extend(snaps[:keep_recent])
        candidates.extend(snaps[keep_recent:])

    # Other files default to kept unless explicitly categorized
    kept.extend(categories["other"])

    return {
        "backup_dir": str(backup_dir),
        "total_items": sum(len(v) for v in categories.values()),
        "protected_count": len(kept),
        "candidates_count": len(candidates),
        "kept": [p.name for p in kept],
        "candidates": [
            {
                "name": p.name,
                "is_dir": p.is_dir(),
                "size_bytes": sum(f.stat().st_size for f in p.rglob('*') if f.is_file()) if p.is_dir() else p.stat().st_size,
                "mtime": datetime.datetime.fromtimestamp(p.stat().st_mtime).isoformat()
            }
            for p in candidates
        ]
    }


def apply_quarantine(backup_dir: Path, candidates: List[str]) -> Dict[str, object]:
    """Move retention candidates into backups/quarantine directory non-destructively."""
    quarantine_dir = backup_dir / "quarantine"
    quarantine_dir.mkdir(parents=True, exist_ok=True)

    moved = []
    errors = []
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    batch_dir = quarantine_dir / f"batch-{stamp}"
    batch_dir.mkdir(parents=True, exist_ok=True)

    for name in candidates:
        src = backup_dir / name
        if not src.exists():
            continue
        dest = batch_dir / name
        try:
            shutil.move(str(src), str(dest))
            moved.append(name)
        except Exception as e:
            errors.append({"name": name, "error": str(e)})

    manifest = {
        "stamp": stamp,
        "moved_count": len(moved),
        "moved": moved,
        "errors": errors
    }
    (batch_dir / "quarantine-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup-dir", type=Path, default=DEFAULT_BACKUP_DIR, help="Path to backups directory")
    parser.add_argument("--keep-recent", type=int, default=10, help="Number of recent snapshots to preserve per category")
    parser.add_argument("--apply", action="store_true", help="Execute non-destructive quarantine move (default: dry-run plan only)")
    args = parser.parse_args()

    plan = scan_backups(args.backup_dir, keep_recent=args.keep_recent)
    print(json.dumps(plan, indent=2))

    if args.apply:
        candidate_names = [c["name"] for c in plan.get("candidates", [])]
        if not candidate_names:
            print("No candidates to quarantine.")
            return 0
        receipt = apply_quarantine(args.backup_dir, candidate_names)
        print("\n--- QUARANTINE APPLIED ---")
        print(json.dumps(receipt, indent=2))
    else:
        print(f"\n[PLAN ONLY] {plan.get('candidates_count', 0)} candidates identified. Pass --apply to quarantine.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
