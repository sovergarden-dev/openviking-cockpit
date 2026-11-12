"""Plan-first ACL retrofit for legacy top-level ov.conf-before-* backup files."""
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


def _read_acl(paths: list[Path]) -> dict[str, dict]:
    if not paths:
        return {}
    if os.name != "nt":
        raise OSError("ACL inspection requires Windows")
    resolved = [str(p.resolve()) for p in paths]
    ps = r"""
$ErrorActionPreference = 'Stop'
$paths = ConvertFrom-Json ([Console]::In.ReadToEnd())
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$expected = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;$sid)"
$rows = @{}
foreach ($p in $paths) {
    $acl = Get-Acl -LiteralPath $p
    $sddl = $acl.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access)
    $rows[$p] = @{
        protected = [bool]$acl.AreAccessRulesProtected
        exact_dacl = (($sddl -replace '^D:PAI', 'D:P') -eq $expected)
        sddl_access = $sddl
    }
}
ConvertTo-Json -Compress -Depth 3 -InputObject $rows
"""
    res = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps],
        input=json.dumps(resolved),
        capture_output=True, text=True, encoding="utf-8", timeout=30, check=True,
    )
    raw = json.loads(res.stdout)
    if not isinstance(raw, dict):
        raise RuntimeError(f"Unexpected ACL response type: {type(raw).__name__}")
    lower_map = {k.lower(): v for k, v in raw.items()}
    out: dict[str, dict] = {}
    for p in resolved:
        entry = raw.get(p) if p in raw else lower_map.get(p.lower())
        if entry is None:
            raise RuntimeError(f"ACL readback missing for {p}")
        out[p] = entry
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
            "sha256": hashlib.sha256(entry.read_bytes()).hexdigest(),
            "protected": acl["protected"],
            "exact_dacl": acl["exact_dacl"],
            "sddl_access": acl["sddl_access"],
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


def apply_retrofit(backup_dir: Path, receipt_path: Path | None = None) -> dict:
    plan = build_plan(backup_dir)
    rows = plan["files"]
    needs = [r for r in rows if r["needs_harden"]]
    applied: list[str] = []
    try:
        for row in needs:
            target = Path(row["path"])
            if _has_reparse_point(target):
                raise ValueError(f"Unsafe reparse point before apply: {target.name}")
            if hashlib.sha256(target.read_bytes()).hexdigest() != row["sha256"]:
                raise RuntimeError(f"Pre-apply hash drift on {target.name}")
            if not apply_restricted_file_acl(target):
                raise PermissionError(f"Failed to restrict ACL on {target.name}")
            st = target.stat()
            if hashlib.sha256(target.read_bytes()).hexdigest() != row["sha256"]:
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
            row["sddl_after"] = post["sddl_access"]
    except Exception as exc:
        if receipt_path is not None:
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
            receipt_path.parent.mkdir(parents=True, exist_ok=True)
            receipt_path.write_text(json.dumps(partial, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        raise

    return {
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup-dir", type=Path, default=DEFAULT_BACKUP_DIR)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--receipt", type=Path, default=None)
    args = parser.parse_args(argv)

    result = apply_retrofit(args.backup_dir, receipt_path=args.receipt) if args.apply else build_plan(args.backup_dir)
    payload = json.dumps(result, ensure_ascii=True, indent=2) + "\n"
    if args.receipt:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(payload, encoding="utf-8")
    summary = {k: v for k, v in result.items() if k != "files"}
    print(json.dumps(summary, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
