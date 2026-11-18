"""Atomic installer for the `openviking-memory` Antigravity plugin (`~/.gemini/config/plugins/openviking-memory`)."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

PLUGIN_NAME = "openviking-memory"
REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_BUNDLE = REPO_ROOT / "integrations" / "antigravity" / PLUGIN_NAME


def default_target_dir() -> Path:
    home = Path(os.environ.get("USERPROFILE") or Path.home())
    return home / ".gemini" / "config" / "plugins" / PLUGIN_NAME


def default_python_exe() -> Path:
    local_app = os.environ.get("LOCALAPPDATA")
    if local_app:
        cand = Path(local_app) / "Programs" / "Python" / "Python311" / "python.exe"
        if cand.is_file():
            return cand
    return Path(sys.executable)


def build_mcp_config(python_exe: Path, bridge_script: Path, ov_url: str, actor_peer: str) -> dict:
    return {
        "mcpServers": {
            PLUGIN_NAME: {
                "command": str(python_exe),
                "args": ["-X", "utf8", "-u", str(bridge_script)],
                "env": {
                    "OPENVIKING_BASE_URL": ov_url,
                    "OPENVIKING_ACTOR_PEER": actor_peer,
                },
            }
        }
    }


def _atomic_write_bytes(dst: Path, data: bytes) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.parent / f".{dst.name}.tmp-{os.getpid()}"
    try:
        tmp.write_bytes(data)
        os.replace(tmp, dst)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def install_plugin(
    target_dir: Path,
    python_exe: Path,
    ov_url: str = "http://127.0.0.1:19330",
    actor_peer: str = "antigravity",
    apply: bool = False,
) -> dict:
    if not SOURCE_BUNDLE.is_dir():
        raise FileNotFoundError(f"Plugin source bundle missing: {SOURCE_BUNDLE}")
    if not python_exe.is_file():
        raise FileNotFoundError(f"Python executable not found: {python_exe}")

    bridge_dst = target_dir / "scripts" / "ov_mcp_bridge.py"
    mcp_cfg = build_mcp_config(python_exe, bridge_dst, ov_url, actor_peer)

    # Write plugin.json last so live watchers see a complete bundle upon manifest discovery.
    source_files = sorted(
        (p for p in SOURCE_BUNDLE.rglob("*") if p.is_file()),
        key=lambda p: (p.name == "plugin.json", p.as_posix()),
    )
    summary = {
        "plugin": PLUGIN_NAME,
        "source": str(SOURCE_BUNDLE),
        "target_dir": str(target_dir),
        "python_exe": str(python_exe),
        "files_count": len(source_files) + 1,
        "applied": apply,
    }
    if not apply:
        return summary

    target_dir.mkdir(parents=True, exist_ok=True)
    # Clean any stale staging directories from interrupted runs if unlocked.
    for leftover in target_dir.parent.glob(f".{PLUGIN_NAME}-staging-*"):
        if leftover.is_dir():
            shutil.rmtree(leftover, ignore_errors=True)

    mcp_bytes = (json.dumps(mcp_cfg, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    _atomic_write_bytes(target_dir / "mcp_config.json", mcp_bytes)

    for src_file in source_files:
        rel = src_file.relative_to(SOURCE_BUNDLE)
        _atomic_write_bytes(target_dir / rel, src_file.read_bytes())

    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Install the openviking-memory Antigravity plugin.")
    parser.add_argument("--target-dir", type=Path, default=default_target_dir())
    parser.add_argument("--python-exe", type=Path, default=default_python_exe())
    parser.add_argument("--ov-url", default="http://127.0.0.1:19330")
    parser.add_argument("--actor-peer", default="antigravity")
    parser.add_argument("--apply", action="store_true", help="Write plugin bundle to target-dir (default is dry-run)")
    args = parser.parse_args(argv)

    result = install_plugin(
        target_dir=args.target_dir,
        python_exe=args.python_exe,
        ov_url=args.ov_url,
        actor_peer=args.actor_peer,
        apply=args.apply,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
