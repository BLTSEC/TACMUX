"""Copy shell-handler session logs (penelope and similar) into the engagement."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import sys
import tempfile
from typing import Iterable

from .errors import SafetyError

SIZE_LIMIT = 100 * 1024 * 1024


def _session_matches(name: str, endpoint: str) -> bool:
    """penelope names sessions host~IP-OS-arch, or IP-OS-arch without a host."""
    tail = name.rsplit("~", 1)[-1]
    return bool(endpoint) and (tail == endpoint or tail.startswith(f"{endpoint}-"))


def _tool_name(base: Path) -> str:
    # ~/.penelope/sessions -> "penelope"; any other directory -> its own name.
    parent = base.parent.name.lstrip(".")
    return parent if base.name == "sessions" and parent else base.name.lstrip(".")


def _wanted(relative: Path) -> bool:
    if relative.parts and relative.parts[0] == "downloads":
        return True
    return len(relative.parts) == 1 and relative.suffix == ".log"


def _private_dirs(path: Path, stop: Path) -> None:
    missing = []
    current = path
    while current != stop and not current.exists():
        missing.append(current)
        current = current.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)
    if path.is_symlink():
        raise SafetyError(f"refusing linked directory: {path}")


def _copy(source: Path, destination: Path, stop: Path) -> bool:
    """Copy when new or changed (size or mtime); owner-only; never via symlinks."""
    info = source.stat()
    if destination.exists():
        if destination.is_symlink():
            raise SafetyError(f"refusing linked file: {destination}")
        current = destination.stat()
        if (current.st_size, current.st_mtime_ns) == (info.st_size, info.st_mtime_ns):
            return False
    _private_dirs(destination.parent, stop)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    os.close(descriptor)
    try:
        shutil.copy2(source, temporary)
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    return True


def _local_offsets(session: Path) -> str:
    """UTC offsets in effect when the logs were written (DST-aware)."""
    offsets = sorted(
        {
            datetime.fromtimestamp(path.stat().st_mtime).astimezone().strftime("%z")
            for path in session.glob("*.log")
            if path.is_file() and not path.is_symlink()
        }
    )
    return ", ".join(offsets) or datetime.now().astimezone().strftime("%z")


def _write_readme(destination: Path, session: Path, tool: str) -> None:
    note = destination / "README.txt"
    if note.is_symlink():
        raise SafetyError(f"refusing linked file: {note}")
    text = (
        f"Copied by TACMUX from {session}\n"
        f"Last refreshed {datetime.now(timezone.utc).isoformat()}\n"
        f"{tool} timestamps are local time (UTC offset {_local_offsets(session)}).\n"
    )
    descriptor, temporary = tempfile.mkstemp(prefix=".README.", dir=destination)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(text)
        os.chmod(temporary, 0o600)
        os.replace(temporary, note)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def collect_shell_logs(
    root: Path, route: str, endpoint: str, directories: Iterable[Path]
) -> list[Path]:
    """Copy matching session logs and downloads to captures/<route>/shells/."""
    shells = root / "captures" / route / "shells"
    copied: list[Path] = []
    for base in directories:
        if not base.is_dir() or base.is_symlink():
            continue
        tool = _tool_name(base)
        for session in sorted(base.iterdir()):
            if session.is_symlink() or not session.is_dir():
                continue
            if not _session_matches(session.name, endpoint):
                continue
            destination = shells / tool / session.name
            for source in sorted(session.rglob("*")):
                relative = source.relative_to(session)
                if source.is_symlink() or not source.is_file() or not _wanted(relative):
                    continue
                if source.stat().st_size > SIZE_LIMIT:
                    print(
                        f"tacmux: skipped {source} (larger than 100 MiB)",
                        file=sys.stderr,
                    )
                    continue
                if _copy(source, destination / relative, root):
                    copied.append(destination / relative)
            if destination.is_dir():
                _write_readme(destination, session, tool)
    return copied
