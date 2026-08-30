"""Minimal public CLI and hidden tmux/job entrypoints."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import sys
from typing import Sequence

from . import __version__
from .archive import verify_archive
from .config import load_settings
from .discovery import run_job
from .errors import TacmuxError
from .hooks import LogController, clipboard_copy, status_segment
from .store import Workspace
from .tmux import TmuxService


USAGE = """TACMUX — operator-first engagement workspaces for tmux

Usage:
  tacmux                         Open the interactive operator cockpit
  tacmux health                  Check configuration and external tools
  tacmux archive verify FILE     Verify an archive and every member hash
  tacmux version                 Print the version
"""


def _health() -> int:
    settings = load_settings()
    tmux = TmuxService(settings)
    checks: list[tuple[str, bool, str]] = []
    checks.append(("Python", sys.version_info >= (3, 11), sys.version.split()[0]))
    checks.append(("tmux", tmux.available(), tmux.version()))
    checks.append(
        (
            "workspace",
            settings.workspace.is_dir() and os.access(settings.workspace, os.W_OK),
            str(settings.workspace),
        )
    )
    invalid = Workspace(settings).invalid_engagements()
    checks.append(
        (
            "engagement manifests",
            not invalid,
            "valid" if not invalid else f"{len(invalid)} invalid",
        )
    )
    checks.append(
        (
            "archive directory",
            settings.archive_dir.is_dir() and os.access(settings.archive_dir, os.W_OK),
            str(settings.archive_dir),
        )
    )
    checks.append(
        (
            "Nmap host discovery",
            shutil.which("nmap") is not None,
            shutil.which("nmap") or "optional; import remains available",
        )
    )
    checks.append(
        (
            "NOCAP",
            not settings.nocap_enabled or shutil.which("cap") is not None,
            "disabled"
            if not settings.nocap_enabled
            else (shutil.which("cap") or "enabled but missing"),
        )
    )
    editor = settings.editor_argv[0]
    checks.append(
        ("editor", shutil.which(editor) is not None, " ".join(settings.editor_argv))
    )
    print(f"TACMUX {__version__}\n")
    for label, ok, detail in checks:
        print(f"[{'ok' if ok else '--'}] {label:22} {detail}")
    for manifest, problem in invalid:
        print(f"     invalid: {manifest}: {problem}")
    print(f"\nConfig: {settings.config_file}")
    return (
        0
        if all(ok for label, ok, _ in checks if label not in {"Nmap host discovery"})
        else 1
    )


def _internal(args: Sequence[str]) -> int:
    if not args:
        raise TacmuxError("missing internal command")
    settings = load_settings()
    tmux = TmuxService(settings)
    command, *rest = args
    if command == "run-job":
        if len(rest) != 1:
            raise TacmuxError("run-job requires one job file")
        return run_job(settings, Path(rest[0]))
    if command == "clip":
        return clipboard_copy(tmux, sys.stdin.buffer.read())
    if command == "status-segment":
        print(status_segment(settings, tmux), end="")
        return 0
    if command == "log":
        if not rest:
            raise TacmuxError("log requires an action")
        action, *parameters = rest
        pane = parameters[0] if parameters else os.environ.get("TMUX_PANE", "")
        controller = LogController(settings, tmux)
        if action == "start":
            controller.start(pane)
        elif action == "force":
            controller.start(
                pane, force=True, kind=parameters[1] if len(parameters) > 1 else "pane"
            )
        elif action == "stop":
            controller.stop(pane)
        elif action == "toggle":
            controller.toggle(pane)
        elif action == "capture":
            controller.capture(pane)
        elif action == "status":
            print(controller.status(pane))
        else:
            raise TacmuxError(f"unknown log action: {action}")
        return 0
    raise TacmuxError(f"unknown internal command: {command}")


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if not args:
            if not sys.stdin.isatty() or not sys.stdout.isatty():
                print(
                    "tacmux: the interactive cockpit requires a terminal",
                    file=sys.stderr,
                )
                return 2
            from .app import TacmuxApp

            settings = load_settings()
            result = TacmuxApp(settings).run()
            return TmuxService(settings).attach(result) if result is not None else 0
        if args[0] in {"version", "--version", "-v"}:
            print(f"tacmux {__version__}")
            return 0
        if args[0] in {"help", "--help", "-h"}:
            print(USAGE, end="")
            return 0
        if args == ["health"]:
            return _health()
        if len(args) == 3 and args[:2] == ["archive", "verify"]:
            document = verify_archive(Path(args[2]))
            print(f"Verified: {args[2]}")
            print(f"SHA-256: {document['archive']['sha256']}")
            print(f"Files: {document['contents']['file_count']}")
            return 0
        if args[0] == "_internal":
            return _internal(args[1:])
        print(USAGE, file=sys.stderr, end="")
        return 2
    except (TacmuxError, OSError, ValueError, KeyError) as exc:
        print(f"tacmux: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
