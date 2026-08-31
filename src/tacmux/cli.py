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
from .context import resolve
from .discovery import DiscoveryJobs, run_job
from .errors import ConflictError, TacmuxError
from .export import create_handoff, parse_export_profile
from .hooks import LogController, clipboard_copy, status_segment
from .model import ActivityResult, EngagementStatus
from .render import render_sitrep
from .store import EngagementRecord, Workspace
from .tmux import TmuxService


USAGE = """TACMUX — operator-first engagement workspaces for tmux

Usage:
  tacmux                         Open the interactive operator cockpit
  tacmux health                  Check configuration and external tools
  tacmux note TEXT...            Append a note in the current TACMUX session
  tacmux activity RESULT [--evidence PATH] TEXT...
                                 Record confirmed, failed, or no-result activity
  tacmux sitrep                  Print the current engagement SITREP
  tacmux export [compact|evidence]
                                 Create a single-file Markdown handoff
  tacmux clip                    Copy stdin through the trusted clipboard path
  tacmux archive verify FILE     Verify an archive and every member hash
  tacmux version                 Print the version
"""


def _require_active(record: EngagementRecord) -> None:
    if record.engagement.status == EngagementStatus.CLOSED:
        raise ConflictError(
            "engagement is closed; reopen it from the engagement picker"
        )


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
    workspace = Workspace(settings)
    invalid = workspace.invalid_engagements()
    engagements = workspace.list_engagements()
    checks.append(
        (
            "engagement manifests",
            not invalid,
            "valid" if not invalid else f"{len(invalid)} invalid",
        )
    )
    closed = sum(item.engagement.status.value == "closed" for item in engagements)
    outside = sum(
        item.engagement.authorization.window_state() == "outside"
        for item in engagements
        if item.engagement.status.value == "active"
    )
    checks.append(
        (
            "engagement lifecycle",
            True,
            f"{closed} closed; {outside} active outside window",
        )
    )
    deleting_roots = [
        settings.workspace / ".tacmux/deleting",
        *(record.root / ".tacmux/deleting" for record in engagements),
    ]
    staged = sorted(
        {
            path
            for deleting_root in deleting_roots
            for path in deleting_root.glob("*")
        }
    )
    checks.append(
        (
            "delete staging",
            True,
            "clear" if not staged else f"{len(staged)} item(s) require manual review",
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
            "Nmap discovery",
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
    for path in staged:
        print(f"     staged deletion: {path}")
    print(f"\nConfig: {settings.config_file}")
    return (
        0
        if all(
            ok
            for label, ok, _ in checks
            if label not in {"Nmap discovery", "editor"}
        )
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
        if args == ["clip"]:
            settings = load_settings()
            return clipboard_copy(TmuxService(settings), sys.stdin.buffer.read())
        if args and args[0] == "note":
            text = " ".join(args[1:]).strip()
            if not text:
                return 2
            settings = load_settings()
            record, target = resolve(settings)
            _require_active(record)
            Workspace(settings).append_note(record, target, text)
            return 0
        if args and args[0] == "activity":
            if len(args) < 3:
                return 2
            result_name = args[1].replace("-", "_")
            rest = args[2:]
            evidence = ""
            if rest[:1] == ["--evidence"]:
                if len(rest) < 3:
                    return 2
                evidence, rest = rest[1], rest[2:]
            text = " ".join(rest).strip()
            if not text:
                return 2
            settings = load_settings()
            tmux = TmuxService(settings)
            record, target = resolve(settings, tmux)
            _require_active(record)
            workspace = Workspace(settings)
            workspace.create_activity(
                record.root,
                record.engagement,
                summary=text,
                result=ActivityResult(result_name),
                target_id=target.id if target else "",
                evidence=evidence,
            )
            workspace.render_documents(
                record.root,
                record.engagement,
                live_target_ids=tmux.live_target_ids(record.engagement),
                jobs=DiscoveryJobs(settings, tmux, workspace).list(record.root),
            )
            return 0
        if args == ["sitrep"]:
            settings = load_settings()
            tmux = TmuxService(settings)
            record, _ = resolve(settings, tmux)
            print(
                render_sitrep(
                    record.engagement,
                    live_sessions=tmux.live_target_ids(record.engagement),
                    jobs=DiscoveryJobs(settings, tmux).list(record.root),
                    include_mermaid=settings.include_mermaid,
                    warnings=Workspace(settings).missing_evidence(
                        record.root, record.engagement
                    ),
                ),
                end="",
            )
            return 0
        if args and args[0] == "export" and len(args) <= 2:
            settings = load_settings()
            tmux = TmuxService(settings)
            record, _ = resolve(settings, tmux)
            profile = parse_export_profile(args[1] if len(args) == 2 else "compact")
            workspace = Workspace(settings)
            path = create_handoff(
                record,
                profile=profile,
                live_target_ids=tmux.live_target_ids(record.engagement),
                jobs=DiscoveryJobs(settings, tmux, workspace).list(record.root),
                include_mermaid=settings.include_mermaid,
            )
            print(path)
            return 0
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
