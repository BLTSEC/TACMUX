"""Lean operator CLI and private tmux hook entrypoints."""

from __future__ import annotations

import getpass
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Sequence

from . import __version__, sitrep
from .config import Settings, load_settings
from .context import Context, resolve
from .discovery import create_reviewed_targets, review_candidates, run_host_discovery
from .errors import TacmuxError, ValidationError
from .hooks import LogController, clipboard_copy, status_segment
from .interaction import (
    ask,
    choose,
    choose_many,
    confirm,
    edit_text,
    format_table,
    open_editor,
)
from .tmux import TmuxService
from .workspace import (
    ACCESS_LEVELS,
    OUTCOMES,
    TARGET_STATUSES,
    Workspace,
    parse_host_candidates,
    parse_nmap_ports,
)


USAGE = """TACMUX — lean tmux-native engagement workspaces

Usage:
  tacmux                         Switch engagement/target with fzf
  tacmux init [NAME]             Create or open an engagement
  tacmux switch                  Switch engagement/target with fzf
  tacmux stop [TARGET]           Stop a target or operations session
  tacmux target add [NAME] [IP]  Create a target and file tree
  tacmux target update [TARGET] [FIELD] [VALUE|--clear]
  tacmux target export [--all|--none|TARGET...]
  tacmux target rename [OLD] [NEW]
  tacmux target delete [TARGET]
  tacmux status [TARGET]         Show target or engagement status
  tacmux sitrep [SECTION]        Edit SITREP, optionally at a heading
  tacmux sitrep sync             Upgrade, validate, and repair SITREP
  tacmux log [OUTCOME] [-c] [-i IMAGE] [TEXT...]
  tacmux done [-c] [-i IMAGE] [TEXT...]
  tacmux history [TARGET]        Show Operations Log history
  tacmux creds [view|add|confirm] View or confirm working credentials
  tacmux ports [TARGET]          View normalized target ports
  tacmux ports add [TARGET] [FILE]
  tacmux todo [add|done|reopen]  View or update planned work
  tacmux cleanup [add|done|reopen]
  tacmux discover [nmap|hosts|netexec] [INPUT]
  tacmux health                  Check required and optional tools
  tacmux clip                    Copy stdin through a trusted clipboard path
  tacmux version                 Print the version
"""


def _settings_services() -> tuple[Settings, Workspace, TmuxService]:
    settings = load_settings()
    return settings, Workspace(settings), TmuxService(settings)


def _completion_values(arguments: Sequence[str]) -> int:
    """Print newline-delimited, non-secret values for shell completion."""
    if len(arguments) != 1:
        return 0
    kind = arguments[0]
    settings, workspace, tmux = _settings_services()
    try:
        if kind == "engagement":
            values = [root.name for root in workspace.engagements()]
        else:
            context = resolve(settings, tmux, allow_picker=False)
            targets = workspace.targets(context.root)
            if kind == "target":
                values = targets
            elif kind == "sitrep":
                values = [
                    "context",
                    "targets",
                    "credentials",
                    "todo",
                    "cleanup",
                    "log",
                    "notes",
                    *targets,
                ]
            elif kind == "credential":
                values = [
                    row[0]
                    for row in sitrep.read_global(
                        workspace.read(context.root), "CREDENTIALS"
                    )
                ]
            elif kind in {"todo", "cleanup"}:
                tasks = sitrep.read_tasks(workspace.read(context.root), kind.upper())
                values = [task.identifier for task in tasks if not task.complete]
            elif kind in {"todo_done", "cleanup_done"}:
                name = kind.removesuffix("_done").upper()
                tasks = sitrep.read_tasks(workspace.read(context.root), name)
                values = [task.identifier for task in tasks if task.complete]
            else:
                values = []
    except (TacmuxError, OSError, ValueError):
        values = []
    for value in values:
        print(value)
    return 0


def _target_choice(workspace: Workspace, root: Path, default: str = "") -> str:
    targets = workspace.targets(root)
    return choose([(name, name) for name in targets], "Target> ", default=default)


def _record_target(workspace: Workspace, context: Context, *, interactive: bool) -> str:
    default = context.target or "ENGAGEMENT"
    if not interactive:
        return default
    choices = [("ENGAGEMENT", "ENGAGEMENT")]
    choices.extend((name, name) for name in workspace.targets(context.root))
    return choose(choices, "Record for> ", default=default)


def _switch(settings: Settings, workspace: Workspace, tmux: TmuxService) -> int:
    live = {
        (str(session.root.resolve()), session.target): session
        for session in tmux.sessions()
    }
    choices: list[tuple[str, str]] = []
    separator = "\x1f"
    for root in workspace.engagements():
        ops_key = (str(root.resolve()), "")
        state = "LIVE" if ops_key in live else "STOP"
        choices.append((f"{state:4}  {root.name} / OPS", f"{root}{separator}"))
        for target in workspace.targets(root):
            details = workspace.target_details(root, target)
            key = (str(root.resolve()), target)
            state = "LIVE" if key in live else "STOP"
            endpoint = details["Endpoint"][0]
            choices.append(
                (
                    f"{state:4}  {root.name} / {target}  {endpoint}",
                    f"{root}{separator}{target}",
                )
            )
    selected = choose(choices, "Session> ")
    root_value, _, target = selected.partition(separator)
    session = tmux.start(Path(root_value), target)
    return tmux.attach(session)


def _stop(workspace: Workspace, tmux: TmuxService, arguments: Sequence[str]) -> int:
    context = resolve(tmux.settings, tmux)
    target = arguments[0] if arguments else context.target
    if target:
        target = workspace.canonical_target(context.root, target)
    elif not arguments and tmux.current_context()[0] is None:
        live = [
            session
            for session in tmux.sessions()
            if session.root.resolve() == context.root.resolve()
        ]
        if len(live) == 1:
            target = live[0].target
        elif len(live) > 1:
            selected = choose(
                [
                    (
                        session.target or "OPS",
                        session.target,
                    )
                    for session in live
                ],
                "Stop> ",
            )
            target = selected
    tmux.stop(context.root, target)
    print(f"Stopped {target or 'OPS'}")
    return 0


def _target_command(
    settings: Settings,
    workspace: Workspace,
    tmux: TmuxService,
    arguments: Sequence[str],
) -> int:
    if not arguments or arguments[0] not in {
        "add",
        "update",
        "export",
        "rename",
        "delete",
    }:
        raise ValidationError("target requires add, update, export, rename, or delete")
    action, *rest = arguments
    context = resolve(settings, tmux)
    if action == "add":
        name = rest[0] if rest else ask("Target name")
        endpoint = rest[1] if len(rest) > 1 else ask("Endpoint")
        workspace.add_target(context.root, name, endpoint)
        print(f"Created {name}: {context.root / 'targets' / name}")
        return 0
    if action == "export":
        return _export_targets(workspace, context, rest)
    old = rest[0] if rest else context.target
    if not old:
        old = _target_choice(workspace, context.root)
    old = workspace.canonical_target(context.root, old)
    if action == "update":
        return _update_target(workspace, tmux, context, old, rest[1:])
    tmux.require_stopped(context.root, old)
    if action == "rename":
        new = rest[1] if len(rest) > 1 else ask("New target name")
        workspace.rename_target(context.root, old, new)
        print(f"Renamed {old} to {new}")
        return 0
    confirmation = input(f"Type {old} to permanently delete its directory: ").strip()
    if confirmation != old:
        raise ValidationError("target deletion cancelled")
    workspace.delete_target(context.root, old)
    print(f"Deleted {old}")
    return 0


def _export_targets(
    workspace: Workspace, context: Context, arguments: Sequence[str]
) -> int:
    available = workspace.targets(context.root)
    if arguments:
        if arguments == ["--all"]:
            selected = available
        elif arguments in (["--none"], ["--clear"]):
            selected = []
        elif any(value.startswith("--") for value in arguments):
            raise ValidationError(
                "target export supports --all, --none, or target names"
            )
        else:
            selected = list(arguments)
    else:
        mode = choose(
            [
                (f"All targets ({len(available)})", "all"),
                ("Select targets", "select"),
                ("None (write an empty targets.txt)", "none"),
            ],
            "Target list> ",
            default="all",
        )
        if mode == "all":
            selected = available
        elif mode == "none":
            selected = []
        else:
            choices = []
            for target in available:
                endpoint = workspace.target_details(context.root, target)["Endpoint"][0]
                choices.append((f"{target:24} {endpoint}", target))
            selected = choose_many(choices, "Targets> ")
    path, count = workspace.write_target_list(context.root, selected)
    print(f"Wrote {count} target(s): {path}")
    return 0


TARGET_DETAIL_FIELDS = {
    "endpoint": "Endpoint",
    "network": "Network",
    "status": "Status",
    "hostnames": "Hostnames",
    "role": "Role",
    "os": "OS",
    "access": "Access",
    "principal": "Principal",
    "method": "Method/Path",
    "route": "Capture Route",
}
REQUIRED_TARGET_FIELDS = {"Endpoint", "Status", "Capture Route"}
STOPPED_ONLY_TARGET_FIELDS = {"Endpoint", "Capture Route"}


def _interactive_target_value(field: str, current: str) -> str:
    if field == "Status":
        return choose(
            [(value, value) for value in TARGET_STATUSES],
            "Status> ",
            default=current,
        )
    if field == "Access":
        return choose(
            [(value, value) for value in ACCESS_LEVELS],
            "Access> ",
            default=current,
        )
    if field == "OS":
        selected = choose(
            [
                ("Linux", "Linux"),
                ("Windows", "Windows"),
                ("macOS", "macOS"),
                ("Other", "other"),
                ("Clear", ""),
            ],
            "OS> ",
            default=current,
        )
        return ask("OS") if selected == "other" else selected
    if current and field not in REQUIRED_TARGET_FIELDS:
        mode = choose(
            [("Set or update value", "set"), ("Clear current value", "clear")],
            f"{field}> ",
            default="set",
        )
        if mode == "clear":
            return ""
    return ask(field, default=current, required=field in REQUIRED_TARGET_FIELDS)


def _update_target(
    workspace: Workspace,
    tmux: TmuxService,
    context: Context,
    target: str,
    arguments: Sequence[str],
) -> int:
    details = workspace.target_details(context.root, target)
    if arguments:
        field_key, *value_parts = arguments
        field = TARGET_DETAIL_FIELDS.get(field_key.casefold())
        if field is None:
            raise ValidationError(
                "target field must be: " + ", ".join(TARGET_DETAIL_FIELDS)
            )
        if not value_parts:
            raise ValidationError("target update requires a value or --clear")
        if value_parts == ["--clear"]:
            if field in REQUIRED_TARGET_FIELDS:
                raise ValidationError(f"{field} cannot be cleared")
            value = ""
        else:
            value = " ".join(value_parts)
    else:
        field_key = choose(
            [
                (f"{label:14} {details[label][0] or '-'}", key)
                for key, label in TARGET_DETAIL_FIELDS.items()
            ],
            "Target field> ",
        )
        field = TARGET_DETAIL_FIELDS[field_key]
        value = _interactive_target_value(field, details[field][0])
    if field in STOPPED_ONLY_TARGET_FIELDS:
        tmux.require_stopped(context.root, target)
    workspace.set_target_detail(context.root, target, field, value)
    print(f"Updated {target} {field}: {value or '-'}")
    return 0


def _print_status(
    workspace: Workspace, tmux: TmuxService, context: Context, target: str = ""
) -> None:
    text = workspace.read(context.root)
    target = target or context.target
    if not target:
        rows = []
        for name in workspace.targets(context.root):
            details = workspace.target_details(context.root, name)
            rows.append(
                [
                    name,
                    details["Endpoint"][0],
                    details["Status"][0],
                    details["OS"][0] or "-",
                    details["Access"][0],
                    "LIVE" if tmux.target_running(context.root, name) else "-",
                ]
            )
        print(f"{context.root.name}\n")
        print(
            format_table(
                ("Target", "Endpoint", "Status", "OS", "Access", "Session"), rows
            )
        )
        return
    target = workspace.canonical_target(context.root, target)
    details = sitrep.read_target(text, target, "DETAILS")
    print(f"{context.root.name} / {target}")
    print(f"Session: {'LIVE' if tmux.target_running(context.root, target) else '-'}\n")
    print(format_table(sitrep.DETAILS, details))
    sections: list[tuple[str, tuple[str, ...], list[list[str]]]] = [
        ("Ports", sitrep.PORTS, sitrep.read_target(text, target, "PORTS")),
    ]
    confirmed_credentials: list[list[str]] = []
    for row in sitrep.read_global(text, "CREDENTIALS"):
        for confirmed_target, service, access in sitrep.parse_confirmed_access(row[5]):
            if confirmed_target == target:
                confirmed_credentials.append(
                    [row[0], row[1], row[2], service, access, row[7], row[8]]
                )
    sections.append(
        (
            "Confirmed Credentials",
            (
                "ID",
                "Principal",
                "Type",
                "Service",
                "Access",
                "Last Confirmed (UTC)",
                "Notes",
            ),
            confirmed_credentials,
        )
    )
    for name, label in (("TODO", "TODO"), ("CLEANUP", "Cleanup")):
        sections.append(
            (
                label,
                sitrep.TASKS,
                [
                    task.row()
                    for task in sitrep.read_tasks(text, name)
                    if task.target == target
                ],
            )
        )
    events = [
        event.row() for event in sitrep.read_events(text) if event.target == target
    ][-10:]
    sections.append(("Recent Operations", sitrep.NARRATIVE, events))
    for label, headers, rows in sections:
        print(f"\n{label}")
        print(format_table(headers, rows) if rows else "-")


def _sitrep_command(
    settings: Settings,
    workspace: Workspace,
    tmux: TmuxService,
    arguments: Sequence[str],
) -> int:
    context = resolve(settings, tmux)
    if arguments == ["sync"]:
        text = workspace.read(context.root)
        if sitrep.uses_legacy_format(text):
            if not confirm(
                "Convert Narrative and task tables to the Operations Log/checklists?"
            ):
                raise ValidationError("SITREP upgrade cancelled")
            backup = workspace.upgrade_sitrep(context.root)
            if backup:
                print(f"Upgraded SITREP; backup: {backup}")
            text = workspace.read(context.root)
        documented = {section.name for section in sitrep.target_sections(text)}
        missing = [
            name for name in workspace.targets(context.root) if name not in documented
        ]
        endpoints = {name: ask(f"Endpoint for {name}") for name in missing}
        problems = workspace.repair_scaffolding(context.root, endpoints)
        if problems:
            print("SITREP requires review:")
            for problem in problems:
                print(f"- {problem}")
            return 1
        print("SITREP is consistent")
        return 0
    section = arguments[0] if arguments else ""
    text = workspace.read(context.root)
    line = sitrep.heading_line(text, section) if section else None
    open_editor(settings, workspace.sitrep_path(context.root), line)
    workspace.mutate(context.root, lambda value: value)
    return 0


def _log_command(
    settings: Settings,
    workspace: Workspace,
    tmux: TmuxService,
    arguments: Sequence[str],
    *,
    force_success: bool = False,
) -> int:
    context = resolve(settings, tmux)
    if arguments == ["edit"] and not force_success:
        return _sitrep_command(settings, workspace, tmux, ["log"])
    words = list(arguments)
    capture_requested = False
    images: list[Path] = []
    position = 0
    while position < len(words):
        value = words[position]
        if value in {"-c", "--capture"}:
            capture_requested = True
            words.pop(position)
            continue
        if value in {"-i", "--image"}:
            if position + 1 >= len(words):
                raise ValidationError(f"{value} requires an image path")
            images.append(Path(words[position + 1]))
            del words[position : position + 2]
            continue
        position += 1
    interactive = not words
    target = _record_target(workspace, context, interactive=interactive)
    if force_success:
        outcome = "success"
        summary = " ".join(words).strip() if words else ask("Completed step")
    elif interactive:
        outcome = choose(
            [(value, value) for value in OUTCOMES], "Outcome> ", default="info"
        )
        summary = ask("Summary")
    else:
        outcome = words[0] if words[0] in OUTCOMES else "info"
        summary_words = words[1:] if words[0] in OUTCOMES else words
        summary = " ".join(summary_words).strip()
    if not summary:
        raise ValidationError("summary cannot be empty")
    notes = ask("Notes", required=False) if interactive else ""
    capture = (
        workspace.inspect_capture(context.root, target) if capture_requested else None
    )
    identifier = workspace.add_event(
        context.root,
        target,
        outcome,
        summary,
        notes,
        capture=capture,
        images=images,
    )
    extras = []
    if capture:
        extras.append(f"capture {capture.identifier}")
    if images:
        extras.append(f"{len(images)} image(s)")
    suffix = f" ({', '.join(extras)})" if extras else ""
    print(f"Logged {identifier} {outcome}: {target} — {summary}{suffix}")
    return 0


def _history(workspace: Workspace, context: Context, target: str = "") -> None:
    if target:
        target = workspace.canonical_target(context.root, target)
    events = sitrep.read_events(workspace.read(context.root))
    rows = [event.row() for event in reversed(events)]
    if target:
        rows = [row for row in rows if row[1] == target]
    print(format_table(sitrep.NARRATIVE, rows) if rows else "No operations logged.")


def _credential_command(
    workspace: Workspace, context: Context, arguments: Sequence[str]
) -> int:
    text = workspace.read(context.root)
    if not arguments or arguments == ["view"]:
        rows = sitrep.read_global(text, "CREDENTIALS")
        print(format_table(sitrep.CREDENTIALS, rows) if rows else "No credentials.")
        return 0
    action, *rest = arguments
    if action == "add":
        secret_type = (
            rest.pop(0).casefold()
            if rest and rest[0].casefold() in {"password", "hash"}
            else ""
        )
        if not secret_type:
            secret_type = choose(
                [("Password", "password"), ("Hash", "hash")], "Credential type> "
            )
        supplied = " ".join(rest).strip()
        if supplied:
            principal, separator, secret = supplied.partition(":")
            if not separator:
                raise ValidationError("credential input must be username:secret")
            source = notes = ""
        else:
            principal = ask("Principal")
            secret = getpass.getpass("Secret: ")
            source = ask("Source", required=False)
            notes = ask("Notes", required=False)
        identifier = workspace.add_credential(
            context.root, principal, secret, secret_type, source, notes
        )
        print(f"Added {identifier} ({principal}, {secret_type})")
        return 0
    if action == "confirm":
        credentials = sitrep.read_global(text, "CREDENTIALS")
        credential = (
            rest[0]
            if rest
            else choose(
                [(f"{row[0]}  {row[1]}  {row[2]}", row[0]) for row in credentials],
                "Credential> ",
            )
        )
        target = (
            rest[1]
            if len(rest) > 1
            else _target_choice(workspace, context.root, context.target)
        )
        access = (
            rest[2]
            if len(rest) > 2
            else choose(
                [(value, value) for value in ACCESS_LEVELS if value != "none"],
                "Confirmed access> ",
                default="authenticated",
            )
        )
        service = rest[3] if len(rest) > 3 else ask("Service")
        notes = " ".join(rest[4:]) if len(rest) > 4 else ask("Notes", required=False)
        workspace.confirm_credential(
            context.root, credential, target, access, service, notes
        )
        print(f"Confirmed {credential} on {target} via {service} ({access})")
        return 0
    raise ValidationError("creds supports view, add, or confirm")


def _input_text(settings: Settings, source: str = "") -> str:
    if source:
        path = Path(source).expanduser()
        if not path.is_file() or path.is_symlink():
            raise ValidationError(f"input file is missing or unsafe: {path}")
        return path.read_text(encoding="utf-8", errors="replace")
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return edit_text(settings, "# Paste input below, save, and close.\n", suffix=".txt")


def _ports_command(
    settings: Settings,
    workspace: Workspace,
    tmux: TmuxService,
    arguments: Sequence[str],
) -> int:
    context = resolve(settings, tmux)
    if arguments and arguments[0] == "add":
        rest = list(arguments[1:])
        target = ""
        if rest and workspace.target_exists(context.root, rest[0]):
            target = workspace.canonical_target(context.root, rest.pop(0))
        target = target or context.target or _target_choice(workspace, context.root)
        content = _input_text(settings, rest[0] if rest else "")
        ports = parse_nmap_ports(content)
        if not ports:
            raise ValidationError("input contained no Nmap port rows")
        raw = workspace.store_scan(context.root, target, content)
        count = workspace.merge_ports(context.root, target, ports)
        print(f"Imported {count} port rows for {target}; raw input: {raw}")
        return 0
    target = arguments[0] if arguments else context.target
    target = target or _target_choice(workspace, context.root)
    target = workspace.canonical_target(context.root, target)
    rows = sitrep.read_target(workspace.read(context.root), target, "PORTS")
    print(
        format_table(sitrep.PORTS, rows) if rows else f"No ports recorded for {target}."
    )
    return 0


def _task_command(
    workspace: Workspace,
    context: Context,
    arguments: Sequence[str],
    *,
    cleanup: bool,
) -> int:
    table_name = "CLEANUP" if cleanup else "TODO"
    tasks = sitrep.read_tasks(workspace.read(context.root), table_name)
    if not arguments:
        print(
            format_table(sitrep.TASKS, [task.row() for task in tasks])
            if tasks
            else f"No {table_name.lower()} items."
        )
        return 0
    action, *rest = arguments
    if action == "add":
        interactive = not rest
        target = _record_target(workspace, context, interactive=interactive)
        item = (
            " ".join(rest).strip()
            if rest
            else ask("Cleanup item" if cleanup else "Task")
        )
        notes = ask("Notes", required=False) if interactive else ""
        identifier = (
            workspace.add_cleanup(context.root, target, item, notes)
            if cleanup
            else workspace.add_task(context.root, target, item, notes)
        )
        print(f"Added {identifier}")
        return 0
    if action in {"done", "reopen"}:
        reopening = action == "reopen"
        candidates = [task for task in tasks if task.complete == reopening]
        identifier = (
            rest[0]
            if rest
            else choose(
                [
                    (
                        f"{task.identifier}  {task.target}  {task.item}",
                        task.identifier,
                    )
                    for task in candidates
                ],
                "Reopen> " if reopening else "Complete> ",
            )
        )
        if cleanup:
            operation = (
                workspace.reopen_cleanup if reopening else workspace.complete_cleanup
            )
        else:
            operation = workspace.reopen_task if reopening else workspace.complete_task
        operation(context.root, identifier)
        print(f"{'Reopened' if reopening else 'Completed'} {identifier}")
        return 0
    raise ValidationError(f"{table_name.lower()} supports add, done, or reopen")


def _discover_command(
    settings: Settings,
    workspace: Workspace,
    tmux: TmuxService,
    arguments: Sequence[str],
) -> int:
    context = resolve(settings, tmux)
    source = (
        arguments[0]
        if arguments
        else choose(
            [
                ("Nmap host discovery", "nmap"),
                ("Paste/import host lines", "hosts"),
                ("Paste/import NetExec SMB output", "netexec"),
            ],
            "Discovery source> ",
        )
    )
    value = arguments[1] if len(arguments) > 1 else ""
    if source == "nmap":
        network = value or ask("Authorized IP or CIDR")
        content = run_host_discovery(network)
        candidates = parse_host_candidates(content, "hosts")
    elif source in {"hosts", "netexec"}:
        content = _input_text(settings, value)
        candidates = parse_host_candidates(content, source)
    else:
        raise ValidationError("discovery source must be nmap, hosts, or netexec")
    reviewed = review_candidates(settings, candidates)
    created, skipped = create_reviewed_targets(workspace, context.root, reviewed)
    print(f"Created {len(created)} target(s): {', '.join(created) or '-'}")
    if skipped:
        print(f"Skipped existing: {', '.join(skipped)}")
    return 0


def _health(settings: Settings, workspace: Workspace, tmux: TmuxService) -> int:
    cap_path = shutil.which("cap")
    cap_ok = True
    cap_detail = "optional; missing"
    if cap_path:
        result = subprocess.run(
            [cap_path, "--version"], text=True, capture_output=True, check=False
        )
        match = re.search(r"\b(\d+)\.(\d+)\.(\d+)\b", result.stdout)
        cap_ok = bool(
            result.returncode == 0
            and match
            and tuple(map(int, match.groups())) >= (2, 3, 0)
        )
        cap_detail = result.stdout.strip() if result.returncode == 0 else "unavailable"
    live_sessions = tmux.sessions()
    hooks_ok = not settings.auto_log or (
        not tmux.legacy_global_autolog_hooks()
        and all(tmux.autolog_hooks_ready(session.name) for session in live_sessions)
    )
    hooks_detail = (
        "disabled"
        if not settings.auto_log
        else f"{len(live_sessions)} TACMUX session(s)"
    )
    checks = [
        ("Python", sys.version_info >= (3, 11), sys.version.split()[0], True),
        ("tmux", tmux.available(), tmux.version(), True),
        (
            "fzf",
            shutil.which("fzf") is not None,
            shutil.which("fzf") or "missing",
            True,
        ),
        (
            "workspace",
            settings.workspace.is_dir() and os.access(settings.workspace, os.W_OK),
            str(settings.workspace),
            True,
        ),
        (
            "SITREP root",
            settings.sitrep_root is None
            or (
                settings.sitrep_root.is_dir()
                and not settings.sitrep_root.is_symlink()
                and os.access(settings.sitrep_root, os.W_OK)
            ),
            str(settings.sitrep_root) if settings.sitrep_root else "engagement-local",
            True,
        ),
        (
            "editor",
            shutil.which(settings.editor_argv[0]) is not None,
            " ".join(settings.editor_argv),
            True,
        ),
        (
            "nmap",
            shutil.which("nmap") is not None,
            shutil.which("nmap") or "optional",
            False,
        ),
        ("cap", cap_ok, cap_detail, True),
        ("log hooks", hooks_ok, hooks_detail, True),
    ]
    invalid: list[tuple[Path, str]] = []
    for root in workspace.engagements():
        try:
            problems = workspace.validate(root)
            invalid.extend((root, problem) for problem in problems)
        except TacmuxError as exc:
            invalid.append((root, str(exc)))
    print(f"TACMUX {__version__}\n")
    for label, ok, detail, _required in checks:
        print(f"[{'ok' if ok else '--'}] {label:12} {detail}")
    for root, problem in invalid:
        print(f"[--] {root.name:12} {problem}")
    required_ok = all(ok for _, ok, _, required in checks if required)
    return 0 if required_ok and not invalid else 1


def _internal(arguments: Sequence[str]) -> int:
    if not arguments:
        raise ValidationError("missing internal command")
    settings, _, tmux = _settings_services()
    command, *rest = arguments
    if command == "clip":
        return clipboard_copy(tmux, sys.stdin.buffer.read())
    if command == "status-segment":
        print(status_segment(settings, tmux), end="")
        return 0
    if command == "hooks" and rest == ["repair"]:
        print(tmux.repair_autolog_hooks())
        return 0
    if command == "log":
        if not rest:
            raise ValidationError("log requires an action")
        action, *parameters = rest
        pane = parameters[0] if parameters else os.environ.get("TMUX_PANE", "")
        controller = LogController(settings, tmux)
        if action == "start":
            controller.start(pane)
        elif action == "stop":
            controller.stop(pane)
        elif action == "toggle":
            controller.toggle(pane)
        elif action == "capture":
            controller.capture(pane)
        elif action == "status":
            print(controller.status(pane))
        else:
            raise ValidationError(f"unknown log action: {action}")
        return 0
    raise ValidationError(f"unknown internal command: {command}")


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        if arguments and arguments[0] in {"help", "--help", "-h"}:
            print(USAGE, end="")
            return 0
        if arguments and arguments[0] in {"version", "--version", "-v"}:
            print(f"tacmux {__version__}")
            return 0
        if arguments and arguments[0] == "_internal":
            return _internal(arguments[1:])
        if arguments and arguments[0] == "_complete":
            return _completion_values(arguments[1:])
        settings, workspace, tmux = _settings_services()
        workspace.initialize()
        if not arguments or arguments == ["switch"]:
            return _switch(settings, workspace, tmux)
        command, *rest = arguments
        if command == "init":
            name = rest[0] if rest else ask("Engagement name")
            root = workspace.create_engagement(name)
            print(root)
            if settings.sitrep_root and (root / "SITREP.md").is_symlink():
                print(f"SITREP: {workspace.sitrep_path(root)}")
                print(
                    "Warning: this external notes location receives raw credentials "
                    "stored in SITREP."
                )
            print("Run tacmux switch to enter the operations session.")
            return 0
        if command == "health":
            return _health(settings, workspace, tmux)
        if command == "stop":
            return _stop(workspace, tmux, rest)
        if command == "target":
            return _target_command(settings, workspace, tmux, rest)
        if command == "status":
            context = resolve(settings, tmux)
            _print_status(workspace, tmux, context, rest[0] if rest else "")
            return 0
        if command == "sitrep":
            return _sitrep_command(settings, workspace, tmux, rest)
        if command == "log":
            return _log_command(settings, workspace, tmux, rest)
        if command == "done":
            return _log_command(settings, workspace, tmux, rest, force_success=True)
        if command == "history":
            context = resolve(settings, tmux)
            _history(workspace, context, rest[0] if rest else "")
            return 0
        if command == "creds":
            return _credential_command(workspace, resolve(settings, tmux), rest)
        if command == "ports":
            return _ports_command(settings, workspace, tmux, rest)
        if command == "todo":
            return _task_command(
                workspace, resolve(settings, tmux), rest, cleanup=False
            )
        if command == "cleanup":
            return _task_command(workspace, resolve(settings, tmux), rest, cleanup=True)
        if command == "discover":
            return _discover_command(settings, workspace, tmux, rest)
        if command == "clip":
            return clipboard_copy(tmux, sys.stdin.buffer.read())
        raise ValidationError(f"unknown command: {command}\n\n{USAGE}")
    except (KeyboardInterrupt, EOFError):
        print("tacmux: cancelled", file=sys.stderr)
        return 130
    except (TacmuxError, OSError, ValueError) as exc:
        print(f"tacmux: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
