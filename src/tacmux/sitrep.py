"""Structured Markdown helpers for TACMUX's operator-edited SITREP."""

from __future__ import annotations

from dataclasses import dataclass, replace
import re
from typing import Iterable, Sequence

from .errors import ValidationError


NARRATIVE = ("Time (UTC)", "Target", "Outcome", "Summary", "Notes")
CREDENTIALS = (
    "ID",
    "Principal",
    "Type",
    "Secret",
    "Source",
    "Confirmed Access",
    "Added (UTC)",
    "Last Confirmed (UTC)",
    "Notes",
)
TASKS = (
    "ID",
    "State",
    "Target",
    "Item",
    "Added (UTC)",
    "Completed (UTC)",
    "Notes",
)
DETAILS = ("Field", "Value", "Notes")
PORTS = (
    "Port",
    "Protocol",
    "State",
    "Service",
    "Version",
    "Last Seen (UTC)",
    "Notes",
)

GLOBAL_TABLES: dict[str, tuple[str, ...]] = {"CREDENTIALS": CREDENTIALS}
DETAIL_FIELDS = (
    "Endpoint",
    "Network",
    "Status",
    "Hostnames",
    "Role",
    "OS",
    "Access",
    "Principal",
    "Method/Path",
    "Capture Route",
)

TARGET_HEADING = re.compile(r"(?m)^### (.+?)\s*$")
CONFIRMATION_SEPARATOR = "; "
CONFIRMATION_FIELD_SEPARATOR = " · "
EVENT_BLOCK = re.compile(
    r"(?ms)^<!-- TACMUX:EVENT:START (E\d{3,}) -->\n"
    r"(.*?)^<!-- TACMUX:EVENT:END \1 -->$"
)
EVENT_HEADING = re.compile(r"^### (\S+) — (.+)$")
TASK_LINE = re.compile(r"^- \[([ xX])\] ([TX]\d{3,}): (.+)$")


@dataclass(slots=True, frozen=True)
class TargetSection:
    name: str
    start: int
    end: int


@dataclass(slots=True, frozen=True)
class Task:
    identifier: str
    target: str
    item: str
    added_at: str = ""
    completed_at: str = ""
    notes: str = ""
    complete: bool = False

    def row(self) -> list[str]:
        return [
            self.identifier,
            "done" if self.complete else "open",
            self.target,
            self.item,
            self.added_at,
            self.completed_at,
            self.notes,
        ]


@dataclass(slots=True, frozen=True)
class Event:
    identifier: str
    timestamp: str
    target: str
    outcome: str
    summary: str
    capture_id: str = ""
    body: str = ""

    def row(self) -> list[str]:
        return [
            self.timestamp,
            self.target,
            self.outcome,
            self.summary,
            event_notes(self),
        ]


def parse_confirmed_access(value: str) -> list[tuple[str, str, str]]:
    """Parse target, service, and access entries from a credential row."""
    if not value.strip():
        return []
    results: list[tuple[str, str, str]] = []
    for raw_entry in value.split(";"):
        parts = tuple(part.strip() for part in raw_entry.split("·"))
        if len(parts) != 3 or not all(parts):
            raise ValidationError(
                "Confirmed Access entries must use: target · service · access"
            )
        results.append((parts[0], parts[1], parts[2]))
    return results


def render_confirmed_access(entries: Iterable[tuple[str, str, str]]) -> str:
    return CONFIRMATION_SEPARATOR.join(
        CONFIRMATION_FIELD_SEPARATOR.join(entry) for entry in entries
    )


def _marker(name: str, edge: str) -> str:
    return f"<!-- TACMUX:{name}:{edge} -->"


def _cell(value: object) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    return text.replace("\\", "\\\\").replace("|", "\\|")


def _split_row(line: str) -> list[str]:
    stripped = line.strip()
    if not stripped.startswith("|") or not stripped.endswith("|"):
        raise ValidationError(f"invalid Markdown table row: {line}")
    values: list[str] = []
    current: list[str] = []
    escaped = False
    for character in stripped[1:-1]:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "|":
            values.append("".join(current).strip())
            current = []
        else:
            current.append(character)
    if escaped:
        current.append("\\")
    values.append("".join(current).strip())
    return values


def render_table(headers: Sequence[str], rows: Iterable[Sequence[object]]) -> str:
    header = "| " + " | ".join(_cell(value) for value in headers) + " |"
    separator = "| " + " | ".join("---" for _ in headers) + " |"
    body = ["| " + " | ".join(_cell(value) for value in row) + " |" for row in rows]
    return "\n".join([header, separator, *body])


def table_block(
    name: str, headers: Sequence[str], rows: Iterable[Sequence[object]]
) -> str:
    return (
        f"{_marker(name, 'START')}\n\n"
        f"{render_table(headers, rows)}\n\n"
        f"{_marker(name, 'END')}"
    )


def _bounds(
    text: str, name: str, start: int = 0, end: int | None = None
) -> tuple[int, int]:
    limit = len(text) if end is None else end
    start_marker = _marker(name, "START")
    end_marker = _marker(name, "END")
    left = text.find(start_marker, start, limit)
    right = text.find(end_marker, start, limit)
    if left < 0 and right < 0:
        raise ValidationError(f"SITREP is missing the managed {name.lower()} block")
    if left < 0 or right < 0 or right < left:
        raise ValidationError(f"SITREP has malformed {name.lower()} markers")
    if (
        text.find(start_marker, left + 1, limit) >= 0
        or text.find(end_marker, right + 1, limit) >= 0
    ):
        raise ValidationError(f"SITREP has duplicate {name.lower()} markers")
    return left, right + len(end_marker)


def _parse_table(block: str, name: str, headers: Sequence[str]) -> list[list[str]]:
    lines = block.splitlines()
    if (
        len(lines) < 3
        or lines[0].strip() != _marker(name, "START")
        or lines[-1].strip() != _marker(name, "END")
    ):
        raise ValidationError(f"SITREP has malformed {name.lower()} table")
    content = lines[1:-1]
    while content and not content[0].strip():
        content.pop(0)
    while content and not content[-1].strip():
        content.pop()
    if len(content) < 2:
        raise ValidationError(f"SITREP has malformed {name.lower()} table")
    actual = _split_row(content[0])
    if actual != list(headers):
        raise ValidationError(f"{name.lower()} columns must be: " + " | ".join(headers))
    separators = _split_row(content[1])
    if len(separators) != len(headers) or any(
        not re.fullmatch(r":?-{3,}:?", value) for value in separators
    ):
        raise ValidationError(f"SITREP has an invalid {name.lower()} separator row")
    rows: list[list[str]] = []
    for line in content[2:]:
        if not line.strip():
            continue
        row = _split_row(line)
        if len(row) != len(headers):
            raise ValidationError(
                f"{name.lower()} row has {len(row)} fields; expected {len(headers)}"
            )
        rows.append(row)
    return rows


def read_global(text: str, name: str) -> list[list[str]]:
    if name not in GLOBAL_TABLES:
        raise ValidationError(f"{name.lower()} is not a managed table")
    left, right = _bounds(text, name)
    return _parse_table(text[left:right], name, GLOBAL_TABLES[name])


def write_global(text: str, name: str, rows: Iterable[Sequence[object]]) -> str:
    if name not in GLOBAL_TABLES:
        raise ValidationError(f"{name.lower()} is not a managed table")
    left, right = _bounds(text, name)
    return text[:left] + table_block(name, GLOBAL_TABLES[name], rows) + text[right:]


def _ensure_block_after_heading(
    text: str,
    *,
    name: str,
    content: str,
    heading: str,
    start: int = 0,
    end: int | None = None,
) -> str:
    limit = len(text) if end is None else end
    start_marker = _marker(name, "START")
    end_marker = _marker(name, "END")
    has_start = text.find(start_marker, start, limit) >= 0
    has_end = text.find(end_marker, start, limit) >= 0
    if has_start != has_end:
        raise ValidationError(f"SITREP has malformed {name.lower()} markers")
    if has_start:
        return text
    match = re.search(rf"(?m)^{re.escape(heading)}\s*$", text[start:limit])
    if match is None:
        raise ValidationError(f"SITREP is missing the {heading.lstrip('# ')} heading")
    heading_end = start + match.end()
    return text[:heading_end] + "\n\n" + content + text[heading_end:]


def checklist_block(name: str, tasks: Iterable[Task]) -> str:
    rows: list[str] = []
    for task in sorted(tasks, key=lambda value: value.complete):
        checked = "x" if task.complete else " "
        rows.extend(
            (
                f"- [{checked}] {task.identifier}: {task.item}",
                f"  - Target: {task.target}",
                f"  - Added (UTC): {task.added_at}",
                f"  - Completed (UTC): {task.completed_at}",
                f"  - Notes: {task.notes}",
            )
        )
    body = "\n".join(rows)
    spacing = f"\n\n{body}\n\n" if body else "\n\n"
    return f"{_marker(name, 'START')}{spacing}{_marker(name, 'END')}"


def read_tasks(text: str, name: str) -> list[Task]:
    if name not in {"TODO", "CLEANUP"}:
        raise ValidationError(f"unknown checklist: {name}")
    left, right = _bounds(text, name)
    lines = text[left:right].splitlines()
    body = [line for line in lines[1:-1] if line.strip()]
    if len(body) % 5:
        raise ValidationError(f"SITREP has malformed {name.lower()} checklist")
    prefix = "T" if name == "TODO" else "X"
    tasks: list[Task] = []
    for index in range(0, len(body), 5):
        group = body[index : index + 5]
        match = TASK_LINE.fullmatch(group[0])
        if match is None or not match.group(2).startswith(prefix):
            raise ValidationError(f"SITREP has malformed {name.lower()} item")
        values: list[str] = []
        for line, key in zip(
            group[1:],
            ("Target", "Added (UTC)", "Completed (UTC)", "Notes"),
            strict=True,
        ):
            expected = f"  - {key}:"
            if not line.startswith(expected):
                raise ValidationError(
                    f"{name.lower()} {match.group(2)} is missing {key}"
                )
            values.append(line[len(expected) :].strip())
        tasks.append(
            Task(
                identifier=match.group(2),
                target=values[0],
                item=match.group(3).strip(),
                added_at=values[1],
                completed_at=values[2],
                notes=values[3],
                complete=match.group(1).casefold() == "x",
            )
        )
    return tasks


def write_tasks(text: str, name: str, tasks: Iterable[Task]) -> str:
    left, right = _bounds(text, name)
    return text[:left] + checklist_block(name, tasks) + text[right:]


def normalize_checklists(text: str) -> str:
    updated = text
    for name in ("TODO", "CLEANUP"):
        tasks = [
            replace(task, completed_at="")
            if not task.complete and task.completed_at
            else task
            for task in read_tasks(updated, name)
        ]
        updated = write_tasks(updated, name, tasks)
    return updated


def normalize_document(text: str) -> str:
    """Render every managed wrapper with Markdown-safe spacing."""
    updated = write_global(text, "CREDENTIALS", read_global(text, "CREDENTIALS"))
    for target in [section.name for section in target_sections(updated)]:
        for name in ("DETAILS", "PORTS"):
            rows = read_target(updated, target, name)
            updated = write_target(updated, target, name, rows)
    updated = normalize_checklists(updated)
    return write_events(updated, read_events(updated))


def _event_block(event: Event) -> str:
    capture = event.capture_id or "-"
    body = event.body.strip()
    suffix = f"\n\n{body}" if body else ""
    return (
        f"<!-- TACMUX:EVENT:START {event.identifier} -->\n\n"
        f"### {event.timestamp} — {event.summary}\n\n"
        f"- **Target:** {event.target}\n"
        f"- **Outcome:** {event.outcome}\n"
        f"- **Capture ID:** {capture}"
        f"{suffix}\n\n"
        f"<!-- TACMUX:EVENT:END {event.identifier} -->"
    )


def operations_block(events: Iterable[Event]) -> str:
    rendered = "\n\n".join(_event_block(event) for event in events)
    spacing = f"\n\n{rendered}\n\n" if rendered else "\n\n"
    return f"{_marker('OPERATIONS', 'START')}{spacing}{_marker('OPERATIONS', 'END')}"


def read_events(text: str) -> list[Event]:
    left, right = _bounds(text, "OPERATIONS")
    start_marker = _marker("OPERATIONS", "START")
    end_marker = _marker("OPERATIONS", "END")
    body = text[left + len(start_marker) : right - len(end_marker)]
    events: list[Event] = []
    cursor = 0
    for match in EVENT_BLOCK.finditer(body):
        if body[cursor : match.start()].strip():
            raise ValidationError("SITREP has text outside an Operations Log event")
        identifier = match.group(1)
        lines = match.group(2).strip().splitlines()
        if len(lines) < 5:
            raise ValidationError(f"operation {identifier} is malformed")
        heading = EVENT_HEADING.fullmatch(lines[0])
        if heading is None:
            raise ValidationError(f"operation {identifier} has a malformed heading")
        if lines[1].strip():
            raise ValidationError(f"operation {identifier} metadata is malformed")
        metadata: list[str] = []
        for line, label in zip(
            lines[2:5], ("Target", "Outcome", "Capture ID"), strict=True
        ):
            expected = f"- **{label}:**"
            if not line.startswith(expected):
                raise ValidationError(f"operation {identifier} is missing {label}")
            metadata.append(line[len(expected) :].strip())
        capture = "" if metadata[2] == "-" else metadata[2]
        events.append(
            Event(
                identifier,
                heading.group(1),
                metadata[0],
                metadata[1],
                heading.group(2).strip(),
                capture,
                "\n".join(lines[5:]).strip(),
            )
        )
        cursor = match.end()
    if body[cursor:].strip():
        raise ValidationError("SITREP has malformed Operations Log event markers")
    return events


def write_events(text: str, events: Iterable[Event]) -> str:
    left, right = _bounds(text, "OPERATIONS")
    return text[:left] + operations_block(events) + text[right:]


def append_event(text: str, event: Event) -> str:
    events = read_events(text)
    events.append(event)
    return write_events(text, events)


def event_notes(event: Event) -> str:
    match = re.search(r"(?ms)^#### Notes\s*\n\n(.*?)(?=\n#### |\Z)", event.body)
    if match:
        value = match.group(1).strip()
        return "" if value.startswith("_Add supporting") else value
    return ""


def next_event_id(events: Sequence[Event]) -> str:
    values = [int(event.identifier[1:]) for event in events]
    return f"E{max(values, default=0) + 1:03d}"


def target_sections(text: str) -> list[TargetSection]:
    targets_heading = text.find("## Targets")
    credentials_heading = text.find("## Credentials", targets_heading + 1)
    if targets_heading < 0 or credentials_heading < 0:
        raise ValidationError("SITREP must contain Targets before Credentials")
    matches = list(TARGET_HEADING.finditer(text, targets_heading, credentials_heading))
    sections: list[TargetSection] = []
    for index, match in enumerate(matches):
        end = (
            matches[index + 1].start()
            if index + 1 < len(matches)
            else credentials_heading
        )
        sections.append(TargetSection(match.group(1).strip(), match.start(), end))
    names = [section.name.casefold() for section in sections]
    if len(names) != len(set(names)):
        raise ValidationError("SITREP contains duplicate target headings")
    return sections


def target_section(text: str, target: str) -> TargetSection:
    matches = [
        item
        for item in target_sections(text)
        if item.name.casefold() == target.casefold()
    ]
    if not matches:
        raise ValidationError(f"SITREP has no target section for {target}")
    return matches[0]


def read_target(text: str, target: str, name: str) -> list[list[str]]:
    headers = DETAILS if name == "DETAILS" else PORTS
    section = target_section(text, target)
    left, right = _bounds(text, name, section.start, section.end)
    return _parse_table(text[left:right], name, headers)


def write_target(
    text: str, target: str, name: str, rows: Iterable[Sequence[object]]
) -> str:
    headers = DETAILS if name == "DETAILS" else PORTS
    section = target_section(text, target)
    left, right = _bounds(text, name, section.start, section.end)
    return text[:left] + table_block(name, headers, rows) + text[right:]


def target_template(name: str, endpoint: str, capture_route: str | None = None) -> str:
    route = capture_route or name
    values = {
        "Endpoint": endpoint,
        "Status": "new",
        "Access": "none",
        "Capture Route": route,
    }
    details = [[field, values.get(field, ""), ""] for field in DETAIL_FIELDS]
    return (
        f"### {name}\n\n"
        "#### Details\n\n"
        f"{table_block('DETAILS', DETAILS, details)}\n\n"
        "#### Ports\n\n"
        f"{table_block('PORTS', PORTS, [])}\n"
    )


def add_target(
    text: str, name: str, endpoint: str, capture_route: str | None = None
) -> str:
    if any(item.name.casefold() == name.casefold() for item in target_sections(text)):
        raise ValidationError(f"target already exists in SITREP: {name}")
    credentials = text.find("## Credentials")
    if credentials < 0:
        raise ValidationError("SITREP is missing the Credentials heading")
    prefix = text[:credentials]
    prefix = re.sub(r"\n?_No targets yet\._\s*\Z", "\n", prefix.rstrip())
    addition = target_template(name, endpoint, capture_route)
    return prefix.rstrip() + "\n\n" + addition + "\n" + text[credentials:]


def remove_target(text: str, name: str) -> str:
    section = target_section(text, name)
    updated = text[: section.start].rstrip() + "\n\n" + text[section.end :].lstrip()
    if not target_sections(updated):
        credentials = updated.find("## Credentials")
        updated = (
            updated[:credentials].rstrip()
            + "\n\n_No targets yet._\n\n"
            + updated[credentials:]
        )
    return updated


def rename_target(text: str, old: str, new: str) -> str:
    if any(
        item.name.casefold() == new.casefold()
        and item.name.casefold() != old.casefold()
        for item in target_sections(text)
    ):
        raise ValidationError(f"target already exists in SITREP: {new}")
    section = target_section(text, old)
    heading_end = text.find("\n", section.start)
    if heading_end < 0:
        raise ValidationError(f"malformed target heading: {old}")
    updated = text[: section.start] + f"### {new}" + text[heading_end:]
    events = [
        replace(event, target=new) if event.target == old else event
        for event in read_events(updated)
    ]
    updated = write_events(updated, events)
    for name in ("TODO", "CLEANUP"):
        tasks = [
            replace(task, target=new) if task.target == old else task
            for task in read_tasks(updated, name)
        ]
        updated = write_tasks(updated, name, tasks)
    credentials = read_global(updated, "CREDENTIALS")
    changed = False
    for row in credentials:
        entries = parse_confirmed_access(row[5])
        renamed = [
            (new if target == old else target, service, access)
            for target, service, access in entries
        ]
        if renamed != entries:
            row[5] = render_confirmed_access(renamed)
            changed = True
        tagged_notes = row[8].replace(f"[{old} / ", f"[{new} / ")
        if tagged_notes != row[8]:
            row[8] = tagged_notes
            changed = True
    return write_global(updated, "CREDENTIALS", credentials) if changed else updated


def details_map(text: str, target: str) -> dict[str, tuple[str, str]]:
    rows = read_target(text, target, "DETAILS")
    fields = [row[0] for row in rows]
    if fields != list(DETAIL_FIELDS):
        raise ValidationError(
            f"{target} Details rows must be: " + ", ".join(DETAIL_FIELDS)
        )
    return {field: (value, notes) for field, value, notes in rows}


def set_detail(
    text: str, target: str, field: str, value: str, notes: str | None = None
) -> str:
    rows = read_target(text, target, "DETAILS")
    for row in rows:
        if row[0] == field:
            row[1] = value
            if notes is not None:
                row[2] = notes
            return write_target(text, target, "DETAILS", rows)
    raise ValidationError(f"unknown target detail field: {field}")


def initial_document(name: str) -> str:
    return f"""# {name} SITREP

This is the engagement's current state and chronological operations log.
TACMUX manages only content between its markers; prose remains operator-owned.

## Engagement Context

_Add scope, rules of engagement, objectives, and reference links here._

## Targets

_No targets yet._

## Credentials

{table_block("CREDENTIALS", CREDENTIALS, [])}

## TODO

{checklist_block("TODO", [])}

## Cleanup

{checklist_block("CLEANUP", [])}

## Operations Log

{operations_block([])}
"""


LEGACY_TABLES = {
    "NARRATIVE": NARRATIVE,
    "TODO": ("ID", "Target", "Task", "Added (UTC)", "Notes"),
    "COMPLETED": ("ID", "Target", "Task", "Completed (UTC)", "Notes"),
    "CLEANUP": (
        "ID",
        "Target",
        "Item",
        "Status",
        "Added (UTC)",
        "Completed (UTC)",
        "Notes",
    ),
}


def uses_legacy_format(text: str) -> bool:
    return (
        _marker("NARRATIVE", "START") in text or _marker("COMPLETED", "START") in text
    )


def _legacy_rows(text: str, name: str) -> list[list[str]]:
    left, right = _bounds(text, name)
    return _parse_table(text[left:right], name, LEGACY_TABLES[name])


def upgrade_legacy(text: str) -> str:
    """Convert v3 tables into checklists and an event log."""
    if not uses_legacy_format(text):
        return text
    narratives = _legacy_rows(text, "NARRATIVE")
    todo_rows = _legacy_rows(text, "TODO")
    completed_rows = _legacy_rows(text, "COMPLETED")
    cleanup_rows = _legacy_rows(text, "CLEANUP")
    events = [
        Event(
            f"E{index:03d}",
            row[0],
            row[1],
            row[2],
            row[3],
            body=(f"#### Notes\n\n{row[4]}" if row[4] else ""),
        )
        for index, row in enumerate(narratives, start=1)
    ]
    tasks = [Task(row[0], row[1], row[2], row[3], notes=row[4]) for row in todo_rows]
    tasks.extend(
        Task(
            row[0],
            row[1],
            row[2],
            completed_at=row[3],
            notes=row[4],
            complete=True,
        )
        for row in completed_rows
    )
    cleanup = [
        Task(
            row[0],
            row[1],
            row[2],
            row[4],
            row[5],
            row[6],
            row[3] == "complete",
        )
        for row in cleanup_rows
    ]
    if "## Narrative" not in text or "## Completed" not in text:
        raise ValidationError("legacy SITREP is missing expected headings")
    updated = text.replace("## Narrative", "## Engagement Context", 1)
    left, right = _bounds(updated, "NARRATIVE")
    updated = (
        updated[:left]
        + "_Add scope, rules of engagement, objectives, and reference links here._"
        + updated[right:]
    )
    left, right = _bounds(updated, "TODO")
    updated = updated[:left] + checklist_block("TODO", tasks) + updated[right:]
    left, right = _bounds(updated, "COMPLETED")
    updated = updated[:left] + updated[right:]
    updated = updated.replace("## Completed", "", 1)
    left, right = _bounds(updated, "CLEANUP")
    updated = updated[:left] + checklist_block("CLEANUP", cleanup) + updated[right:]
    return updated.rstrip() + f"\n\n## Operations Log\n\n{operations_block(events)}\n"


def ensure_scaffolding(text: str) -> str:
    if uses_legacy_format(text):
        raise ValidationError("legacy SITREP format; run tacmux sitrep sync")
    updated = _ensure_block_after_heading(
        text,
        name="CREDENTIALS",
        content=table_block("CREDENTIALS", CREDENTIALS, []),
        heading="## Credentials",
    )
    for name, heading in (("TODO", "## TODO"), ("CLEANUP", "## Cleanup")):
        updated = _ensure_block_after_heading(
            updated,
            name=name,
            content=checklist_block(name, []),
            heading=heading,
        )
    updated = _ensure_block_after_heading(
        updated,
        name="OPERATIONS",
        content=operations_block([]),
        heading="## Operations Log",
    )
    for target_name in [section.name for section in target_sections(updated)]:
        section = target_section(updated, target_name)
        try:
            _bounds(updated, "PORTS", section.start, section.end)
        except ValidationError as exc:
            if "missing" not in str(exc):
                raise
            updated = _ensure_block_after_heading(
                updated,
                name="PORTS",
                content=table_block("PORTS", PORTS, []),
                heading="#### Ports",
                start=section.start,
                end=section.end,
            )
    return updated


def heading_line(text: str, section: str) -> int:
    aliases = {
        "context": "## Engagement Context",
        "targets": "## Targets",
        "credentials": "## Credentials",
        "creds": "## Credentials",
        "todo": "## TODO",
        "completed": "## TODO",
        "cleanup": "## Cleanup",
        "operations": "## Operations Log",
        "log": "## Operations Log",
        "notes": "## Operations Log",
        "narrative": "## Operations Log",
    }
    wanted = aliases.get(section.casefold())
    if wanted is None:
        for item in target_sections(text):
            if item.name.casefold() == section.casefold():
                wanted = f"### {item.name}"
                break
    if wanted is None:
        raise ValidationError(f"unknown SITREP section or target: {section}")
    for number, line in enumerate(text.splitlines(), start=1):
        if line.strip() == wanted:
            return number
    raise ValidationError(f"SITREP section is missing: {section}")


def next_id(rows: Sequence[Sequence[str]], prefix: str) -> str:
    values = []
    for row in rows:
        value = row[0]
        if value.startswith(prefix) and value[len(prefix) :].isdigit():
            values.append(int(value[len(prefix) :]))
    return f"{prefix}{max(values, default=0) + 1:03d}"
