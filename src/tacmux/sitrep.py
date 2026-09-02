"""Predictable Markdown tables for the operator-edited SITREP."""

from __future__ import annotations

from dataclasses import dataclass
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
    "Added (UTC)",
    "Notes",
)
CREDENTIAL_CHECKS = (
    "ID",
    "Credential",
    "Target",
    "Result",
    "Access",
    "Tested (UTC)",
    "Notes",
)
TODO = ("ID", "Target", "Task", "Added (UTC)", "Notes")
COMPLETED = ("ID", "Target", "Task", "Completed (UTC)", "Notes")
CLEANUP = (
    "ID",
    "Target",
    "Item",
    "Status",
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

GLOBAL_TABLES: dict[str, tuple[str, ...]] = {
    "NARRATIVE": NARRATIVE,
    "CREDENTIALS": CREDENTIALS,
    "CREDENTIAL_CHECKS": CREDENTIAL_CHECKS,
    "TODO": TODO,
    "COMPLETED": COMPLETED,
    "CLEANUP": CLEANUP,
}

GLOBAL_HEADINGS = {
    "NARRATIVE": "Narrative",
    "CREDENTIALS": "Credentials",
    "CREDENTIAL_CHECKS": "Credential Checks",
    "TODO": "TODO",
    "COMPLETED": "Completed",
    "CLEANUP": "Cleanup",
}

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


@dataclass(slots=True, frozen=True)
class TargetSection:
    name: str
    start: int
    end: int


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
        f"{_marker(name, 'START')}\n"
        f"{render_table(headers, rows)}\n"
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
        raise ValidationError(f"SITREP is missing the managed {name.lower()} table")
    if left < 0 or right < 0 or right < left:
        raise ValidationError(f"SITREP has malformed {name.lower()} table markers")
    if (
        text.find(start_marker, left + 1, limit) >= 0
        or text.find(end_marker, right + 1, limit) >= 0
    ):
        raise ValidationError(f"SITREP has duplicate {name.lower()} table markers")
    return left, right + len(end_marker)


def _parse_block(block: str, name: str, headers: Sequence[str]) -> list[list[str]]:
    lines = block.splitlines()
    if (
        len(lines) < 4
        or lines[0].strip() != _marker(name, "START")
        or lines[-1].strip() != _marker(name, "END")
    ):
        raise ValidationError(f"SITREP has malformed {name.lower()} table")
    actual = _split_row(lines[1])
    if actual != list(headers):
        raise ValidationError(f"{name.lower()} columns must be: " + " | ".join(headers))
    separators = _split_row(lines[2])
    if len(separators) != len(headers) or any(
        not re.fullmatch(r":?-{3,}:?", value) for value in separators
    ):
        raise ValidationError(f"SITREP has an invalid {name.lower()} separator row")
    rows: list[list[str]] = []
    for line in lines[3:-1]:
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
    headers = GLOBAL_TABLES[name]
    left, right = _bounds(text, name)
    return _parse_block(text[left:right], name, headers)


def write_global(text: str, name: str, rows: Iterable[Sequence[object]]) -> str:
    left, right = _bounds(text, name)
    return text[:left] + table_block(name, GLOBAL_TABLES[name], rows) + text[right:]


def _ensure_block_after_heading(
    text: str,
    *,
    name: str,
    headers: Sequence[str],
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
        raise ValidationError(f"SITREP has malformed {name.lower()} table markers")
    if has_start:
        return text
    match = re.search(rf"(?m)^{re.escape(heading)}\s*$", text[start:limit])
    if match is None:
        raise ValidationError(f"SITREP is missing the {heading.lstrip('# ')} heading")
    heading_end = start + match.end()
    return (
        text[:heading_end]
        + "\n\n"
        + table_block(name, headers, [])
        + text[heading_end:]
    )


def ensure_empty_tables(text: str) -> str:
    """Restore only absent empty tables; malformed or partial markers fail."""
    updated = text
    for name, headers in GLOBAL_TABLES.items():
        updated = _ensure_block_after_heading(
            updated,
            name=name,
            headers=headers,
            heading=f"## {GLOBAL_HEADINGS[name]}",
        )
    target_names = [section.name for section in target_sections(updated)]
    for target_name in target_names:
        section = target_section(updated, target_name)
        try:
            _bounds(updated, "PORTS", section.start, section.end)
        except ValidationError as exc:
            if "missing" not in str(exc):
                raise
            updated = _ensure_block_after_heading(
                updated,
                name="PORTS",
                headers=PORTS,
                heading="#### Ports",
                start=section.start,
                end=section.end,
            )
    return updated


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
    return _parse_block(text[left:right], name, headers)


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
    for table_name in (
        "NARRATIVE",
        "CREDENTIAL_CHECKS",
        "TODO",
        "COMPLETED",
        "CLEANUP",
    ):
        rows = read_global(updated, table_name)
        header = GLOBAL_TABLES[table_name]
        target_index = header.index("Target")
        changed = False
        for row in rows:
            if row[target_index] == old:
                row[target_index] = new
                changed = True
        if changed:
            updated = write_global(updated, table_name, rows)
    return updated


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

This is the engagement's working operational record. TACMUX manages only the
tables between its markers; prose outside those markers remains yours.

## Narrative

{table_block("NARRATIVE", NARRATIVE, [])}

## Targets

_No targets yet._

## Credentials

{table_block("CREDENTIALS", CREDENTIALS, [])}

## Credential Checks

{table_block("CREDENTIAL_CHECKS", CREDENTIAL_CHECKS, [])}

## TODO

{table_block("TODO", TODO, [])}

## Completed

{table_block("COMPLETED", COMPLETED, [])}

## Cleanup

{table_block("CLEANUP", CLEANUP, [])}
"""


def heading_line(text: str, section: str) -> int:
    aliases = {
        "narrative": "## Narrative",
        "targets": "## Targets",
        "credentials": "## Credentials",
        "creds": "## Credentials",
        "checks": "## Credential Checks",
        "todo": "## TODO",
        "completed": "## Completed",
        "cleanup": "## Cleanup",
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
