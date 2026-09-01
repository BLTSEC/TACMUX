"""Portable, point-in-time Markdown handoffs for an engagement."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Iterable, Mapping

from . import __version__
from .errors import ConflictError, SafetyError, ValidationError
from .model import Engagement
from .render import (
    ACCESS_LABELS,
    md_escape,
    render_activity_markdown,
    render_attack_path_markdown,
    render_sitrep,
)
from .store import (
    TARGET_PHASES,
    EngagementRecord,
    _private_directory,
    write_private_bytes,
)
from .terminal_output import render_sample


PER_FILE_TEXT_LIMIT = 256 * 1024
TOTAL_TEXT_LIMIT = 2 * 1024 * 1024


class ExportProfile(StrEnum):
    COMPACT = "compact"
    EVIDENCE = "evidence"


@dataclass(slots=True, frozen=True)
class EvidenceFile:
    path: Path
    relative: str
    size: int
    sha256: str


def _fenced(content: str, language: str = "") -> str:
    longest = max((len(item) for item in re.findall(r"`+", content)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{language}\n{content.rstrip()}\n{fence}"


def _demote_headings(content: str, levels: int = 1) -> str:
    lines: list[str] = []
    fenced = False
    for line in content.splitlines():
        marker = line.lstrip()
        if marker.startswith("```") or marker.startswith("~~~"):
            fenced = not fenced
        if not fenced and line.startswith("#"):
            line = "#" * levels + line
        lines.append(line)
    return "\n".join(lines)


def _contained_regular_file(root: Path, path: Path) -> Path | None:
    try:
        if path.is_symlink():
            return None
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
        if not resolved.is_file():
            return None
        return resolved
    except (OSError, ValueError):
        return None


def _walk_files(root: Path) -> Iterable[Path]:
    if not root.is_dir() or root.is_symlink():
        return
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(
            name
            for name in directories
            if not (current_path / name).is_symlink()
        )
        for name in sorted(files):
            path = current_path / name
            if not path.is_symlink():
                yield path


def _authored_markdown(record: EngagementRecord) -> list[Path]:
    root = record.root
    generated = {
        root / "SITREP.md",
        root / "notes/activity.md",
        root / "notes/attack-path.md",
        root / "findings/README.md",
    }
    paths: set[Path] = set()
    for path in _walk_files(root):
        if path.suffix.casefold() not in {".md", ".markdown"}:
            continue
        if path in generated or "exports" in path.relative_to(root).parts:
            continue
        if _contained_regular_file(root, path) is not None:
            paths.add(path)
    return sorted(paths, key=lambda item: item.relative_to(root).as_posix())


def _evidence_paths(record: EngagementRecord) -> list[Path]:
    root = record.root
    paths: set[Path] = set()
    for target in record.engagement.targets:
        target_root = root / "targets" / target.directory
        for phase in TARGET_PHASES:
            paths.update(_walk_files(target_root / phase))
    for relative in (".tacmux/imports", ".tacmux/jobs"):
        paths.update(_walk_files(root / relative))
    references = [
        item.evidence for item in record.engagement.access if item.evidence
    ]
    references.extend(
        item.evidence for item in record.engagement.activities if item.evidence
    )
    references.extend(
        reference
        for item in record.engagement.findings
        for reference in item.evidence
    )
    references.extend(
        service.source
        for target in record.engagement.targets
        for service in target.services
        if service.source
    )
    paths.update(root / reference for reference in references)
    return sorted(
        {
            resolved
            for path in paths
            if (resolved := _contained_regular_file(root, path)) is not None
            and "exports" not in resolved.relative_to(root).parts
        },
        key=lambda item: item.relative_to(root).as_posix(),
    )


def _inventory(record: EngagementRecord) -> tuple[list[EvidenceFile], list[str]]:
    files: list[EvidenceFile] = []
    warnings: list[str] = []
    for path in _evidence_paths(record):
        relative = path.relative_to(record.root).as_posix()
        try:
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
            files.append(
                EvidenceFile(path, relative, path.stat().st_size, digest.hexdigest())
            )
        except OSError as exc:
            warnings.append(f"Could not inventory {relative}: {exc}")
    return files, warnings


def _records(engagement: Engagement) -> str:
    lines = [
        "## Complete Structured Records",
        "",
        "### Targets",
        "",
    ]
    for target in engagement.targets:
        lines.extend(
            [
                f"#### {md_escape(target.display_name)} `{target.id}`",
                "",
                f"- **Directory:** `{md_escape(target.directory)}`",
                f"- **Identity state:** {target.identity_state}",
                f"- **Primary endpoint:** `{md_escape(target.primary_endpoint)}`"
                if target.primary_endpoint
                else "- **Primary endpoint:** —",
                f"- **Hostnames:** {md_escape(', '.join(target.hostnames)) or '—'}",
                f"- **Created UTC:** {md_escape(target.created_at)}",
                "",
                "| Address | Scope |",
                "|---|---|",
            ]
        )
        for address in target.addresses:
            scope = engagement.scope_by_id(address.scope_id)
            lines.append(
                f"| `{md_escape(address.value)}` | {md_escape(scope.label)} (`{scope.id}`) |"
            )
        if not target.addresses:
            lines.append("| — | — |")
        lines.extend(
            [
                "",
                "| Port | Proto | State | Service | Product / version | "
                "Tunnel | Observed | Source |",
                "|---:|---|---|---|---|---|---|---|",
            ]
        )
        for service in target.services:
            details = " ".join(
                item
                for item in (service.product, service.version, service.extra)
                if item
            )
            lines.append(
                f"| {service.port} | {md_escape(service.protocol)} | "
                f"{md_escape(service.state)} | {md_escape(service.name) or '—'} | "
                f"{md_escape(details) or '—'} | {md_escape(service.tunnel) or '—'} | "
                f"{md_escape(service.observed_at)} | {md_escape(service.source) or '—'} |"
            )
        if not target.services:
            lines.append("| — | — | — | — | — | — | — | — |")
        lines.append("")
    if not engagement.targets:
        lines.extend(["No targets have been recorded.", ""])

    lines.extend(
        [
            "### Confirmed Access",
            "",
            "| ID | Observed UTC | Target | Principal | Level | Method | Evidence |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    for item in engagement.access:
        target = engagement.target_by_id(item.target_id)
        principal = (
            f"{item.authority}\\{item.principal}"
            if item.authority
            else item.principal
        )
        evidence = f"`{md_escape(item.evidence)}`" if item.evidence else "—"
        lines.append(
            f"| `{item.id}` | {md_escape(item.observed_at)} | "
            f"{md_escape(target.display_name)} (`{target.id}`) | {md_escape(principal)} | "
            f"{ACCESS_LABELS[item.level]} | {md_escape(item.method) or '—'} | "
            f"{evidence} |"
        )
    if not engagement.access:
        lines.append("| — | — | — | — | — | — | — |")

    lines.extend(
        [
            "",
            "### Findings",
            "",
            "| ID | Created | Severity | State | Finding | Targets | Evidence | Document |",
            "|---|---|---|---|---|---|---|---|",
        ]
    )
    for finding in engagement.findings:
        targets = ", ".join(
            engagement.target_by_id(item).display_name for item in finding.target_ids
        )
        lines.append(
            f"| `{finding.id}` | {md_escape(finding.created_at) or '—'} | "
            f"{finding.severity.value} | {finding.state.value} | "
            f"{md_escape(finding.title)} | {md_escape(targets) or '—'} | "
            f"{md_escape(', '.join(finding.evidence)) or '—'} | "
            f"`{md_escape(finding.document)}` |"
        )
    if not engagement.findings:
        lines.append("| — | — | — | — | — | — | — | — |")

    lines.extend(
        ["", _demote_headings(render_activity_markdown(engagement).rstrip(), 2), ""]
    )
    lines.extend(
        [_demote_headings(render_attack_path_markdown(engagement).rstrip(), 2), ""]
    )
    lines.extend(
        [
            "### Cleanup",
            "",
            "| ID | Target | Kind | Location | Created | Removed | SHA-256 | Note |",
            "|---|---|---|---|---|---|---|---|",
        ]
    )
    for item in engagement.cleanup:
        target = engagement.target_by_id(item.target_id)
        lines.append(
            f"| `{item.id}` | {md_escape(target.display_name)} (`{target.id}`) | "
            f"{item.kind.value} | {md_escape(item.location)} | "
            f"{md_escape(item.created_at)} | {md_escape(item.removed_at) or '—'} | "
            f"{md_escape(item.sha256) or '—'} | {md_escape(item.note) or '—'} |"
        )
    if not engagement.cleanup:
        lines.append("| — | — | — | — | — | — | — | — |")
    return "\n".join(lines).rstrip()


def _job_history(jobs: Iterable[Mapping[str, object]]) -> str:
    lines = [
        "## Discovery Job History",
        "",
        "| Job | Profile | Pace | State / phase | Scope | Started | Finished |",
        "|---|---|---|---|---|---|---|",
    ]
    count = 0
    for job in jobs:
        count += 1
        state = str(job.get("state", "unknown"))
        phase = str(job.get("phase") or "")
        if phase:
            state += f" / {phase}"
        scope_ids = job.get("scope_ids", [])
        scope = (
            ", ".join(str(item) for item in scope_ids)
            if isinstance(scope_ids, list)
            else "—"
        )
        lines.append(
            f"| `{md_escape(job.get('id', ''))}` | "
            f"{md_escape(job.get('profile', 'hosts'))} | "
            f"{md_escape(job.get('pace', 'careful'))} | {md_escape(state)} | "
            f"{md_escape(scope) or '—'} | {md_escape(job.get('started_at') or '—')} | "
            f"{md_escape(job.get('finished_at') or '—')} |"
        )
    if not count:
        lines.append("| — | — | — | — | — | — | — |")
    return "\n".join(lines)


def render_handoff(
    record: EngagementRecord,
    *,
    profile: ExportProfile,
    live_target_ids: set[str] | None = None,
    jobs: Iterable[Mapping[str, object]] = (),
    include_mermaid: bool = True,
    generated_at: str | None = None,
) -> str:
    engagement = record.engagement
    generated = generated_at or datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    job_list = list(jobs)
    evidence, inventory_warnings = _inventory(record)
    warnings = [
        *_missing_references(record),
        *inventory_warnings,
    ]
    lines = [
        f"# TACMUX Handoff — {engagement.client}: {engagement.name}",
        "",
        "> Sensitive assessment material. Store and transfer through an approved channel.",
        "> This is a point-in-time reporting handoff, not a verified evidence archive.",
        "",
        f"- **Generated UTC:** {generated}",
        f"- **TACMUX version:** {__version__}",
        f"- **Export profile:** {profile.value}",
        f"- **Engagement ID:** `{engagement.id}`",
        f"- **Manifest revision:** {engagement.revision}",
        "",
        _demote_headings(
            render_sitrep(
                engagement,
                live_sessions=live_target_ids or set(),
                jobs=job_list,
                include_mermaid=include_mermaid,
                warnings=warnings,
            ).rstrip()
        ),
        "",
        _records(engagement),
        "",
        _job_history(job_list),
        "",
        "## Authored Documents",
        "",
    ]
    documents = _authored_markdown(record)
    authored_paths = set(documents)
    if not documents:
        lines.append("No authored Markdown documents were found.")
    for path in documents:
        relative = path.relative_to(record.root).as_posix()
        lines.extend([f"### `{relative}`", ""])
        try:
            lines.extend([_fenced(path.read_text(encoding="utf-8"), "markdown"), ""])
        except (OSError, UnicodeError) as exc:
            lines.extend([f"_Could not read this document: {md_escape(exc)}_", ""])

    lines.extend(
        [
            "## Evidence Inventory",
            "",
            "| Path | Size (bytes) | SHA-256 |",
            "|---|---:|---|",
        ]
    )
    for item in evidence:
        lines.append(
            f"| `{md_escape(item.relative)}` | {item.size} | `{item.sha256}` |"
        )
    if not evidence:
        lines.append("| — | — | — |")

    if profile == ExportProfile.EVIDENCE:
        lines.extend(["", "## Embedded Text Evidence", ""])
        remaining = TOTAL_TEXT_LIMIT
        for item in evidence:
            if item.path in authored_paths:
                continue
            if remaining <= 0:
                lines.append(
                    f"- `{item.relative}` omitted: the {TOTAL_TEXT_LIMIT}-byte "
                    "total embedding limit was reached."
                )
                continue
            amount = min(PER_FILE_TEXT_LIMIT, remaining)
            try:
                with item.path.open("rb") as stream:
                    sample = stream.read(amount + 1)
            except OSError as exc:
                lines.append(f"- `{item.relative}` unreadable: {md_escape(exc)}")
                continue
            if b"\0" in sample:
                lines.append(f"- `{item.relative}` is binary and was not embedded.")
                continue
            included = sample[:amount]
            remaining -= len(included)
            truncated = item.size > len(included)
            lines.extend(
                [
                    f"### `{item.relative}`",
                    "",
                    _fenced(render_sample(included), "text"),
                ]
            )
            if truncated:
                lines.append(
                    f"_Truncated after {len(included)} of {item.size} bytes._"
                )
            lines.append("")

    lines.extend(
        [
            "## Machine-readable Manifest",
            "",
            _fenced(
                json.dumps(
                    engagement.to_dict(), indent=2, sort_keys=True, ensure_ascii=False
                ),
                "json",
            ),
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _missing_references(record: EngagementRecord) -> list[str]:
    engagement = record.engagement
    references: list[str] = []
    references.extend(item.evidence for item in engagement.access if item.evidence)
    references.extend(item.evidence for item in engagement.activities if item.evidence)
    references.extend(
        reference for item in engagement.findings for reference in item.evidence
    )
    references.extend(
        service.source
        for target in engagement.targets
        for service in target.services
        if service.source
    )
    return [
        f"Referenced evidence is missing: {reference}"
        for reference in sorted(set(references))
        if _contained_regular_file(record.root, record.root / reference) is None
    ]


def create_handoff(
    record: EngagementRecord,
    *,
    profile: ExportProfile,
    live_target_ids: set[str] | None = None,
    jobs: Iterable[Mapping[str, object]] = (),
    include_mermaid: bool = True,
) -> Path:
    root = record.root.resolve(strict=True)
    exports = root / "exports"
    if exports.exists() and exports.is_symlink():
        raise SafetyError(f"refusing symlinked export directory: {exports}")
    _private_directory(exports)
    try:
        exports.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as exc:
        raise SafetyError("export directory must stay inside the engagement") from exc
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    destination = exports / f"{stamp}-{record.engagement.id}-handoff.md"
    if destination.exists():
        raise ConflictError(f"export destination already exists: {destination}")
    document = render_handoff(
        record,
        profile=profile,
        live_target_ids=live_target_ids,
        jobs=jobs,
        include_mermaid=include_mermaid,
    )
    write_private_bytes(destination, document.encode("utf-8"), replace=False)
    return destination


def parse_export_profile(value: str) -> ExportProfile:
    try:
        return ExportProfile(value)
    except ValueError as exc:
        raise ValidationError("export profile must be compact or evidence") from exc
