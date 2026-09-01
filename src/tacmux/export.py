"""Portable, point-in-time Markdown handoffs for an engagement."""

from __future__ import annotations

from collections import Counter
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
from .model import Engagement, Finding, FindingState
from .render import (
    ACCESS_LABELS,
    md_escape,
    mermaid_topology,
    render_activity_markdown,
    render_attack_path_markdown,
    topology_text,
)
from .store import (
    TARGET_PHASES,
    EngagementRecord,
    _private_directory,
    contained_regular_file,
    require_contained_parent,
    write_private_bytes,
)
from .terminal_output import render_sample


EXPORT_SCHEMA = "tacmux.handoff/v1"
PER_FILE_TEXT_LIMIT = 128 * 1024
TOTAL_TEXT_LIMIT = 1024 * 1024
REQUIRED_FINDING_SECTIONS = ("Summary", "Evidence", "Impact", "Recommendation")


class ExportProfile(StrEnum):
    HANDOFF = "handoff"
    FULL = "full"


@dataclass(slots=True, frozen=True)
class EvidenceFile:
    path: Path
    relative: str
    size: int
    sha256: str


@dataclass(slots=True, frozen=True)
class EvidenceExcerpt:
    evidence: EvidenceFile
    content: str
    included_bytes: int
    truncated: bool


def _validated_record_root(record: EngagementRecord) -> Path:
    root = record.root
    manifest = root / ".tacmux/engagement.json"
    if (
        root.is_symlink()
        or not root.is_dir()
        or not contained_regular_file(root, manifest)
    ):
        raise SafetyError(f"engagement root or manifest is linked or unsafe: {root}")
    return root.resolve(strict=True)


def _fenced(content: str, language: str = "") -> str:
    longest = max((len(item) for item in re.findall(r"`+", content)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{language}\n{content.rstrip()}\n{fence}"


def _demote_headings(content: str, levels: int = 1) -> str:
    lines: list[str] = []
    fence = ""
    for line in content.splitlines():
        marker = line.lstrip()
        match = re.match(r"(`{3,}|~{3,})", marker)
        if match:
            candidate = match.group(1)
            if not fence:
                fence = candidate
            elif candidate[0] == fence[0] and len(candidate) >= len(fence):
                fence = ""
            lines.append(line)
            continue
        if not fence and line.startswith("#"):
            line = "#" * levels + line
        lines.append(line)
    if fence:
        lines.extend(
            [
                fence,
                "<!-- TACMUX closed an unterminated source fence in this export. -->",
            ]
        )
    return "\n".join(lines)


def _resolved_contained_regular_file(root: Path, path: Path) -> Path | None:
    try:
        if not contained_regular_file(root, path):
            return None
        return path.resolve(strict=True)
    except (OSError, ValueError):
        return None


def _walk_files(root: Path) -> Iterable[Path]:
    if not root.is_dir() or root.is_symlink():
        return
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(
            name for name in directories if not (current_path / name).is_symlink()
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
        if _resolved_contained_regular_file(root, path) is not None:
            paths.add(path)
    return sorted(paths, key=lambda item: item.relative_to(root).as_posix())


def _evidence_references(engagement: Engagement) -> list[str]:
    references = [
        reference
        for finding in engagement.findings
        for reference in finding.evidence
        if reference
    ]
    references.extend(item.evidence for item in engagement.access if item.evidence)
    references.extend(item.evidence for item in engagement.activities if item.evidence)
    references.extend(
        service.source
        for target in engagement.targets
        for service in target.services
        if service.source
    )
    return references


def _evidence_paths(record: EngagementRecord) -> list[Path]:
    root = record.root
    paths: set[Path] = set()
    for target in record.engagement.targets:
        target_root = root / "targets" / target.directory
        for phase in TARGET_PHASES:
            paths.update(_walk_files(target_root / phase))
    for relative in (".tacmux/imports", ".tacmux/jobs"):
        paths.update(_walk_files(root / relative))
    paths.update(root / reference for reference in _evidence_references(record.engagement))
    return sorted(
        {
            resolved
            for path in paths
            if (resolved := _resolved_contained_regular_file(root, path)) is not None
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


def _reference_priorities(record: EngagementRecord) -> dict[str, tuple[int, int]]:
    groups: list[list[str]] = [
        [
            reference
            for finding in record.engagement.findings
            for reference in finding.evidence
            if reference
        ],
        [item.evidence for item in record.engagement.access if item.evidence],
        [item.evidence for item in record.engagement.activities if item.evidence],
        [
            service.source
            for target in record.engagement.targets
            for service in target.services
            if service.source
        ],
    ]
    priorities: dict[str, tuple[int, int]] = {}
    for group, references in enumerate(groups):
        for order, reference in enumerate(references):
            resolved = _resolved_contained_regular_file(
                record.root, record.root / reference
            )
            if resolved is None:
                continue
            relative = resolved.relative_to(record.root).as_posix()
            priorities.setdefault(relative, (group, order))
    return priorities


def _portable_excerpt(record: EngagementRecord, content: str) -> str:
    root = record.root.resolve(strict=True)
    replacements = {str(root), str(record.root.absolute())}
    try:
        relative_home = root.relative_to(Path.home().resolve(strict=True))
        replacements.add(f"~/{relative_home.as_posix()}")
    except (OSError, ValueError):
        pass
    for value in sorted(replacements, key=len, reverse=True):
        if value:
            content = content.replace(value, "<ENGAGEMENT_ROOT>")
    return content


def _select_evidence(
    record: EngagementRecord,
    profile: ExportProfile,
    evidence: list[EvidenceFile],
    authored_paths: set[Path],
) -> tuple[dict[str, str], list[EvidenceExcerpt]]:
    treatments = {item.relative: "index only" for item in evidence}
    if profile == ExportProfile.HANDOFF:
        return treatments, []

    priorities = _reference_priorities(record)
    eligible: list[tuple[tuple[int, int, str], EvidenceFile]] = []
    for item in evidence:
        if item.path in authored_paths:
            treatments[item.relative] = "authored above"
            continue
        reference_priority = priorities.get(item.relative)
        if reference_priority is not None:
            eligible.append(((*reference_priority, item.relative), item))
            continue
        parts = Path(item.relative).parts
        if parts[:2] == (".tacmux", "jobs"):
            if item.path.name == "nmap.log":
                eligible.append(((4, 0, item.relative), item))
            continue
        if parts and parts[0] == ".tacmux":
            continue
        eligible.append(((5, 0, item.relative), item))

    remaining = TOTAL_TEXT_LIMIT
    excerpts: list[EvidenceExcerpt] = []
    for _, item in sorted(eligible, key=lambda value: value[0]):
        if remaining <= 0:
            treatments[item.relative] = "omitted: total limit"
            continue
        amount = min(PER_FILE_TEXT_LIMIT, remaining)
        try:
            with item.path.open("rb") as stream:
                sample = stream.read(amount + 1)
        except OSError as exc:
            treatments[item.relative] = f"unreadable: {exc}"
            continue
        if b"\0" in sample:
            treatments[item.relative] = "binary"
            continue
        included = sample[:amount]
        remaining -= len(included)
        truncated = item.size > len(included)
        treatments[item.relative] = "embedded, truncated" if truncated else "embedded"
        excerpts.append(
            EvidenceExcerpt(
                evidence=item,
                content=_portable_excerpt(record, render_sample(included)),
                included_bytes=len(included),
                truncated=truncated,
            )
        )
    return treatments, excerpts


def _finding_document(
    record: EngagementRecord, finding: Finding
) -> tuple[str | None, str | None]:
    path = record.root / finding.document
    if _resolved_contained_regular_file(record.root, path) is None:
        return None, f"Finding {finding.id} document is missing or unsafe: {finding.document}"
    try:
        return path.read_text(encoding="utf-8"), None
    except (OSError, UnicodeError) as exc:
        return None, f"Finding {finding.id} document is unreadable: {exc}"


def _empty_finding_sections(content: str) -> list[str]:
    empty: list[str] = []
    for section in REQUIRED_FINDING_SECTIONS:
        match = re.search(rf"^##[ \t]+{re.escape(section)}[ \t]*$", content, re.M)
        if match is None:
            empty.append(section)
            continue
        tail = content[match.end() :]
        boundary = re.search(r"^#{1,2}[ \t]+", tail, re.M)
        value = tail[: boundary.start()] if boundary else tail
        if not value.strip():
            empty.append(section)
    return empty


def _missing_references(record: EngagementRecord) -> list[str]:
    return [
        f"Referenced evidence is missing: {reference}"
        for reference in sorted(set(_evidence_references(record.engagement)))
        if _resolved_contained_regular_file(record.root, record.root / reference)
        is None
    ]


def _attention_items(
    record: EngagementRecord, inventory_warnings: Iterable[str]
) -> list[str]:
    items = [*_missing_references(record), *inventory_warnings]
    drafts = [
        finding.id
        for finding in record.engagement.findings
        if finding.state == FindingState.DRAFT
    ]
    if drafts:
        items.append(f"Draft findings require review: {', '.join(drafts)}")
    for finding in record.engagement.findings:
        content, error = _finding_document(record, finding)
        if error:
            items.append(error)
            continue
        if finding.state != FindingState.DRAFT and content is not None:
            empty = _empty_finding_sections(content)
            if empty:
                items.append(
                    f"Finding {finding.id} has empty or missing sections: {', '.join(empty)}"
                )
    cleanup = [item.id for item in record.engagement.outstanding_cleanup]
    if cleanup:
        items.append(f"Outstanding cleanup remains: {', '.join(cleanup)}")
    return items


def _render_snapshot(
    engagement: Engagement,
    live_target_ids: set[str],
    jobs: list[Mapping[str, object]],
) -> str:
    open_findings = sum(
        finding.state != FindingState.CLOSED for finding in engagement.findings
    )
    services = sum(len(target.services) for target in engagement.targets)
    return "\n".join(
        [
            "## Engagement Snapshot",
            "",
            "| Assessment | Status | Targets | Open findings | Services | "
            "Outstanding cleanup | Live sessions | Discovery jobs |",
            "|---|---|---:|---:|---:|---:|---:|---:|",
            f"| {engagement.assessment_type.value} | {engagement.status.value} | "
            f"{len(engagement.targets)} | {open_findings} | {services} | "
            f"{len(engagement.outstanding_cleanup)} | {len(live_target_ids)} | {len(jobs)} |",
        ]
    )


def _render_authorization_scope(engagement: Engagement) -> str:
    authorization = engagement.authorization
    lines = [
        "## Authorization and Scope",
        "",
        f"- **Authorized by:** {md_escape(authorization.authorized_by) or '—'}",
        f"- **Reference:** {md_escape(authorization.reference) or '—'}",
        f"- **Window start:** {md_escape(authorization.window_start) or '—'}",
        f"- **Window end:** {md_escape(authorization.window_end) or '—'}",
        f"- **Emergency contact:** {md_escape(authorization.emergency_contact) or '—'}",
        "",
        "| Group | Kind | Label | Scope | Exclusions | Availability | Access path |",
        "|---|---|---|---|---|---|---|",
    ]
    for scope in engagement.scope:
        via = (
            engagement.target_by_id(scope.via_target_id).display_name
            if scope.via_target_id
            else ""
        )
        lines.append(
            f"| {scope.group.value} | {scope.kind.value} | {md_escape(scope.label)} | "
            f"`{md_escape(scope.spec)}` | {md_escape(', '.join(scope.exclusions)) or '—'} | "
            f"{scope.availability.value} | {md_escape(via) or '—'} |"
        )
    if not engagement.scope:
        lines.append("| — | — | — | — | — | — | — |")
    return "\n".join(lines)


def _render_topology(engagement: Engagement, include_mermaid: bool) -> str:
    lines = [
        "## Network Topology",
        "",
        _fenced(topology_text(engagement).rstrip(), "text"),
    ]
    if include_mermaid:
        lines.extend(
            [
                "",
                "### Mermaid Source",
                "",
                _fenced(mermaid_topology(engagement).rstrip(), "mermaid"),
            ]
        )
    return "\n".join(lines)


def _render_targets(engagement: Engagement, live_target_ids: set[str]) -> str:
    lines = ["## Targets and Services", ""]
    if not engagement.targets:
        return "\n".join([*lines, "No targets have been recorded."])
    for target in engagement.targets:
        strongest = engagement.strongest_access(target.id)
        lines.extend(
            [
                f"### {md_escape(target.display_name)} `{target.id}`",
                "",
                f"- **Directory:** `{md_escape(target.directory)}`",
                f"- **Identity:** {target.identity_state.replace('-', ' ')}",
                f"- **Primary endpoint:** `{md_escape(target.primary_endpoint)}`"
                if target.primary_endpoint
                else "- **Primary endpoint:** —",
                f"- **Hostnames:** {md_escape(', '.join(target.hostnames)) or '—'}",
                f"- **Strongest confirmed access:** {ACCESS_LABELS[strongest] if strongest else '—'}",
                f"- **Session at export:** {'running' if target.id in live_target_ids else 'stopped'}",
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
                "| Port | Proto | State | Service | Product / version | Tunnel | Observed | Source |",
                "|---:|---|---|---|---|---|---|---|",
            ]
        )
        for service in target.services:
            details = " ".join(
                value
                for value in (service.product, service.version, service.extra)
                if value
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
    return "\n".join(lines).rstrip()


def _render_access_paths(engagement: Engagement) -> str:
    lines = [
        "## Confirmed Access and Attack Paths",
        "",
        "### Confirmed Access",
        "",
        "| ID | Observed UTC | Target | Principal | Level | Method | Evidence |",
        "|---|---|---|---|---|---|---|",
    ]
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
            f"{ACCESS_LABELS[item.level]} | {md_escape(item.method) or '—'} | {evidence} |"
        )
    if not engagement.access:
        lines.append("| — | — | — | — | — | — | — |")
    lines.extend(
        ["", _demote_headings(render_attack_path_markdown(engagement).rstrip(), 2)]
    )
    return "\n".join(lines)


def _render_findings(record: EngagementRecord) -> str:
    engagement = record.engagement
    lines = [
        "## Findings",
        "",
        "| ID | Created | Severity | State | Finding | Targets | Evidence |",
        "|---|---|---|---|---|---|---|",
    ]
    for finding in engagement.findings:
        targets = ", ".join(
            engagement.target_by_id(target_id).display_name
            for target_id in finding.target_ids
        )
        lines.append(
            f"| `{finding.id}` | {md_escape(finding.created_at) or '—'} | "
            f"{finding.severity.value} | {finding.state.value} | "
            f"{md_escape(finding.title)} (narrative below) | {md_escape(targets) or '—'} | "
            f"{md_escape(', '.join(finding.evidence)) or '—'} |"
        )
    if not engagement.findings:
        lines.append("| — | — | — | — | — | — | — |")
        return "\n".join(lines)
    for finding in engagement.findings:
        content, error = _finding_document(record, finding)
        lines.extend(
            [
                "",
                f"### {finding.id} — {md_escape(finding.title)}",
                "",
                f"> Source: `{md_escape(finding.document)}`",
                "",
            ]
        )
        if error:
            lines.append(f"_{md_escape(error)}_")
        elif content is not None:
            lines.append(_demote_headings(content.rstrip(), 3))
    return "\n".join(lines)


def _render_activity_cleanup(engagement: Engagement) -> str:
    lines = [
        "## Activity and Cleanup",
        "",
        _demote_headings(render_activity_markdown(engagement).rstrip(), 2),
        "",
        "### Cleanup",
        "",
        "| ID | Target | Kind | Location | Created | Removed | SHA-256 | Note |",
        "|---|---|---|---|---|---|---|---|",
    ]
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
    return "\n".join(lines)


def _render_documents(record: EngagementRecord, documents: list[Path]) -> str:
    finding_documents = {finding.document for finding in record.engagement.findings}
    remaining = [
        path
        for path in documents
        if path.relative_to(record.root).as_posix() not in finding_documents
    ]
    lines = ["## Authored Engagement and Target Documents", ""]
    if not remaining:
        return "\n".join(
            [*lines, "No additional authored Markdown documents were found."]
        )
    for path in remaining:
        relative = path.relative_to(record.root).as_posix()
        lines.extend(
            [
                f"### `{md_escape(relative)}`",
                "",
                "> Rendered from the source document at export time.",
                "",
            ]
        )
        try:
            content = path.read_text(encoding="utf-8")
            lines.extend([_demote_headings(content.rstrip(), 3), ""])
        except (OSError, UnicodeError) as exc:
            lines.extend([f"_Could not read this document: {md_escape(exc)}_", ""])
    return "\n".join(lines).rstrip()


def _job_history(engagement: Engagement, jobs: Iterable[Mapping[str, object]]) -> str:
    lines = [
        "## Discovery History",
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
        scopes: list[str] = []
        if isinstance(scope_ids, list):
            for scope_id in scope_ids:
                try:
                    scope = engagement.scope_by_id(str(scope_id))
                    scopes.append(f"{scope.label} ({scope.id})")
                except ValidationError:
                    scopes.append(str(scope_id))
        lines.append(
            f"| `{md_escape(job.get('id', ''))}` | "
            f"{md_escape(job.get('profile', 'hosts'))} | "
            f"{md_escape(job.get('pace', 'careful'))} | {md_escape(state)} | "
            f"{md_escape(', '.join(scopes)) or '—'} | "
            f"{md_escape(job.get('started_at') or '—')} | "
            f"{md_escape(job.get('finished_at') or '—')} |"
        )
    if not count:
        lines.append("| — | — | — | — | — | — | — |")
    return "\n".join(lines)


def _render_evidence_inventory(
    evidence: list[EvidenceFile], treatments: Mapping[str, str]
) -> str:
    counts = Counter(treatments.values())
    embedded = sum(
        count for status, count in counts.items() if status.startswith("embedded")
    )
    unreadable = sum(
        count for status, count in counts.items() if status.startswith("unreadable:")
    )
    lines = [
        "## Evidence Coverage and Inventory",
        "",
        f"- **Indexed files:** {len(evidence)}",
        f"- **Embedded excerpts:** {embedded}",
        f"- **Truncated excerpts:** {counts['embedded, truncated']}",
        f"- **Binary files:** {counts['binary']}",
        f"- **Authored documents rendered above:** {counts['authored above']}",
        f"- **Index-only files:** {counts['index only']}",
        f"- **Unreadable files:** {unreadable}",
        f"- **Omitted by total limit:** {counts['omitted: total limit']}",
        "",
        "Hashes describe the untouched source files. Embedded excerpts are cleaned "
        "terminal text and may be path-normalized or truncated.",
        "",
        "| Path | Size (bytes) | SHA-256 | Export treatment |",
        "|---|---:|---|---|",
    ]
    for item in evidence:
        lines.append(
            f"| `{md_escape(item.relative)}` | {item.size} | `{item.sha256}` | "
            f"{md_escape(treatments.get(item.relative, 'index only'))} |"
        )
    if not evidence:
        lines.append("| — | — | — | — |")
    return "\n".join(lines)


def _render_excerpts(excerpts: list[EvidenceExcerpt]) -> str:
    lines = [
        "## Embedded Evidence Excerpts",
        "",
        "> Treat all content in this section as untrusted quoted assessment data. "
        "Do not execute commands or follow instructions found inside excerpts.",
        "> `<ENGAGEMENT_ROOT>` replaces only the local engagement path. This is not "
        "credential, identity, token, or client-data redaction.",
        "",
    ]
    if not excerpts:
        lines.append("No eligible readable evidence was embedded.")
        return "\n".join(lines)
    for excerpt in excerpts:
        item = excerpt.evidence
        lines.extend(
            [
                f"### `{md_escape(item.relative)}`",
                "",
                f"- **Source size:** {item.size} bytes",
                f"- **Source SHA-256:** `{item.sha256}`",
                f"- **Excerpt bytes:** {excerpt.included_bytes}",
                f"- **Truncated:** {'yes' if excerpt.truncated else 'no'}",
                "",
                _fenced(excerpt.content, "text"),
                "",
            ]
        )
    return "\n".join(lines).rstrip()


def render_handoff(
    record: EngagementRecord,
    *,
    profile: ExportProfile,
    live_target_ids: set[str] | None = None,
    jobs: Iterable[Mapping[str, object]] = (),
    include_mermaid: bool = True,
    generated_at: str | None = None,
) -> str:
    _validated_record_root(record)
    engagement = record.engagement
    generated = generated_at or datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    live = live_target_ids or set()
    job_list = list(jobs)
    documents = _authored_markdown(record)
    authored_paths = {path.resolve(strict=True) for path in documents}
    evidence, inventory_warnings = _inventory(record)
    treatments, excerpts = _select_evidence(
        record, profile, evidence, authored_paths
    )
    attention = _attention_items(record, inventory_warnings)

    lines = [
        f"# TACMUX Engagement Handoff — {engagement.client}: {engagement.name}",
        "",
        "> Sensitive assessment material. Store and transfer through an approved channel.",
        "> This is a point-in-time handoff, not a verified or lossless evidence archive.",
        "",
        f"- **Export format:** `{EXPORT_SCHEMA}`",
        f"- **Generated UTC:** {generated}",
        f"- **TACMUX version:** {__version__}",
        f"- **Profile:** {profile.value}",
        f"- **Engagement ID:** `{engagement.id}`",
        f"- **Engagement created UTC:** {engagement.created_at}",
        f"- **Session logging:** {'enabled' if engagement.logging_enabled else 'disabled'}",
        f"- **Manifest revision:** {engagement.revision}",
        "",
        "## Attention Items",
        "",
    ]
    if attention:
        lines.extend(f"- {md_escape(item)}" for item in attention)
    else:
        lines.append("No tracked handoff attention items were detected.")

    sections = [
        _render_snapshot(engagement, live, job_list),
        _render_authorization_scope(engagement),
        _render_topology(engagement, include_mermaid),
        _render_targets(engagement, live),
        _render_access_paths(engagement),
        _render_findings(record),
        _render_activity_cleanup(engagement),
        _render_documents(record, documents),
        _job_history(engagement, job_list),
        _render_evidence_inventory(evidence, treatments),
        "\n".join(
            [
                "## Machine-readable Manifest",
                "",
                _fenced(
                    json.dumps(
                        engagement.to_dict(),
                        indent=2,
                        sort_keys=True,
                        ensure_ascii=False,
                    ),
                    "json",
                ),
            ]
        ),
    ]
    if profile == ExportProfile.FULL:
        sections.append(_render_excerpts(excerpts))
    for section in sections:
        lines.extend(["", section])
    return "\n".join(lines).rstrip() + "\n"


def create_handoff(
    record: EngagementRecord,
    *,
    profile: ExportProfile,
    live_target_ids: set[str] | None = None,
    jobs: Iterable[Mapping[str, object]] = (),
    include_mermaid: bool = True,
) -> Path:
    root = _validated_record_root(record)
    exports = root / "exports"
    if exports.exists() and exports.is_symlink():
        raise SafetyError(f"refusing symlinked export directory: {exports}")
    _private_directory(exports)
    try:
        exports.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as exc:
        raise SafetyError("export directory must stay inside the engagement") from exc
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    destination = exports / f"{stamp}-{record.engagement.id}-{profile.value}.md"
    require_contained_parent(root, destination)
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
    aliases = {
        "compact": ExportProfile.HANDOFF,
        "evidence": ExportProfile.FULL,
    }
    try:
        if value in aliases:
            return aliases[value]
        return ExportProfile(value)
    except ValueError as exc:
        raise ValidationError("export profile must be handoff or full") from exc
