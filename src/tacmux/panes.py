"""Presentation-only widgets for the engagement cockpit."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from rich.markdown import Markdown as RichMarkdown
from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import DataTable, Label, Static

from .errors import TacmuxError, ValidationError
from .model import Engagement, Target
from .render import ACCESS_LABELS, attack_paths_text, topology_text
from .store import EngagementRecord
from .terminal_output import render_sample


def bounded_files(
    root: Path, limit: int, scan_budget: int = 2_000
) -> tuple[list[Path], bool]:
    files: list[Path] = []
    pending = [root]
    scanned = 0
    while pending and len(files) < limit and scanned < scan_budget:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    scanned += 1
                    if scanned > scan_budget:
                        break
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        pending.append(Path(entry.path))
                    elif entry.is_file(follow_symlinks=False):
                        files.append(Path(entry.path))
                        if len(files) >= limit:
                            break
        except OSError:
            continue
    return files, bool(pending) or scanned >= scan_budget or len(files) >= limit


class TargetsPane(Horizontal):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.engagement: Engagement | None = None

    def compose(self) -> ComposeResult:
        yield DataTable(id="target-table", cursor_type="row", zebra_stripes=True)
        yield Static("No target selected", id="target-detail")

    def selected_target_id(self, *, required: bool = True) -> str | None:
        table = self.query_one("#target-table", DataTable)
        if table.row_count == 0:
            if required:
                raise ValidationError("no target is selected")
            return None
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        return str(row_key.value)

    def populate(
        self, engagement: Engagement, live_target_ids: set[str], query: str = ""
    ) -> None:
        self.engagement = engagement
        table = self.query_one("#target-table", DataTable)
        if not table.columns:
            table.add_columns("State", "Group", "Target", "Addresses", "Access")
        table.clear()
        query = query.casefold().strip()
        for target in engagement.targets:
            addresses = ", ".join(item.value for item in target.addresses)
            identity = target.identity_state.replace("-", " ")
            haystack = (
                f"{target.display_name} {addresses} {' '.join(target.hostnames)}"
            ).casefold()
            if query and query not in haystack:
                continue
            groups = sorted(
                {
                    engagement.scope_by_id(item.scope_id).group.value
                    for item in target.addresses
                }
            )
            access = engagement.strongest_access(target.id)
            table.add_row(
                "RUN" if target.id in live_target_ids else "—",
                "/".join(groups) or "—",
                target.display_name,
                addresses or identity,
                ACCESS_LABELS[access] if access else "—",
                key=target.id,
            )
        selected = self.selected_target_id(required=False)
        self.update_detail(engagement.target_by_id(selected) if selected else None)

    def update_detail(self, target: Target | None) -> None:
        detail = self.query_one("#target-detail", Static)
        if target is None or self.engagement is None:
            detail.update(
                "No target selected\n\nPress n to create one or d to import discovery."
            )
            return
        access = [
            item for item in self.engagement.access if item.target_id == target.id
        ]
        recent = [
            item for item in self.engagement.activities if item.target_id == target.id
        ][-5:]
        lines = [
            f"{target.display_name}  {target.id}",
            "",
            "Identity: "
            + target.identity_state.replace("-", " "),
            f"Directory: {target.directory}",
            f"Primary: {target.primary_endpoint or '—'}",
            f"Addresses: {', '.join(item.value for item in target.addresses) or '—'}",
            f"Hostnames: {', '.join(target.hostnames) or '—'}",
            "",
            "Confirmed access",
        ]
        if access:
            lines.extend(
                f"• {item.authority + chr(92) if item.authority else ''}{item.principal}: "
                f"{ACCESS_LABELS[item.level]} via {item.method or 'unspecified'}"
                for item in access
            )
        else:
            lines.append("• None")
        lines.extend(["", "Recent curated activity"])
        lines.extend(f"• {item.result.value}: {item.summary}" for item in recent)
        if not recent:
            lines.append("• None")
        detail.update(Text("\n".join(lines)))

    @on(DataTable.RowHighlighted, "#target-table")
    def row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if self.engagement is not None:
            try:
                target = self.engagement.target_by_id(str(event.row_key.value))
            except TacmuxError:
                return
            self.update_detail(target)


class ScopeDiscoveryPane(Static):
    def compose(self) -> ComposeResult:
        yield Label("Declared Scope", classes="section-title")
        yield DataTable(id="scope-table", cursor_type="row", zebra_stripes=True)
        yield Label("Detached Discovery Jobs", classes="section-title")
        yield DataTable(id="jobs-table", cursor_type="row", zebra_stripes=True)

    def populate(self, engagement: Engagement, jobs: list[dict]) -> None:
        table = self.query_one("#scope-table", DataTable)
        if not table.columns:
            table.add_columns("Group", "Label", "Network", "Availability", "Via")
        table.clear()
        for item in engagement.scope:
            via = (
                engagement.target_by_id(item.via_target_id).display_name
                if item.via_target_id
                else "—"
            )
            table.add_row(
                item.group.value,
                item.label,
                item.network,
                item.availability.value,
                via,
                key=item.id,
            )
        jobs_table = self.query_one("#jobs-table", DataTable)
        if not jobs_table.columns:
            jobs_table.add_columns("Job", "State", "Scope", "Started", "Result")
        jobs_table.clear()
        for job in jobs:
            state = str(job.get("state", ""))
            if job.get("imported_at"):
                state += " / imported"
            jobs_table.add_row(
                str(job.get("id", "")),
                state,
                ", ".join(job.get("scope_ids", [])),
                str(job.get("started_at") or "—")[:19],
                str(job.get("xml_path", "")),
                key=str(job.get("id", "")),
            )

    def selected_scope_id(self) -> str:
        table = self.query_one("#scope-table", DataTable)
        if table.row_count == 0:
            raise ValidationError("no scope entry is selected")
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        return str(row_key.value)

    def selected_job_id(self) -> str:
        table = self.query_one("#jobs-table", DataTable)
        if table.row_count == 0:
            raise ValidationError("no discovery job is selected")
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        return str(row_key.value)


class SituationPane(Static):
    def populate(self, engagement: Engagement) -> None:
        topology = topology_text(engagement).rstrip()
        paths = attack_paths_text(engagement).rstrip()
        self.update(
            RichMarkdown(
                f"# Network Topology\n\n```text\n{topology}\n```\n\n"
                f"# Confirmed Attack Paths\n\n```text\n{paths}\n```\n"
            )
        )


class DocumentsPane(Horizontal):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.record: EngagementRecord | None = None
        self.document_paths: dict[str, tuple[Path, bool, str]] = {}

    def compose(self) -> ComposeResult:
        yield DataTable(id="documents-table", cursor_type="row", zebra_stripes=True)
        yield Static(id="document-preview")

    @staticmethod
    def _document_entries(
        record: EngagementRecord,
    ) -> list[tuple[str, Path, bool, str]]:
        entries = [
            ("Engagement narrative", record.root / "ENGAGEMENT.md", True, "markdown"),
            ("Generated SITREP", record.root / "SITREP.md", False, "generated"),
            (
                "Generated activity",
                record.root / "notes/activity.md",
                False,
                "generated",
            ),
            (
                "Generated attack paths",
                record.root / "notes/attack-path.md",
                False,
                "generated",
            ),
            ("Payload log", record.root / "notes/payloads.md", True, "markdown"),
        ]
        entries.extend(
            (
                f"Finding {item.id}: {item.title}",
                record.root / item.document,
                True,
                "markdown",
            )
            for item in record.engagement.findings
        )
        entries.extend(
            (
                f"Target {item.id}: {item.display_name}",
                record.root / "targets" / item.directory / "NOTES.md",
                True,
                "markdown",
            )
            for item in record.engagement.targets
        )
        return entries

    @staticmethod
    def _evidence_entries(
        record: EngagementRecord,
    ) -> tuple[list[tuple[str, Path, bool, str]], bool]:
        entries: list[tuple[str, Path, bool, str]] = []
        evidence_count = 0
        limit_reached = False
        for target in record.engagement.targets:
            target_root = record.root / "targets" / target.directory
            for phase in (
                "recon",
                "exploitation",
                "loot",
                "screenshots",
                "reports",
                "logs",
            ):
                phase_root = target_root / phase
                if not phase_root.is_dir():
                    continue
                paths, truncated = bounded_files(phase_root, 500 - evidence_count)
                for path in paths:
                    relative = path.relative_to(target_root)
                    editable = path.suffix.casefold() in {".md", ".markdown"}
                    entries.append(
                        (
                            f"{target.display_name} / {relative}",
                            path,
                            editable,
                            "markdown" if editable else "evidence",
                        )
                    )
                    evidence_count += 1
                if truncated:
                    limit_reached = True
                if limit_reached:
                    break
            if limit_reached:
                break
        return entries, limit_reached

    def populate(self, record: EngagementRecord) -> None:
        self.record = record
        entries = self._document_entries(record)
        evidence, limit_reached = self._evidence_entries(record)
        entries.extend(evidence)
        table = self.query_one("#documents-table", DataTable)
        if not table.columns:
            table.add_columns("Document / Evidence", "Mode")
        table.clear()
        self.document_paths.clear()
        for index, (label, path, editable, kind) in enumerate(entries):
            key = f"D{index:04d}"
            self.document_paths[key] = (path, editable, kind)
            table.add_row(label, "editable" if editable else kind, key=key)
        if limit_reached:
            self.app.notify(
                "Evidence list is limited to the first 500 files", severity="warning"
            )
        self.preview_selected()

    def selected_document(self) -> tuple[Path, bool, str] | None:
        table = self.query_one("#documents-table", DataTable)
        if table.row_count == 0:
            return None
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        return self.document_paths.get(str(row_key.value))

    def preview_selected(self) -> None:
        selected = self.selected_document()
        if selected is None:
            self.query_one("#document-preview", Static).update("No document selected.")
            return
        path, _, kind = selected
        try:
            preview = self.query_one("#document-preview", Static)
            size = path.stat().st_size
            with path.open("rb") as stream:
                sample = stream.read(256 * 1024)
            truncated = size > 256 * 1024
            if b"\0" in sample:
                digest = "not computed for files over 2 MiB"
                if size <= 2 * 1024 * 1024:
                    with path.open("rb") as stream:
                        digest = hashlib.file_digest(stream, "sha256").hexdigest()
                relative = (
                    path.relative_to(self.record.root) if self.record else path
                )
                preview.update(
                    Text(
                        f"Binary evidence\n\nPath: {relative}\n"
                        f"Size: {size:,} bytes\nSHA-256: {digest}"
                    )
                )
                return
            content = sample.decode("utf-8", errors="replace")
            truncation = ""
            if truncated:
                truncation = (
                    f"\n\n[preview truncated at 256 KiB; file size is {size:,} bytes]"
                )
            preview.update(
                RichMarkdown(content + truncation)
                if kind in {"markdown", "generated"}
                else Text(render_sample(sample) + truncation)
            )
        except OSError as exc:
            self.query_one("#document-preview", Static).update(
                f"Unable to read `{path}`: {exc}"
            )

    @on(DataTable.RowHighlighted, "#documents-table")
    def row_highlighted(self, _event: DataTable.RowHighlighted) -> None:
        self.preview_selected()
