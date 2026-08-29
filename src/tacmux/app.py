"""Transient Textual operator cockpit for TACMUX v2."""

from __future__ import annotations

from copy import deepcopy
from contextlib import suppress
from dataclasses import asdict, fields
import hashlib
import ipaddress
import os
from pathlib import Path
import shutil
import subprocess
from typing import ClassVar

from rich.markdown import Markdown as RichMarkdown
from rich.text import Text
from textual import events, on
from textual.app import App, ComposeResult, get_system_commands_provider
from textual.binding import Binding
from textual.command import DiscoveryHit, Hit, Hits, Provider
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Static,
    TabbedContent,
    TabPane,
)

from .archive import create_archive, restore_archive, verify_archive
from .config import Settings
from .dialogs import (
    AccessForm,
    ActionMenu,
    ActivityForm,
    AttackPathForm,
    ConfirmModal,
    DiscoveryReview,
    EngagementForm,
    FindingForm,
    ImportDiscoveryForm,
    LegacyImportForm,
    MessageModal,
    PromptModal,
    ScanForm,
    ScopeForm,
    TargetAddressForm,
    TargetForm,
)
from .discovery import (
    DiscoveryJobs,
    apply_reconciliation,
    parse_host_lines,
    parse_nmap_xml,
    reconcile_candidates,
)
from .errors import TacmuxError, ValidationError
from .migration import import_v1_workspace
from .model import (
    AccessRecord,
    Activity,
    AttackPath,
    AttackPathStep,
    Engagement,
    Finding,
    ScopeAvailability,
    ScopeGroup,
    Target,
    TargetAddress,
)
from .nocap import NocapReader
from .render import ACCESS_LABELS, attack_paths_text, topology_text
from .store import EngagementRecord, Workspace
from .tmux import LaunchIntent, TmuxService


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


class OperatorCommands(Provider):
    """Fuzzy access to the same actions exposed by visible UI controls."""

    def _commands(self) -> list[tuple[str, str, str]]:
        screen = self.screen
        return list(getattr(screen, "operator_commands", []))

    async def discover(self) -> Hits:
        for title, action, help_text in self._commands():
            yield DiscoveryHit(
                title,
                lambda name=action: self.screen.run_operator_command(name),
                help=help_text,
            )

    async def search(self, query: str) -> Hits:
        matcher = self.matcher(query)
        for title, action, help_text in self._commands():
            score = matcher.match(title)
            if score > 0:
                yield Hit(
                    score,
                    matcher.highlight(title),
                    lambda name=action: self.screen.run_operator_command(name),
                    help=help_text,
                )


class EngagementPickerScreen(Screen):
    BINDINGS: ClassVar[list[Binding]] = [
        Binding("enter", "open_selected", "Open", priority=True),
        Binding("n", "new_engagement", "New"),
        Binding("i", "import_legacy", "Import v1"),
        Binding("/", "filter", "Filter"),
        Binding("q", "app.quit", "Quit"),
    ]
    operator_commands: ClassVar[list[tuple[str, str, str]]] = [
        (
            "Open selected engagement",
            "open_selected",
            "Open the highlighted client or lab",
        ),
        (
            "Create engagement",
            "new_engagement",
            "Create an external, internal, both, or lab engagement",
        ),
        (
            "Copy a TACMUX v1 workspace",
            "import_legacy",
            "Copy existing evidence into a stable v2 layout",
        ),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="picker-body"):
            yield Label("Engagements", id="picker-title")
            yield Input(
                placeholder="Filter client, engagement, or type", id="engagement-filter"
            )
            yield DataTable(id="engagements", cursor_type="row", zebra_stripes=True)
            yield Static("n: new  i: copy v1  /: filter  Enter: open", id="picker-hint")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#engagement-filter", Input).display = False
        self.refresh_table()
        self.query_one("#engagements", DataTable).focus()

    def refresh_table(self, query: str = "") -> None:
        table = self.query_one("#engagements", DataTable)
        if not table.columns:
            table.add_columns("Client / Lab", "Engagement", "Type", "Created")
        table.clear()
        query = query.casefold()
        for record in self.app.workspace.list_engagements():
            engagement = record.engagement
            haystack = f"{engagement.client} {engagement.name} {engagement.assessment_type.value}".casefold()
            if query and query not in haystack:
                continue
            table.add_row(
                engagement.client,
                engagement.name,
                engagement.assessment_type.value.replace("_", " "),
                engagement.created_at[:10],
                key=engagement.id,
            )

    def selected_id(self) -> str:
        table = self.query_one("#engagements", DataTable)
        if table.row_count == 0:
            raise ValidationError("no engagement is selected")
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        return str(row_key.value)

    def action_open_selected(self) -> None:
        try:
            self.app.open_engagement(self.app.workspace.find(self.selected_id()))
        except TacmuxError as exc:
            self.app.show_error(str(exc))

    @on(DataTable.RowSelected, "#engagements")
    def row_selected(self) -> None:
        self.action_open_selected()

    def action_filter(self) -> None:
        field = self.query_one("#engagement-filter", Input)
        field.display = True
        field.focus()

    @on(Input.Changed, "#engagement-filter")
    def filter_changed(self, event: Input.Changed) -> None:
        self.refresh_table(event.value)

    @on(Input.Submitted, "#engagement-filter")
    def filter_submitted(self) -> None:
        self.query_one("#engagement-filter", Input).display = False
        self.query_one("#engagements", DataTable).focus()

    def action_new_engagement(self) -> None:
        self.app.push_screen(
            EngagementForm(self.app.settings.auto_log), self._create_engagement
        )

    def _create_engagement(self, value: dict | None) -> None:
        if value is None:
            return
        try:
            scope_specs: list[tuple[str, ScopeGroup, str, ScopeAvailability]] = []
            for group_name, group, availability in (
                ("external", ScopeGroup.EXTERNAL, ScopeAvailability.READY),
                (
                    "internal",
                    ScopeGroup.INTERNAL,
                    value["internal_availability"],
                ),
            ):
                for raw_line in value[group_name].splitlines():
                    line = raw_line.strip()
                    if not line:
                        continue
                    label, separator, network = line.partition("=")
                    network = network.strip() if separator else label.strip()
                    label = label.strip() if separator else network
                    scope_specs.append((label, group, network, availability))
            record = self.app.workspace.create_engagement(
                value["client"],
                value["name"],
                value["assessment_type"],
                logging_enabled=value["logging_enabled"],
                initial_scope=scope_specs,
            )
            self.app.open_engagement(record)
        except (TacmuxError, OSError, ValueError) as exc:
            self.app.show_error(str(exc))

    def action_import_legacy(self) -> None:
        self.app.push_screen(LegacyImportForm(), self._import_legacy)

    def _import_legacy(self, value: dict | None) -> None:
        if value is None:
            return
        try:
            record = import_v1_workspace(self.app.workspace, **value)
            self.app.open_engagement(record)
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))

    def run_operator_command(self, action: str) -> None:
        getattr(self, f"action_{action}")()


class MainScreen(Screen):
    BINDINGS: ClassVar[list[Binding]] = [
        Binding("enter", "default_action", "Open / Attach", priority=True),
        Binding("a", "actions", "Actions"),
        Binding("n", "new_target", "New target"),
        Binding("d", "discovery", "Discovery"),
        Binding("g", "switch_engagement", "Engagements"),
        Binding("/", "filter", "Filter"),
        Binding("r", "refresh", "Refresh"),
        Binding("1", "tab('targets')", "Targets", show=False),
        Binding("2", "tab('scope')", "Scope", show=False),
        Binding("3", "tab('situation')", "Situation", show=False),
        Binding("4", "tab('documents')", "Documents", show=False),
        Binding("q", "app.quit", "Quit"),
    ]
    operator_commands: ClassVar[list[tuple[str, str, str]]] = [
        (
            "Attach or start selected target",
            "attach",
            "Create a detached target session if needed, then enter it",
        ),
        (
            "Target actions",
            "actions",
            "Stop, rename, edit, archive, or delete the highlighted target",
        ),
        (
            "Add target",
            "new_target",
            "Create a target with an optional scope-qualified address",
        ),
        ("Add scope entry", "add_scope", "Declare an external or internal IP/CIDR"),
        (
            "Run detached host discovery",
            "scan",
            "Run the fixed Nmap host-identification profile",
        ),
        (
            "Import discovery results",
            "import_discovery",
            "Review Nmap XML or pasted IP/hostname lines",
        ),
        (
            "Import a completed discovery job",
            "import_completed",
            "Review the output of a successful detached scan",
        ),
        (
            "Record curated activity",
            "activity",
            "Record a confirmed, failed, or no-result activity",
        ),
        (
            "Build confirmed attack path",
            "attack_path",
            "Assemble a path from confirmed records",
        ),
        (
            "Manage engagement records",
            "records",
            "Edit or delete access, activity, findings, and attack paths",
        ),
        (
            "Open engagement operations session",
            "ops",
            "Create or enter the optional engagement-level tmux session",
        ),
        (
            "Stop engagement operations session",
            "stop_ops",
            "Stop only the optional engagement-level session",
        ),
        (
            "Stop every engagement session",
            "stop_all",
            "Stop target, operations, and discovery sessions for this engagement",
        ),
        (
            "Refresh topology, jobs, and SITREP",
            "refresh",
            "Reconcile live tmux and detached-job state",
        ),
        (
            "Archive entire engagement",
            "archive_engagement",
            "Create and verify a private engagement archive",
        ),
        (
            "Restore verified archive",
            "restore",
            "Restore an engagement or missing target from a v2 archive",
        ),
        ("Switch engagement", "switch_engagement", "Return to the engagement picker"),
    ]

    def __init__(self, record: EngagementRecord):
        super().__init__()
        self.record = record
        self.document_paths: dict[str, tuple[Path, bool, str]] = {}
        self.pending_job_id = ""

    @property
    def engagement(self) -> Engagement:
        return self.record.engagement

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Label(
            f"{self.engagement.client}  /  {self.engagement.name}",
            id="engagement-banner",
        )
        yield Input(placeholder="Filter targets", id="target-filter")
        with TabbedContent(initial="targets", id="workspace-tabs"):
            with TabPane("Targets", id="targets"), Horizontal(id="target-layout"):
                yield DataTable(
                    id="target-table", cursor_type="row", zebra_stripes=True
                )
                yield Static("No target selected", id="target-detail")
            with TabPane("Scope & Discovery", id="scope"):
                yield Label("Declared Scope", classes="section-title")
                yield DataTable(id="scope-table", cursor_type="row", zebra_stripes=True)
                yield Label("Detached Discovery Jobs", classes="section-title")
                yield DataTable(id="jobs-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Situation", id="situation"):
                yield Static(id="situation-view")
            with (
                TabPane("Documents", id="documents"),
                Horizontal(id="documents-layout"),
            ):
                yield DataTable(
                    id="documents-table", cursor_type="row", zebra_stripes=True
                )
                yield Static(id="document-preview")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#target-filter", Input).display = False
        self.app.title = "TACMUX"
        self.app.sub_title = f"{self.engagement.client}: {self.engagement.name}"
        self.refresh_all()
        self.query_one("#target-table", DataTable).focus()

    def on_resize(self, event: events.Resize) -> None:
        self.set_class(event.size.width < 100, "narrow")

    def action_tab(self, tab_id: str) -> None:
        self.query_one("#workspace-tabs", TabbedContent).active = tab_id
        focus_target = {
            "targets": "#target-table",
            "scope": "#scope-table",
            "documents": "#documents-table",
        }.get(tab_id)
        if focus_target:
            self.query_one(focus_target).focus()

    def selected_target(self, *, required: bool = True) -> Target | None:
        table = self.query_one("#target-table", DataTable)
        if table.row_count == 0:
            if required:
                raise ValidationError("no target is selected")
            return None
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        return self.engagement.target_by_id(str(row_key.value))

    def refresh_all(self) -> bool:
        try:
            self.record = EngagementRecord(
                self.record.root, self.app.workspace.load(self.record.root)
            )
            live = self.app.tmux.live_target_ids(self.engagement)
            jobs = self.app.jobs.list(self.record.root)
            self.app.workspace.refresh_sitrep(
                self.record.root, self.engagement, live_target_ids=live, jobs=jobs
            )
            self.refresh_targets(self.query_one("#target-filter", Input).value)
            self.refresh_scope()
            self.refresh_situation()
            self.refresh_documents()
            return True
        except (TacmuxError, OSError, ValueError) as exc:
            self.app.show_error(str(exc))
            return False

    def refresh_targets(self, query: str = "") -> None:
        table = self.query_one("#target-table", DataTable)
        if not table.columns:
            table.add_columns("State", "Group", "Target", "Addresses", "Access")
        table.clear()
        live = self.app.tmux.live_target_ids(self.engagement)
        query = query.casefold().strip()
        for target in self.engagement.targets:
            addresses = ", ".join(item.value for item in target.addresses)
            haystack = f"{target.display_name} {addresses} {' '.join(target.hostnames)}".casefold()
            if query and query not in haystack:
                continue
            groups = sorted(
                {
                    self.engagement.scope_by_id(item.scope_id).group.value
                    for item in target.addresses
                }
            )
            access = self.engagement.strongest_access(target.id)
            table.add_row(
                "RUN" if target.id in live else "—",
                "/".join(groups) or "—",
                target.display_name,
                addresses or "—",
                ACCESS_LABELS[access] if access else "—",
                key=target.id,
            )
        self.update_target_detail(self.selected_target(required=False))

    def update_target_detail(self, target: Target | None) -> None:
        detail = self.query_one("#target-detail", Static)
        if target is None:
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
            f"Directory: {target.directory}",
            f"Primary: {target.primary_endpoint or '—'}",
            f"Addresses: {', '.join(item.value for item in target.addresses) or '—'}",
            f"Hostnames: {', '.join(target.hostnames) or '—'}",
            "",
            "Confirmed access",
        ]
        if access:
            lines.extend(
                f"• {item.authority + chr(92) if item.authority else ''}{item.principal}: {ACCESS_LABELS[item.level]} via {item.method or 'unspecified'}"
                for item in access
            )
        else:
            lines.append("• None")
        lines.extend(["", "Recent curated activity"])
        lines.extend(
            (f"• {item.result.value}: {item.summary}" for item in recent),
        )
        if not recent:
            lines.append("• None")
        detail.update(Text("\n".join(lines)))

    def refresh_scope(self) -> None:
        table = self.query_one("#scope-table", DataTable)
        if not table.columns:
            table.add_columns("Group", "Label", "Network", "Availability", "Via")
        table.clear()
        for item in self.engagement.scope:
            via = (
                self.engagement.target_by_id(item.via_target_id).display_name
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
        for job in self.app.jobs.list(self.record.root):
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

    def refresh_situation(self) -> None:
        topology = topology_text(self.engagement).rstrip()
        paths = attack_paths_text(self.engagement).rstrip()
        self.query_one("#situation-view", Static).update(
            RichMarkdown(
                f"# Network Topology\n\n```text\n{topology}\n```\n\n"
                f"# Confirmed Attack Paths\n\n```text\n{paths}\n```\n"
            )
        )

    def _document_entries(self) -> list[tuple[str, Path, bool, str]]:
        entries = [
            (
                "Engagement narrative",
                self.record.root / "ENGAGEMENT.md",
                True,
                "markdown",
            ),
            ("Generated SITREP", self.record.root / "SITREP.md", False, "generated"),
            (
                "Generated activity",
                self.record.root / "notes/activity.md",
                False,
                "generated",
            ),
            (
                "Generated attack paths",
                self.record.root / "notes/attack-path.md",
                False,
                "generated",
            ),
            ("Payload log", self.record.root / "notes/payloads.md", True, "markdown"),
        ]
        entries.extend(
            (
                f"Finding {item.id}: {item.title}",
                self.record.root / item.document,
                True,
                "markdown",
            )
            for item in self.engagement.findings
        )
        entries.extend(
            (
                f"Target {item.id}: {item.display_name}",
                self.record.root / "targets" / item.directory / "NOTES.md",
                True,
                "markdown",
            )
            for item in self.engagement.targets
        )
        return entries

    def _evidence_entries(self) -> tuple[list[tuple[str, Path, bool, str]], bool]:
        entries: list[tuple[str, Path, bool, str]] = []
        evidence_count = 0
        limit_reached = False
        for target in self.engagement.targets:
            target_root = self.record.root / "targets" / target.directory
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

    def refresh_documents(self) -> None:
        entries = self._document_entries()
        evidence, limit_reached = self._evidence_entries()
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
        self.preview_selected_document()

    def selected_document(self) -> tuple[Path, bool, str] | None:
        table = self.query_one("#documents-table", DataTable)
        if table.row_count == 0:
            return None
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        return self.document_paths.get(str(row_key.value))

    def preview_selected_document(self) -> None:
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
                preview.update(
                    Text(
                        f"Binary evidence\n\nPath: {path.relative_to(self.record.root)}\n"
                        f"Size: {size:,} bytes\nSHA-256: {digest}"
                    )
                )
                return
            content = sample.decode("utf-8", errors="replace")
            if truncated:
                content += (
                    f"\n\n[preview truncated at 256 KiB; file size is {size:,} bytes]"
                )
            preview.update(
                RichMarkdown(content)
                if kind in {"markdown", "generated"}
                else Text.from_ansi(content)
            )
        except OSError as exc:
            self.query_one("#document-preview", Static).update(
                f"Unable to read `{path}`: {exc}"
            )

    @on(DataTable.RowHighlighted)
    def row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id == "target-table":
            with suppress(TacmuxError):
                self.update_target_detail(
                    self.engagement.target_by_id(str(event.row_key.value))
                )
        elif event.data_table.id == "documents-table":
            self.preview_selected_document()

    @on(DataTable.RowSelected)
    def row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "target-table":
            self.action_attach()
        elif event.data_table.id == "scope-table":
            self.edit_scope()
        elif event.data_table.id == "jobs-table":
            self.job_actions()
        elif event.data_table.id == "documents-table":
            self.edit_selected_document()

    def action_default_action(self) -> None:
        active = self.query_one("#workspace-tabs", TabbedContent).active
        if active == "targets":
            self.action_attach()
        elif active == "scope":
            focused = self.app.focused
            if isinstance(focused, DataTable) and focused.id == "jobs-table":
                self.job_actions()
            else:
                self.edit_scope()
        elif active == "documents":
            self.edit_selected_document()

    def action_filter(self) -> None:
        field = self.query_one("#target-filter", Input)
        self.action_tab("targets")
        field.display = True
        field.focus()

    @on(Input.Changed, "#target-filter")
    def filter_changed(self, event: Input.Changed) -> None:
        self.refresh_targets(event.value)

    @on(Input.Submitted, "#target-filter")
    def filter_submitted(self) -> None:
        self.query_one("#target-filter", Input).display = False
        self.query_one("#target-table", DataTable).focus()

    def action_refresh(self) -> None:
        if self.refresh_all():
            self.app.notify("Topology, jobs, live sessions, and SITREP refreshed")

    def action_switch_engagement(self) -> None:
        self.app.switch_screen(EngagementPickerScreen())

    def action_new_target(self) -> None:
        self.app.push_screen(TargetForm(self.engagement), self._create_target)

    def _create_target(self, value: dict | None) -> None:
        if value is None:
            return
        try:
            addresses = (
                [TargetAddress(value["address"], value["scope_id"])]
                if value["address"]
                else []
            )
            primary = value["hostnames"][0] if value["hostnames"] else value["address"]
            self.app.workspace.create_target(
                self.record.root,
                self.engagement,
                value["display_name"],
                addresses=addresses,
                hostnames=value["hostnames"],
                primary_endpoint=primary,
            )
            self.refresh_all()
        except (TacmuxError, OSError, ValueError) as exc:
            self.app.show_error(str(exc))

    def action_add_scope(self) -> None:
        self.app.push_screen(ScopeForm(self.engagement), self._add_scope)

    def _add_scope(self, value: dict | None) -> None:
        if value is None:
            return
        scope = None
        try:
            scope = self.engagement.add_scope(**value)
            self.app.save_engagement(self.record)
            self.refresh_all()
        except (TacmuxError, OSError, ValueError) as exc:
            if scope is not None:
                self.engagement.scope = [
                    item for item in self.engagement.scope if item.id != scope.id
                ]
            self.app.show_error(str(exc))

    def selected_scope_id(self) -> str:
        table = self.query_one("#scope-table", DataTable)
        if table.row_count == 0:
            raise ValidationError("no scope entry is selected")
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        return str(row_key.value)

    def scope_actions(self) -> None:
        actions = [
            ("edit_scope", "Edit selected scope entry"),
            ("delete_scope", "Delete selected unused scope entry"),
            ("add_scope", "Add external or internal scope"),
            ("discovery", "Host discovery actions"),
            ("records", "Manage engagement records"),
        ]
        self.app.push_screen(
            ActionMenu("Scope & Discovery", actions), self._scope_action
        )

    def _scope_action(self, action: str | None) -> None:
        if not action:
            return
        if action == "edit_scope":
            self.edit_scope()
        elif action == "delete_scope":
            self.delete_scope()
        else:
            getattr(self, f"action_{action}")()

    def edit_scope(self) -> None:
        try:
            scope = self.engagement.scope_by_id(self.selected_scope_id())
        except TacmuxError as exc:
            self.app.show_error(str(exc))
            return
        self.app.push_screen(
            ScopeForm(self.engagement, scope),
            lambda value: self._edit_scope(scope.id, value),
        )

    def _edit_scope(self, scope_id: str, value: dict | None) -> None:
        if value is None:
            return
        scope = self.engagement.scope_by_id(scope_id)
        previous = deepcopy(scope)
        try:
            scope.label = value["label"]
            scope.group = value["group"]
            scope.network = str(ipaddress.ip_network(value["network"], strict=False))
            scope.availability = value["availability"]
            scope.via_target_id = value["via_target_id"]
            if any(
                item.id != scope.id
                and item.group == scope.group
                and item.network == scope.network
                for item in self.engagement.scope
            ):
                raise ValidationError(
                    f"scope already exists in {scope.group.value}: {scope.network}"
                )
            self.app.save_engagement(self.record)
            self.refresh_all()
        except (TacmuxError, OSError, ValueError) as exc:
            for item in fields(scope):
                setattr(scope, item.name, getattr(previous, item.name))
            self.app.show_error(str(exc))

    def delete_scope(self) -> None:
        try:
            scope = self.engagement.scope_by_id(self.selected_scope_id())
        except TacmuxError as exc:
            self.app.show_error(str(exc))
            return
        self.app.push_screen(
            ConfirmModal(
                "Delete Scope Entry",
                f"Delete {scope.label} ({scope.network})? Referenced scope cannot be deleted.",
            ),
            lambda confirmed: self._delete_scope(scope.id) if confirmed else None,
        )

    def _delete_scope(self, scope_id: str) -> None:
        try:
            self.app.workspace.delete_scope(self.record.root, self.engagement, scope_id)
            self.refresh_all()
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))

    def action_attach(self) -> None:
        try:
            target = self.selected_target()
            intent = self.app.tmux.start_target(
                self.record.root, self.engagement, target
            )
            self.app.exit(intent)
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))

    def action_ops(self) -> None:
        try:
            self.app.exit(self.app.tmux.start_ops(self.record.root, self.engagement))
        except TacmuxError as exc:
            self.app.show_error(str(exc))

    def action_stop_ops(self) -> None:
        try:
            self.app.tmux.stop_ops(self.engagement)
            self.refresh_all()
            self.app.notify("Engagement operations session stopped")
        except TacmuxError as exc:
            self.app.show_error(str(exc))

    def action_stop_all(self) -> None:
        try:
            jobs = self.app.jobs.cancel_all(self.record.root, self.engagement)
            sessions = self.app.tmux.stop_engagement_sessions(self.engagement)
            self.refresh_all()
            self.app.notify(
                f"Stopped {sessions} target/operations session(s) and "
                f"cancelled {jobs} discovery job(s)"
            )
        except TacmuxError as exc:
            self.app.show_error(str(exc))

    def action_actions(self) -> None:
        active = self.query_one("#workspace-tabs", TabbedContent).active
        if active == "scope":
            self.scope_actions()
        elif active == "documents":
            self.edit_selected_document()
        elif active == "situation":
            self.app.push_screen(
                ActionMenu(
                    "Situation",
                    [
                        ("attack_path", "Build confirmed attack path"),
                        ("records", "Manage engagement records"),
                        ("refresh", "Refresh topology and SITREP"),
                    ],
                ),
                lambda action: self.run_operator_command(action) if action else None,
            )
        else:
            self.target_actions()

    def target_actions(self) -> None:
        try:
            target = self.selected_target()
        except TacmuxError as exc:
            self.app.show_error(str(exc))
            return
        running = self.app.tmux.target_session_running(self.engagement, target)
        actions = [("attach", "Attach" if running else "Start and attach")]
        if running:
            actions.append(("stop", "Stop session"))
        actions.extend(
            [
                ("identity", "Edit target identity and addresses"),
                ("notes", "Edit target notes"),
                ("access", "Record confirmed access"),
                ("activity", "Record activity"),
                ("finding", "Create finding"),
                ("records", "Manage engagement records"),
                ("archive", "Archive target"),
                ("delete", "Permanently delete mistaken target"),
            ]
        )
        if self.app.settings.nocap_enabled:
            actions.insert(-2, ("nocap", "View NOCAP timeline"))
        self.app.push_screen(
            ActionMenu(target.display_name, actions), self._target_action
        )

    def _target_action(self, action: str | None) -> None:
        if action is None:
            return
        dispatch = {
            "attach": self.action_attach,
            "stop": self.stop_target,
            "identity": self.edit_target_identity,
            "notes": self.edit_target_notes,
            "access": self.record_access,
            "activity": self.action_activity,
            "finding": self.create_finding,
            "records": self.action_records,
            "nocap": self.view_nocap,
            "archive": self.archive_target,
            "delete": self.delete_target,
        }
        dispatch[action]()

    def edit_target_identity(self) -> None:
        target = self.selected_target()
        actions = [
            ("rename", "Rename display name"),
            ("add_address", "Add scope-qualified address"),
            ("remove_address", "Remove an address"),
            ("hostnames", "Edit hostnames"),
            ("primary", "Choose primary endpoint"),
        ]
        self.app.push_screen(
            ActionMenu(f"Edit {target.display_name}", actions), self._identity_action
        )

    def _identity_action(self, action: str | None) -> None:
        if not action:
            return
        dispatch = {
            "rename": self.rename_target,
            "add_address": self.add_target_address,
            "remove_address": self.remove_target_address,
            "hostnames": self.edit_target_hostnames,
            "primary": self.choose_primary_endpoint,
        }
        dispatch[action]()

    def add_target_address(self) -> None:
        target = self.selected_target()
        self.app.push_screen(
            TargetAddressForm(self.engagement, target.display_name),
            lambda value: self._add_target_address(target.id, value),
        )

    def _add_target_address(self, target_id: str, value: dict | None) -> None:
        if value is None:
            return
        target = self.engagement.target_by_id(target_id)
        previous_primary = target.primary_endpoint
        target.addresses.append(TargetAddress(value["address"], value["scope_id"]))
        if value["primary"] or not target.primary_endpoint:
            target.primary_endpoint = value["address"]
        try:
            self.app.save_engagement(self.record)
            self.refresh_all()
        except (TacmuxError, OSError, ValueError) as exc:
            target.addresses.pop()
            target.primary_endpoint = previous_primary
            self.app.show_error(str(exc))

    def remove_target_address(self) -> None:
        target = self.selected_target()
        if not target.addresses:
            self.app.show_error("This target has no addresses")
            return
        actions = []
        for index, address in enumerate(target.addresses):
            scope = self.engagement.scope_by_id(address.scope_id)
            actions.append(
                (str(index), f"{address.value} — {scope.group.value}: {scope.label}")
            )
        self.app.push_screen(
            ActionMenu("Remove Address", actions),
            lambda index: self._remove_target_address(target.id, index),
        )

    def _remove_target_address(self, target_id: str, index: str | None) -> None:
        if index is None:
            return
        target = self.engagement.target_by_id(target_id)
        removed = target.addresses.pop(int(index))
        previous_primary = target.primary_endpoint
        if target.primary_endpoint == removed.value:
            target.primary_endpoint = (
                target.hostnames[0]
                if target.hostnames
                else (target.addresses[0].value if target.addresses else "")
            )
        try:
            self.app.save_engagement(self.record)
            self.refresh_all()
        except (TacmuxError, OSError, ValueError) as exc:
            target.addresses.insert(int(index), removed)
            target.primary_endpoint = previous_primary
            self.app.show_error(str(exc))

    def edit_target_hostnames(self) -> None:
        target = self.selected_target()
        self.app.push_screen(
            PromptModal(
                "Edit Hostnames",
                "Comma-separated hostnames",
                ", ".join(target.hostnames),
            ),
            lambda value: self._edit_target_hostnames(target.id, value),
        )

    def _edit_target_hostnames(self, target_id: str, value: str | None) -> None:
        if value is None:
            return
        target = self.engagement.target_by_id(target_id)
        previous = target.hostnames
        previous_primary = target.primary_endpoint
        target.hostnames = sorted(
            {item.strip() for item in value.split(",") if item.strip()}
        )
        if (
            target.primary_endpoint in previous
            and target.primary_endpoint not in target.hostnames
        ):
            target.primary_endpoint = (
                target.hostnames[0]
                if target.hostnames
                else (target.addresses[0].value if target.addresses else "")
            )
        try:
            self.app.save_engagement(self.record)
            self.refresh_all()
        except (TacmuxError, OSError, ValueError) as exc:
            target.hostnames = previous
            target.primary_endpoint = previous_primary
            self.app.show_error(str(exc))

    def choose_primary_endpoint(self) -> None:
        target = self.selected_target()
        endpoints = list(
            dict.fromkeys(
                [*target.hostnames, *(item.value for item in target.addresses)]
            )
        )
        if not endpoints:
            self.app.show_error(
                "Add an address or hostname before choosing a primary endpoint"
            )
            return
        self.app.push_screen(
            ActionMenu("Choose Primary Endpoint", [(item, item) for item in endpoints]),
            lambda endpoint: self._set_primary_endpoint(target.id, endpoint),
        )

    def _set_primary_endpoint(self, target_id: str, endpoint: str | None) -> None:
        if not endpoint:
            return
        target = self.engagement.target_by_id(target_id)
        previous = target.primary_endpoint
        target.primary_endpoint = endpoint
        try:
            self.app.save_engagement(self.record)
            self.refresh_all()
        except (TacmuxError, OSError, ValueError) as exc:
            target.primary_endpoint = previous
            self.app.show_error(str(exc))

    def stop_target(self) -> None:
        try:
            target = self.selected_target()
            self.app.tmux.stop_target(self.engagement, target)
            self.refresh_all()
        except TacmuxError as exc:
            self.app.show_error(str(exc))

    def rename_target(self) -> None:
        target = self.selected_target()
        self.app.push_screen(
            PromptModal("Rename Target", "Display Name", target.display_name),
            lambda value: self._rename_target(target.id, value),
        )

    def _rename_target(self, target_id: str, value: str | None) -> None:
        if value is None:
            return
        try:
            self.app.workspace.rename_target(
                self.record.root, self.engagement, target_id, value
            )
            self.refresh_all()
        except TacmuxError as exc:
            self.app.show_error(str(exc))

    def edit_target_notes(self) -> None:
        target = self.selected_target()
        self.app.edit_file(self.record.root / "targets" / target.directory / "NOTES.md")
        self.refresh_documents()

    def record_access(self) -> None:
        target = self.selected_target()
        self.app.push_screen(
            AccessForm(target.display_name),
            lambda value: self._record_access(target.id, value),
        )

    def _record_access(self, target_id: str, value: dict | None) -> None:
        if value is None:
            return
        record = AccessRecord(
            id=self.engagement.next_id("access", "AR"),
            target_id=target_id,
            **value,
        )
        self.engagement.access.append(record)
        try:
            self.app.save_engagement(self.record)
            self.refresh_all()
        except (TacmuxError, OSError, ValueError) as exc:
            self.engagement.access = [
                item for item in self.engagement.access if item.id != record.id
            ]
            self.app.show_error(str(exc))

    def action_activity(self) -> None:
        target = self.selected_target(required=False)
        self.app.push_screen(
            ActivityForm(self.engagement, target.id if target else ""),
            self._record_activity,
        )

    def _record_activity(self, value: dict | None) -> None:
        if value is None:
            return
        activity = Activity(id=self.engagement.next_id("activity", "A"), **value)
        self.engagement.activities.append(activity)
        try:
            self.app.save_engagement(self.record)
            self.refresh_all()
        except (TacmuxError, OSError, ValueError) as exc:
            self.engagement.activities = [
                item for item in self.engagement.activities if item.id != activity.id
            ]
            self.app.show_error(str(exc))

    def create_finding(self) -> None:
        target = self.selected_target(required=False)
        self.app.push_screen(
            FindingForm(self.engagement, target.id if target else ""),
            self._create_finding,
        )

    def _create_finding(self, value: dict | None) -> None:
        if value is None:
            return
        try:
            finding = self.app.workspace.create_finding(
                self.record.root, self.engagement, **value
            )
            self.app.edit_file(self.record.root / finding.document)
            self.refresh_all()
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))

    def action_attack_path(self) -> None:
        self.app.push_screen(AttackPathForm(self.engagement), self._create_attack_path)

    def _create_attack_path(self, value: dict | None) -> None:
        if value is None:
            return
        path = AttackPath(
            id=self.engagement.next_id("attack_path", "P"),
            name=value["name"],
            steps=[
                AttackPathStep(ref_type=item[0], ref_id=item[1], narrative=item[2])
                for item in value["steps"]
            ],
        )
        self.engagement.attack_paths.append(path)
        try:
            self.app.save_engagement(self.record)
            self.refresh_all()
            self.action_tab("situation")
        except (TacmuxError, OSError, ValueError) as exc:
            self.engagement.attack_paths = [
                item for item in self.engagement.attack_paths if item.id != path.id
            ]
            self.app.show_error(str(exc))

    def action_records(self) -> None:
        actions: list[tuple[str, str]] = []
        actions.extend(
            (
                f"access:{item.id}",
                f"Access {item.id} — {item.authority + chr(92) if item.authority else ''}{item.principal}",
            )
            for item in self.engagement.access
        )
        actions.extend(
            (f"activity:{item.id}", f"Activity {item.id} — {item.summary}")
            for item in self.engagement.activities
        )
        actions.extend(
            (f"finding:{item.id}", f"Finding {item.id} — {item.title}")
            for item in self.engagement.findings
        )
        actions.extend(
            (f"attack_path:{item.id}", f"Attack Path {item.id} — {item.name}")
            for item in self.engagement.attack_paths
        )
        if not actions:
            self.app.show_error("No engagement records have been created")
            return
        self.app.push_screen(
            ActionMenu("Manage Engagement Records", actions), self._record_actions
        )

    def _record_actions(self, key: str | None) -> None:
        if not key:
            return
        kind, record_id = key.split(":", 1)
        self.app.push_screen(
            ActionMenu(
                f"{kind.replace('_', ' ').title()} {record_id}",
                [("edit", "Edit record"), ("delete", "Delete record")],
            ),
            lambda action: self._record_action(kind, record_id, action),
        )

    def _record_action(self, kind: str, record_id: str, action: str | None) -> None:
        if action == "edit":
            self._edit_record(kind, record_id)
        elif action == "delete":
            self.app.push_screen(
                ConfirmModal(
                    "Delete Engagement Record",
                    f"Delete {kind.replace('_', ' ')} {record_id}? "
                    "Records used by an attack path cannot be deleted.",
                ),
                lambda confirmed: self._delete_record(kind, record_id)
                if confirmed
                else None,
            )

    def _record(
        self, kind: str, record_id: str
    ) -> AccessRecord | Activity | Finding | AttackPath:
        collections = {
            "access": self.engagement.access,
            "activity": self.engagement.activities,
            "finding": self.engagement.findings,
            "attack_path": self.engagement.attack_paths,
        }
        record = next(
            (item for item in collections.get(kind, []) if item.id == record_id), None
        )
        if record is None:
            raise ValidationError(f"unknown {kind} record: {record_id}")
        return record

    @staticmethod
    def _apply_record_update(
        record: AccessRecord | Activity | Finding | AttackPath,
        kind: str,
        value: dict,
    ) -> None:
        names = {
            "access": ("principal", "authority", "method", "level", "evidence"),
            "activity": ("summary", "result", "target_id", "evidence"),
            "finding": ("title", "severity", "state", "target_ids", "evidence"),
        }
        if kind == "attack_path":
            record.name = value["name"]
            record.steps = [
                AttackPathStep(item[0], item[1], item[2]) for item in value["steps"]
            ]
            return
        for name in names[kind]:
            setattr(record, name, value[name])

    def _edit_record(self, kind: str, record_id: str) -> None:
        try:
            record = self._record(kind, record_id)
            if kind == "access":
                target = self.engagement.target_by_id(record.target_id)
                form = AccessForm(target.display_name, record)
            elif kind == "activity":
                form = ActivityForm(self.engagement, activity=record)
            elif kind == "finding":
                form = FindingForm(self.engagement, finding=record)
            else:
                form = AttackPathForm(self.engagement, path=record)
            self.app.push_screen(
                form, lambda value: self._save_record(kind, record_id, value)
            )
        except TacmuxError as exc:
            self.app.show_error(str(exc))

    def _save_record(self, kind: str, record_id: str, value: dict | None) -> None:
        if value is None:
            return
        record = self._record(kind, record_id)
        previous = deepcopy(record)
        try:
            self._apply_record_update(record, kind, value)
            self.app.save_engagement(self.record)
        except (TacmuxError, OSError, ValueError) as exc:
            for item in fields(record):
                setattr(record, item.name, deepcopy(getattr(previous, item.name)))
            self.app.show_error(str(exc))
            return
        if kind == "finding":
            try:
                self.app.workspace.sync_finding_document(self.record.root, record)
            except (TacmuxError, OSError) as exc:
                self.app.notify(
                    f"Finding metadata saved, but its Markdown header was not updated: {exc}",
                    severity="warning",
                )
        self.refresh_all()

    def _delete_record(self, kind: str, record_id: str) -> None:
        try:
            self.app.workspace.delete_record(
                self.record.root, self.engagement, kind, record_id
            )
            self.refresh_all()
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))

    def view_nocap(self) -> None:
        target = self.selected_target()
        route = str(
            (self.record.root / "targets" / target.directory).relative_to(
                self.app.settings.workspace
            )
        )
        try:
            captures = self.app.nocap.timeline(route)
            lines = [f"NOCAP timeline for {target.display_name}", ""]
            lines.extend(
                f"{str(item.get('started_at', ''))[:19]}  {item.get('status', ''):10}  "
                f"{item.get('effective_tool', ''):16}  {item.get('path', '')}"
                for item in captures[-30:]
            )
            self.app.push_screen(MessageModal("NOCAP Timeline", "\n".join(lines)))
        except TacmuxError as exc:
            self.app.show_error(str(exc))

    def archive_target(self) -> None:
        target = self.selected_target()
        if self.app.tmux.target_session_running(self.engagement, target):
            self.app.show_error(
                "Stop the target session before creating a consistent archive"
            )
            return
        try:
            archive, _ = create_archive(
                self.record.root / "targets" / target.directory,
                self.app.settings.archive_dir,
                kind="targets",
                engagement_id=self.engagement.id,
                object_id=target.id,
                object_metadata=asdict(target),
            )
            self.app.push_screen(MessageModal("Archive Verified", str(archive)))
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))

    def delete_target(self) -> None:
        target = self.selected_target()
        if self.app.tmux.target_session_running(self.engagement, target):
            self.app.show_error("Stop the target session before deleting its directory")
            return
        required = f"DELETE {target.display_name}"
        message = (
            f"This permanently deletes {target.display_name}'s complete target directory. "
            "It is only allowed when no scope, access, activity, or finding references remain."
        )
        self.app.push_screen(
            ConfirmModal("Permanently Delete Mistaken Target", message, required),
            lambda confirmed: self._delete_target(target.id) if confirmed else None,
        )

    def _delete_target(self, target_id: str) -> None:
        try:
            self.app.workspace.delete_target(
                self.record.root, self.engagement, target_id
            )
            self.refresh_all()
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))

    def action_scan(self) -> None:
        self.app.push_screen(ScanForm(self.engagement), self._start_scan)

    def action_discovery(self) -> None:
        self.app.push_screen(
            ActionMenu(
                "Host Discovery",
                [
                    ("scan", "Run detached Nmap host identification"),
                    ("import_discovery", "Import XML or pasted hosts"),
                    ("import_completed", "Review a completed detached scan"),
                ],
            ),
            lambda action: self.run_operator_command(action) if action else None,
        )

    def _start_scan(self, scope_ids: list[str] | None) -> None:
        if not scope_ids:
            return
        try:
            job = self.app.jobs.create(self.record.root, self.engagement, scope_ids)
            self.app.notify(f"Discovery {job['id']} started in detached mode")
            self.action_tab("scope")
            self.refresh_scope()
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))

    def action_import_discovery(self) -> None:
        self.pending_job_id = ""
        self.app.push_screen(ImportDiscoveryForm(self.engagement), self._prepare_import)

    def action_import_completed(self) -> None:
        jobs = [
            item
            for item in self.app.jobs.list(self.record.root)
            if item.get("state") == "succeeded" and not item.get("imported_at")
        ]
        if not jobs:
            self.app.show_error("No completed discovery jobs are available")
            return
        actions = [
            (str(item["id"]), f"{item['id']} — {', '.join(item.get('scope_ids', []))}")
            for item in jobs
        ]
        self.app.push_screen(
            ActionMenu("Import Completed Job", actions),
            lambda job_id: self._open_job_import(jobs, job_id),
        )

    def import_selected_job(self) -> None:
        table = self.query_one("#jobs-table", DataTable)
        if table.row_count == 0:
            self.app.show_error("No discovery job is selected")
            return
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        job_id = str(row_key.value)
        jobs = self.app.jobs.list(self.record.root)
        job = next((item for item in jobs if str(item.get("id")) == job_id), None)
        if job is None or job.get("state") != "succeeded":
            self.app.show_error("Only a successful discovery job can be imported")
            return
        self._open_job_import([job], job_id)

    def job_actions(self) -> None:
        table = self.query_one("#jobs-table", DataTable)
        if table.row_count == 0:
            self.app.show_error("No discovery job is selected")
            return
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        job_id = str(row_key.value)
        job = next(
            (
                item
                for item in self.app.jobs.list(self.record.root)
                if str(item.get("id")) == job_id
            ),
            None,
        )
        if job is None:
            self.app.show_error("The selected discovery job no longer exists")
            return
        actions = []
        if job.get("state") == "succeeded":
            actions.append(("import", "Review and import results"))
        if job.get("state") in {"queued", "running"}:
            actions.append(("cancel", "Cancel detached scan"))
        if not actions:
            self.app.show_error(f"Discovery {job_id} has no available actions")
            return
        self.app.push_screen(
            ActionMenu(f"Discovery {job_id}", actions),
            lambda action: self._job_action(job_id, action),
        )

    def _job_action(self, job_id: str, action: str | None) -> None:
        if action == "import":
            jobs = self.app.jobs.list(self.record.root)
            self._open_job_import(jobs, job_id)
        elif action == "cancel":
            try:
                self.app.jobs.cancel(self.record.root, self.engagement, job_id)
                self.refresh_all()
                self.app.notify(f"Discovery {job_id} cancelled")
            except (TacmuxError, OSError) as exc:
                self.app.show_error(str(exc))

    def _open_job_import(self, jobs: list[dict], job_id: str | None) -> None:
        if not job_id:
            return
        job = next(item for item in jobs if item["id"] == job_id)
        self.pending_job_id = job_id
        self.app.push_screen(
            ImportDiscoveryForm(
                self.engagement,
                xml_path=str(job["xml_path"]),
                selected_scope_ids=list(job.get("scope_ids", [])),
            ),
            self._prepare_import,
        )

    def _prepare_import(self, value: dict | None) -> None:
        if value is None:
            return
        try:
            candidates = (
                parse_nmap_xml(Path(value["xml_path"]).expanduser())
                if value["xml_path"]
                else parse_host_lines(value["pasted"])
            )
            decisions = reconcile_candidates(
                self.engagement, candidates, allowed_scope_ids=set(value["scope_ids"])
            )
            merge_targets = [
                (
                    target.id,
                    f"{target.display_name} — {', '.join(item.value for item in target.addresses) or 'no address'}",
                )
                for target in self.engagement.targets
            ]
            self.app.push_screen(
                DiscoveryReview(decisions, merge_targets), self._commit_import
            )
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))

    def _commit_import(self, value: tuple[list, bool] | None) -> None:
        if value is None:
            return
        decisions, create_sessions = value
        try:
            targets = apply_reconciliation(
                self.app.workspace, self.record.root, self.engagement, decisions
            )
            if self.pending_job_id:
                self.app.jobs.mark_imported(self.record.root, self.pending_job_id)
                self.pending_job_id = ""
            if create_sessions:
                self.app.tmux.start_targets_detached(
                    self.record.root, self.engagement, targets
                )
            self.app.notify(f"Accepted {len(targets)} discovery result(s)")
            self.refresh_all()
            self.action_tab("targets")
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))

    def edit_selected_document(self) -> None:
        selected = self.selected_document()
        if selected is None:
            return
        path, editable, _ = selected
        if not editable:
            self.app.show_error(
                "Generated documents are read-only; update their records through TACMUX"
            )
            return
        self.app.edit_file(path)
        self.preview_selected_document()

    def action_archive_engagement(self) -> None:
        live = self.app.tmux.live_target_ids(self.engagement)
        active_jobs = self.app.jobs.active(self.record.root)
        if (
            live
            or active_jobs
            or self.app.tmux.has_session(self.app.tmux.session_name(self.engagement))
        ):
            self.app.show_error(
                "Stop all target, operations, and discovery sessions before archiving the engagement"
            )
            return
        try:
            archive, _ = create_archive(
                self.record.root,
                self.app.settings.archive_dir,
                kind="engagements",
                engagement_id=self.engagement.id,
                object_id=self.engagement.id,
            )
            self.app.push_screen(
                MessageModal("Engagement Archive Verified", str(archive))
            )
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))

    def action_restore(self) -> None:
        self.app.push_screen(
            PromptModal("Restore Verified Archive", "Path to .tar.gz archive"),
            self._restore,
        )

    def _restore(self, value: str | None) -> None:
        if value is None:
            return
        try:
            archive = Path(value).expanduser()
            document = verify_archive(archive)
            context = document["context"]
            if context["kind"] == "engagements":
                self._restore_engagement(archive, context)
            elif context["kind"] == "targets":
                self._restore_target(archive, context)
            else:
                raise ValidationError(f"unsupported archive kind: {context['kind']}")
        except (TacmuxError, OSError, KeyError) as exc:
            self.app.show_error(str(exc))

    def _restore_engagement(self, archive: Path, context: dict) -> None:
        restored = restore_archive(archive, self.app.settings.workspace)
        try:
            engagement = self.app.workspace.load(restored)
            if (
                engagement.id != context["engagement_id"]
                or engagement.id != context["object_id"]
                or not restored.name.startswith(f"{engagement.id}-")
            ):
                raise ValidationError(
                    "restored engagement manifest does not match archive context"
                )
        except BaseException:
            shutil.rmtree(restored, ignore_errors=True)
            raise
        self.app.push_screen(MessageModal("Engagement Restored", str(restored)))

    def _restore_target(self, archive: Path, context: dict) -> None:
        if context["engagement_id"] != self.engagement.id:
            raise ValidationError("target archive belongs to a different engagement")
        metadata = context.get("object_metadata")
        if not isinstance(metadata, dict):
            raise ValidationError(
                "target archive does not contain restorable target metadata"
            )
        archived_target = Target.from_dict(metadata)
        if (
            archived_target.id != context["object_id"]
            or archived_target.directory != context["source_name"]
        ):
            raise ValidationError(
                "target archive metadata does not match archive context"
            )
        existing_target = next(
            (item for item in self.engagement.targets if item.id == archived_target.id),
            None,
        )
        restored_target = None
        if existing_target is not None:
            if asdict(existing_target) != asdict(archived_target):
                raise ValidationError(
                    "target archive metadata does not match the existing target"
                )
        else:
            restored_target = archived_target
            self.engagement.targets.append(restored_target)
            try:
                self.engagement.validate()
            finally:
                self.engagement.targets.pop()
        restored = restore_archive(archive, self.record.root / "targets")
        if restored_target is not None:
            self.engagement.targets.append(restored_target)
            try:
                self.app.save_engagement(self.record)
            except BaseException:
                self.engagement.targets = [
                    item
                    for item in self.engagement.targets
                    if item.id != restored_target.id
                ]
                shutil.rmtree(restored, ignore_errors=True)
                raise
        self.app.push_screen(MessageModal("Target Files Restored", str(restored)))
        self.refresh_all()

    def run_operator_command(self, action: str) -> None:
        getattr(self, f"action_{action}")()


class TacmuxApp(App[LaunchIntent | None]):
    CSS = """
    Screen { background: $background; }
    #picker-body { padding: 1 2; }
    #picker-title, #engagement-banner { height: 3; padding: 1 2; text-style: bold; color: $accent; }
    #picker-hint { height: 2; color: $text-muted; }
    #engagement-filter, #target-filter { margin: 0 2; }
    #target-layout, #documents-layout { height: 1fr; }
    #target-table { width: 62%; }
    #target-detail { width: 38%; padding: 1 2; border-left: solid $panel; overflow-y: auto; }
    #scope-table { height: 44%; }
    #jobs-table { height: 36%; }
    .section-title { height: 2; padding-left: 1; text-style: bold; }
    #situation-view { padding: 1 2; }
    #documents-table { width: 38%; }
    #document-preview { width: 62%; padding: 1 2; border-left: solid $panel; }
    MainScreen.narrow #target-layout, MainScreen.narrow #documents-layout { layout: vertical; }
    MainScreen.narrow #target-table, MainScreen.narrow #documents-table {
        width: 1fr; height: 55%;
    }
    MainScreen.narrow #target-detail, MainScreen.narrow #document-preview {
        width: 1fr; height: 45%; border-left: none; border-top: solid $panel;
    }
    """
    COMMANDS: ClassVar[set] = {get_system_commands_provider, OperatorCommands}

    def __init__(self, settings: Settings):
        super().__init__()
        self.settings = settings
        self.workspace = Workspace(settings)
        self.tmux = TmuxService(settings)
        self.jobs = DiscoveryJobs(settings, self.tmux)
        self.nocap = NocapReader(settings)

    def on_mount(self) -> None:
        self.workspace.initialize()
        self.call_after_refresh(self.bootstrap)

    def bootstrap(self) -> None:
        records = self.workspace.list_engagements()
        engagement_id, _ = self.tmux.current_context()
        if not engagement_id and self.settings.startup == "resume_last":
            engagement_id = self.workspace.get_last_engagement()
        record = next(
            (item for item in records if item.engagement.id == engagement_id), None
        )
        if record is not None:
            self.workspace.set_last_engagement(record.engagement.id)
            self.push_screen(MainScreen(record))
        else:
            self.push_screen(EngagementPickerScreen())

    def open_engagement(self, record: EngagementRecord) -> None:
        self.workspace.set_last_engagement(record.engagement.id)
        self.switch_screen(MainScreen(record))

    def save_engagement(self, record: EngagementRecord) -> None:
        self.workspace.save(record.root, record.engagement)
        try:
            self.workspace.refresh_sitrep(
                record.root,
                record.engagement,
                live_target_ids=self.tmux.live_target_ids(record.engagement),
                jobs=self.jobs.list(record.root),
            )
        except (TacmuxError, OSError) as exc:
            self.notify(
                f"Saved engagement, but live SITREP refresh failed: {exc}",
                severity="warning",
            )

    def show_error(self, message: str) -> None:
        self.notify(message, title="TACMUX", severity="error", timeout=8)

    def edit_file(self, path: Path) -> None:
        try:
            path = path.resolve(strict=True)
            path.relative_to(self.settings.workspace.resolve(strict=True))
            with self.suspend():
                result = subprocess.run(
                    [*self.settings.editor_argv, str(path)], check=False
                )
            if result.returncode:
                self.show_error(f"editor exited with status {result.returncode}")
        except (OSError, ValueError, TacmuxError) as exc:
            self.show_error(str(exc))
