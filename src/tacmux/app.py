"""Transient Textual operator cockpit for TACMUX v2."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import shutil
import subprocess
from typing import ClassVar

from textual import events, on
from textual.app import (
    App,
    ComposeResult,
    SuspendNotSupported,
    get_system_commands_provider,
)
from textual.binding import Binding
from textual.command import DiscoveryHit, Hit, Hits, Provider
from textual.containers import Vertical
from textual.screen import Screen
from textual.theme import Theme
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

from .archive import (
    create_archive,
    restore_engagement_archive,
    restore_target_archive,
    verify_archive,
)
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
    Engagement,
    Finding,
    ScopeAvailability,
    ScopeGroup,
    Target,
    TargetAddress,
)
from .nocap import NocapReader
from .panes import DocumentsPane, ScopeDiscoveryPane, SituationPane, TargetsPane
from .store import EngagementRecord, Workspace
from .themes import BLTSEC_THEME, CURATED_THEME_NAMES, DEFAULT_THEME
from .terminal_output import iter_rendered
from .tmux import LaunchIntent, TmuxService


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
        self.pending_job_id = ""
        self.live_target_ids: set[str] = set()

    @property
    def engagement(self) -> Engagement:
        return self.record.engagement

    @property
    def document_paths(self) -> dict[str, tuple[Path, bool, str]]:
        return self.query_one(DocumentsPane).document_paths

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Label(
            f"{self.engagement.client}  /  {self.engagement.name}",
            id="engagement-banner",
        )
        yield Input(placeholder="Filter targets", id="target-filter")
        with TabbedContent(initial="targets", id="workspace-tabs"):
            with TabPane("Targets", id="targets"):
                yield TargetsPane(id="target-layout")
            with TabPane("Scope & Discovery", id="scope"):
                yield ScopeDiscoveryPane()
            with TabPane("Situation", id="situation"):
                yield SituationPane(id="situation-view")
            with TabPane("Documents", id="documents"):
                yield DocumentsPane(id="documents-layout")
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
        target_id = self.query_one(TargetsPane).selected_target_id(required=required)
        return self.engagement.target_by_id(target_id) if target_id else None

    def refresh_all(self) -> bool:
        try:
            self.record = EngagementRecord(
                self.record.root, self.app.workspace.load(self.record.root)
            )
            live = self.app.tmux.live_target_ids(self.engagement)
            self.live_target_ids = live
            jobs = self.app.jobs.list(self.record.root)
            self.app.workspace.refresh_sitrep(
                self.record.root, self.engagement, live_target_ids=live, jobs=jobs
            )
            self.query_one(TargetsPane).populate(
                self.engagement,
                live,
                self.query_one("#target-filter", Input).value,
            )
            self.query_one(ScopeDiscoveryPane).populate(self.engagement, jobs)
            self.query_one(SituationPane).populate(self.engagement)
            self.query_one(DocumentsPane).populate(self.record)
            return True
        except (TacmuxError, OSError, ValueError) as exc:
            self.app.show_error(str(exc))
            return False

    @on(DataTable.RowSelected)
    def row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "target-table":
            self.action_attach()
        elif event.data_table.id == "scope-table":
            self.edit_scope()
        elif event.data_table.id == "jobs-table":
            self.job_actions()
        elif event.data_table.id == "documents-table":
            self.open_selected_document()

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
            self.open_selected_document()

    def action_filter(self) -> None:
        field = self.query_one("#target-filter", Input)
        self.action_tab("targets")
        field.display = True
        field.focus()

    @on(Input.Changed, "#target-filter")
    def filter_changed(self, event: Input.Changed) -> None:
        self.query_one(TargetsPane).populate(
            self.engagement,
            self.live_target_ids,
            event.value,
        )

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
        try:
            self.app.workspace.add_scope(
                self.record.root, self.engagement, **value
            )
            self.refresh_all()
        except (TacmuxError, OSError, ValueError) as exc:
            self.app.show_error(str(exc))

    def selected_scope_id(self) -> str:
        return self.query_one(ScopeDiscoveryPane).selected_scope_id()

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
        try:
            self.app.workspace.update_scope(
                self.record.root, self.engagement, scope_id, **value
            )
            self.refresh_all()
        except (TacmuxError, OSError, ValueError) as exc:
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
            self.document_actions()
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
        try:
            self.app.workspace.add_target_address(
                self.record.root,
                self.engagement,
                target_id,
                value["address"],
                value["scope_id"],
                primary=value["primary"],
            )
            self.refresh_all()
        except (TacmuxError, OSError, ValueError) as exc:
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
        try:
            self.app.workspace.remove_target_address(
                self.record.root, self.engagement, target_id, int(index)
            )
            self.refresh_all()
        except (TacmuxError, OSError, ValueError) as exc:
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
        try:
            self.app.workspace.replace_target_hostnames(
                self.record.root, self.engagement, target_id, value.split(",")
            )
            self.refresh_all()
        except (TacmuxError, OSError, ValueError) as exc:
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
        try:
            self.app.workspace.set_primary_endpoint(
                self.record.root, self.engagement, target_id, endpoint
            )
            self.refresh_all()
        except (TacmuxError, OSError, ValueError) as exc:
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
        self.query_one(DocumentsPane).populate(self.record)

    def record_access(self) -> None:
        target = self.selected_target()
        self.app.push_screen(
            AccessForm(target.display_name),
            lambda value: self._record_access(target.id, value),
        )

    def _record_access(self, target_id: str, value: dict | None) -> None:
        if value is None:
            return
        try:
            self.app.workspace.create_access(
                self.record.root, self.engagement, target_id, **value
            )
            self.refresh_all()
        except (TacmuxError, OSError, ValueError) as exc:
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
        try:
            self.app.workspace.create_activity(
                self.record.root, self.engagement, **value
            )
            self.refresh_all()
        except (TacmuxError, OSError, ValueError) as exc:
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
        try:
            self.app.workspace.create_attack_path(
                self.record.root,
                self.engagement,
                value["name"],
                value["steps"],
            )
            self.refresh_all()
            self.action_tab("situation")
        except (TacmuxError, OSError, ValueError) as exc:
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
        try:
            record = self.app.workspace.update_record(
                self.record.root, self.engagement, kind, record_id, value
            )
        except (TacmuxError, OSError, ValueError) as exc:
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
            self.query_one(ScopeDiscoveryPane).populate(
                self.engagement, self.app.jobs.list(self.record.root)
            )
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
        try:
            job_id = self.query_one(ScopeDiscoveryPane).selected_job_id()
        except ValidationError as exc:
            self.app.show_error(str(exc))
            return
        jobs = self.app.jobs.list(self.record.root)
        job = next((item for item in jobs if str(item.get("id")) == job_id), None)
        if job is None or job.get("state") != "succeeded":
            self.app.show_error("Only a successful discovery job can be imported")
            return
        self._open_job_import([job], job_id)

    def job_actions(self) -> None:
        try:
            job_id = self.query_one(ScopeDiscoveryPane).selected_job_id()
        except ValidationError as exc:
            self.app.show_error(str(exc))
            return
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
        self.pending_job_id = ""
        job = next((item for item in jobs if item.get("id") == job_id), None)
        if job is None:
            self.app.show_error("The selected discovery job no longer exists")
            return
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
                DiscoveryReview(
                    decisions,
                    merge_targets,
                    allowed_scope_ids=value["scope_ids"],
                ),
                self._commit_import,
            )
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))

    def _commit_import(self, value: tuple[list, bool, set[str]] | None) -> None:
        if value is None:
            return
        decisions, create_sessions, allowed_scope_ids = value
        try:
            targets = apply_reconciliation(
                self.app.workspace,
                self.record.root,
                self.engagement,
                decisions,
                allowed_scope_ids=allowed_scope_ids,
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
        documents = self.query_one(DocumentsPane)
        selected = documents.selected_document()
        if selected is None:
            return
        path, editable, _ = selected
        if not editable:
            self.app.show_error(
                "Generated documents are read-only; update their records through TACMUX"
            )
            return
        self.app.edit_file(path)
        documents.preview_selected()

    def open_selected_document(self) -> None:
        selected = self.query_one(DocumentsPane).selected_document()
        if selected is None:
            return
        path, editable, kind = selected
        if editable:
            self.edit_selected_document()
        else:
            self.app.page_file(path, terminal_output=kind == "evidence")

    def document_actions(self) -> None:
        selected = self.query_one(DocumentsPane).selected_document()
        if selected is None:
            self.app.show_error("No document or evidence file is selected")
            return
        path, editable, _ = selected
        actions = [("view", "View full file in pager")]
        if editable:
            actions.append(("edit", "Edit with $VISUAL or $EDITOR"))
        self.app.push_screen(
            ActionMenu(path.name, actions), self._document_action
        )

    def _document_action(self, action: str | None) -> None:
        if action == "edit":
            self.edit_selected_document()
        elif action == "view":
            selected = self.query_one(DocumentsPane).selected_document()
            if selected is not None:
                path, _, kind = selected
                self.app.page_file(path, terminal_output=kind == "evidence")

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
                restored = restore_engagement_archive(
                    archive, self.app.workspace, context
                )
                self.app.push_screen(
                    MessageModal("Engagement Restored", str(restored))
                )
            elif context["kind"] == "targets":
                restored = restore_target_archive(
                    archive,
                    self.app.workspace,
                    self.record.root,
                    self.engagement,
                    context,
                )
                self.app.push_screen(
                    MessageModal("Target Files Restored", str(restored))
                )
                self.refresh_all()
            else:
                raise ValidationError(f"unsupported archive kind: {context['kind']}")
        except (TacmuxError, OSError, KeyError) as exc:
            self.app.show_error(str(exc))

    def run_operator_command(self, action: str) -> None:
        getattr(self, f"action_{action}")()


class TacmuxApp(App[LaunchIntent | None]):
    BINDINGS: ClassVar[list[Binding]] = [Binding("t", "change_theme", "Theme")]
    CSS = """
    Screen { background: $background; }
    #picker-body { padding: 1 2; }
    #picker-title, #engagement-banner { height: 3; padding: 1 2; text-style: bold; color: $accent; }
    #picker-hint { height: 2; color: $text-muted; }
    #engagement-filter, #target-filter { margin: 0 2; }
    #target-layout, #documents-layout { height: 1fr; }
    #target-table { width: 62%; }
    #target-detail { width: 38%; padding: 1 2; border-left: solid $panel; overflow-y: auto; }
    ScopeDiscoveryPane { height: 1fr; }
    #scope-table { height: 44%; }
    #jobs-table { height: 36%; }
    .section-title { height: 2; padding-left: 1; text-style: bold; }
    #situation-view { height: 1fr; padding: 1 2; overflow-y: auto; }
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
        self.jobs = DiscoveryJobs(settings, self.tmux, self.workspace)
        self.nocap = NocapReader(settings)
        self.register_theme(BLTSEC_THEME)
        saved_theme = self.workspace.get_theme()
        self._invalid_saved_theme = (
            saved_theme if saved_theme and saved_theme not in CURATED_THEME_NAMES else ""
        )
        self._startup_theme = (
            saved_theme if saved_theme in CURATED_THEME_NAMES else DEFAULT_THEME
        )
        for theme_name in tuple(self.available_themes):
            if theme_name not in CURATED_THEME_NAMES:
                self.unregister_theme(theme_name)

    def on_mount(self) -> None:
        self.workspace.initialize()
        self.theme = self._startup_theme
        self.theme_changed_signal.subscribe(self, self._persist_theme)
        if self._invalid_saved_theme:
            self.notify(
                f"Saved theme {self._invalid_saved_theme!r} is unavailable; using {DEFAULT_THEME}",
                title="TACMUX Theme",
                severity="warning",
            )
            self._save_theme(DEFAULT_THEME)
        self.call_after_refresh(self.bootstrap)

    def _persist_theme(self, theme: Theme) -> None:
        self._save_theme(theme.name)

    def _save_theme(self, theme_name: str) -> None:
        try:
            self.workspace.set_theme(theme_name)
        except (OSError, TacmuxError) as exc:
            self.notify(
                f"Theme changed for this run but could not be saved: {exc}",
                title="TACMUX Theme",
                severity="warning",
            )

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

    def page_file(self, path: Path, *, terminal_output: bool = False) -> None:
        try:
            path = path.resolve(strict=True)
            path.relative_to(self.settings.workspace.resolve(strict=True))
            with path.open("rb") as stream:
                if b"\0" in stream.read(64 * 1024):
                    raise ValidationError(
                        "binary evidence cannot be displayed in the terminal pager"
                    )
            candidates = [self.settings.pager_argv, ["less", "-SR"], ["more"]]
            pager = next(
                (argv for argv in candidates if shutil.which(argv[0]) is not None),
                None,
            )
            if pager is None:
                raise ValidationError(
                    "no terminal pager is available; set $PAGER or install less"
                )
            with self.suspend():
                if terminal_output:
                    process = subprocess.Popen(pager, stdin=subprocess.PIPE)
                    assert process.stdin is not None
                    try:
                        with path.open("rb") as stream:
                            for line in iter_rendered(stream):
                                process.stdin.write((line + "\n").encode())
                    except BrokenPipeError:
                        pass
                    finally:
                        try:
                            process.stdin.close()
                        except BrokenPipeError:
                            pass
                        return_code = process.wait()
                else:
                    return_code = subprocess.run(
                        [*pager, str(path)], check=False
                    ).returncode
            if return_code:
                self.show_error(f"pager exited with status {return_code}")
        except (OSError, ValueError, TacmuxError, SuspendNotSupported) as exc:
            self.show_error(str(exc))
