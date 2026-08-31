"""Transient Textual operator cockpit for TACMUX v2."""

from __future__ import annotations

from dataclasses import asdict
import ipaddress
from pathlib import Path
import shutil
import subprocess
from typing import Callable, ClassVar
from uuid import uuid4

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
from rich.text import Text

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
    CleanupForm,
    EngagementDetailsForm,
    EngagementForm,
    ExportForm,
    FindingForm,
    ImportDiscoveryForm,
    LegacyImportForm,
    MessageModal,
    PromptModal,
    ScanForm,
    ServicesModal,
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
from .errors import ConflictError, TacmuxError, ValidationError
from .export import ExportProfile, create_handoff, parse_export_profile
from .migration import import_v1_workspace
from .model import (
    AccessRecord,
    Activity,
    AttackPath,
    CleanupItem,
    Engagement,
    EngagementStatus,
    Finding,
    ScopeAvailability,
    ScopeGroup,
    ScopeKind,
    Target,
    TargetAddress,
    classify_scope,
    looks_like_credential,
    pattern_inside,
    utc_now,
)
from .nocap import NocapReader
from .panes import (
    DocumentsPane,
    RecordsPane,
    ScopeDiscoveryPane,
    SituationPane,
    TargetsPane,
)
from .store import EngagementRecord, Workspace, safe_filename
from .themes import BLTSEC_THEME, CURATED_THEME_NAMES, DEFAULT_THEME
from .terminal_output import iter_rendered
from .tmux import LaunchIntent, TmuxService
from .ui import plain, sentence


def _newest_archives(paths: list[Path]) -> list[Path]:
    def modified(path: Path) -> int:
        try:
            return path.stat().st_mtime_ns
        except OSError:
            return 0

    return sorted((path for path in paths if path.is_file()), key=modified, reverse=True)


def _engagement_archives(settings: Settings) -> list[Path]:
    return _newest_archives(
        list(settings.archive_dir.glob("*/engagements/*.tar.gz"))
    )


def _cockpit_archives(settings: Settings, engagement_id: str) -> list[Path]:
    return _newest_archives(
        [
            *settings.archive_dir.glob("*/engagements/*.tar.gz"),
            *(settings.archive_dir / engagement_id / "targets").glob("*.tar.gz"),
        ]
    )


class OperatorCommands(Provider):
    """Fuzzy access to the same actions exposed by visible UI controls."""

    def _commands(self) -> list[tuple[str, str, str]]:
        screen = self.screen
        available = getattr(screen, "operator_command_available", None)
        commands = list(getattr(screen, "operator_commands", []))
        return [
            command
            for command in commands
            if available is None or available(command[1])
        ]

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
        Binding("enter", "open_selected", "Open"),
        Binding("a", "actions", "Actions"),
        Binding("n", "new_engagement", "New"),
        Binding("i", "import_legacy", "Import v1"),
        Binding("r", "restore", "Restore"),
        Binding("/", "filter", "Filter"),
        Binding("escape", "close_filter", show=False),
        Binding("q", "app.quit", "Quit"),
    ]
    operator_commands: ClassVar[list[tuple[str, str, str]]] = [
        (
            "Engagement actions",
            "actions",
            "Open, archive, or permanently delete the highlighted engagement",
        ),
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
            "Import v1 workspace",
            "import_legacy",
            "Import existing evidence into a stable v2 layout",
        ),
        (
            "Restore verified engagement archive",
            "restore",
            "Restore a deleted or missing engagement from a v2 archive",
        ),
    ]

    def __init__(self):
        super().__init__()
        self.restore_options: list[Path] = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="picker-body"):
            yield Label("Engagements", id="picker-title")
            yield Input(
                placeholder="Filter client, lab, platform, engagement, or type",
                id="engagement-filter",
            )
            yield DataTable(id="engagements", cursor_type="row", zebra_stripes=True)
            yield Static(
                str(self.app.settings.workspace),
                id="picker-hint",
            )
        yield Footer()

    def on_mount(self) -> None:
        self.app.sub_title = ""
        self.call_after_refresh(self._finish_mount)

    def _finish_mount(self) -> None:
        if self.app.screen is not self:
            return
        self.refresh_table()
        self.query_one("#engagements", DataTable).focus()

    def refresh_table(self, query: str = "") -> None:
        table = self.query_one("#engagements", DataTable)
        if not table.columns:
            table.add_columns(
                "Client / Lab / Platform", "Engagement", "Type", "Status", "Targets", "Live"
            )
        table.clear()
        query = query.casefold()
        records = self.app.workspace.list_engagements()
        live = self.app.tmux.live_target_ids_by_engagement()
        for record in records:
            engagement = record.engagement
            haystack = (
                f"{engagement.client} {engagement.name} "
                f"{engagement.assessment_type.value}"
            ).casefold()
            if query and query not in haystack:
                continue
            table.add_row(
                engagement.client,
                engagement.name,
                engagement.assessment_type.value.replace("_", " "),
                engagement.status.value,
                str(len(engagement.targets)),
                str(len(live.get(engagement.id, set()))),
                key=engagement.id,
            )
        self.query_one("#picker-hint", Static).update(
            plain(
                f"{self.app.settings.workspace} · {len(records)} "
                f"{'engagement' if len(records) == 1 else 'engagements'}"
            )
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

    def action_actions(self) -> None:
        try:
            record = self.app.workspace.find(self.selected_id())
        except TacmuxError as exc:
            self.app.show_error(str(exc))
            return
        self.app.push_screen(
            ActionMenu(
                f"{record.engagement.client} / {record.engagement.name}",
                [
                    ("open", "Open engagement"),
                    ("edit", "Edit engagement details"),
                    (
                        "reopen" if record.engagement.status == EngagementStatus.CLOSED else "close",
                        "Reopen engagement"
                        if record.engagement.status == EngagementStatus.CLOSED
                        else "Close engagement",
                    ),
                    ("archive", "Create verified archive"),
                    ("delete", "Delete engagement…"),
                ],
            ),
            lambda action: self._engagement_action(record.engagement.id, action),
        )

    def _engagement_action(self, engagement_id: str, action: str | None) -> None:
        if action == "open":
            try:
                self.app.open_engagement(self.app.workspace.find(engagement_id))
            except TacmuxError as exc:
                self.app.show_error(str(exc))
        elif action == "archive":
            self._archive_engagement(engagement_id)
        elif action == "edit":
            self._edit_engagement(engagement_id)
        elif action == "close":
            self._confirm_close_engagement(engagement_id)
        elif action == "reopen":
            self._set_engagement_status(engagement_id, EngagementStatus.ACTIVE)
        elif action == "delete":
            self._confirm_delete_engagement(engagement_id)

    def _edit_engagement(self, engagement_id: str) -> None:
        try:
            record = self.app.workspace.find(engagement_id)
        except TacmuxError as exc:
            self.app.show_error(str(exc))
            return
        self.app.push_screen(
            EngagementDetailsForm(record.engagement),
            lambda value: self._save_engagement_details(engagement_id, value),
        )

    def _save_engagement_details(self, engagement_id: str, value: dict | None) -> None:
        if value is None:
            return
        try:
            record = self.app.workspace.find(engagement_id)
            self.app.workspace.update_engagement_details(
                record.root, record.engagement, **value
            )
            self.app.render_runtime_documents(record)
            self.refresh_table(self.query_one("#engagement-filter", Input).value)
        except (TacmuxError, OSError, ValueError) as exc:
            self.app.show_error(str(exc))

    def _confirm_close_engagement(self, engagement_id: str) -> None:
        try:
            record = self.app.require_idle_engagement(
                engagement_id, "closing the engagement"
            )
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))
            return
        outstanding = len(record.engagement.outstanding_cleanup)
        message = "Close this engagement? Operational changes will be blocked until it is reopened."
        if outstanding:
            message += f"\n\n{outstanding} cleanup item(s) are still outstanding."
        self.app.push_screen(
            ConfirmModal("Close Engagement", message),
            lambda confirmed: self._set_engagement_status(
                engagement_id, EngagementStatus.CLOSED
            )
            if confirmed
            else None,
        )

    def _set_engagement_status(
        self, engagement_id: str, status: EngagementStatus
    ) -> None:
        try:
            record = self.app.workspace.find(engagement_id)
            self.app.workspace.set_status(record.root, record.engagement, status)
            self.app.render_runtime_documents(record)
            self.refresh_table(self.query_one("#engagement-filter", Input).value)
            self.app.notify(f"Engagement {status.value}")
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))

    def _archive_engagement(self, engagement_id: str) -> None:
        try:
            archive = self.app.archive_engagement(engagement_id)
            self.app.push_screen(
                MessageModal("Engagement Archive Verified", str(archive))
            )
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))

    def _confirm_delete_engagement(self, engagement_id: str) -> None:
        try:
            record = self.app.require_idle_engagement(
                engagement_id, "deleting the engagement"
            )
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))
            return
        engagement = record.engagement
        message = (
            "This permanently deletes the complete live engagement directory, "
            "including scope, targets, notes, findings, evidence, and completed "
            "jobs.\n\n"
            f"Client / Lab / Platform: {engagement.client}\n"
            f"Engagement: {engagement.name}\n"
            f"Stable ID: {engagement.id}\n"
            f"Directory: {record.root}\n\n"
            "Verified archives stored outside this directory are not deleted."
        )
        self.app.push_screen(
            ConfirmModal(
                "Permanently Delete Engagement",
                message,
                f"DELETE {engagement.id}",
            ),
            lambda confirmed: self._delete_engagement(engagement.id)
            if confirmed
            else None,
        )

    def _delete_engagement(self, engagement_id: str) -> None:
        deleted_name = engagement_id
        try:
            record = self.app.require_idle_engagement(
                engagement_id, "deleting the engagement"
            )
            deleted_name = (
                f"{record.engagement.client} / {record.engagement.name}"
            )
            self.app.workspace.delete_engagement(engagement_id)
            self.app.notify(f"Permanently deleted {deleted_name}")
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))
        finally:
            query = self.query_one("#engagement-filter", Input).value
            self.refresh_table(query)
            self.query_one("#engagements", DataTable).focus()

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
        self.action_close_filter()
        if self.query_one("#engagements", DataTable).row_count:
            self.action_open_selected()

    def action_close_filter(self) -> None:
        field = self.query_one("#engagement-filter", Input)
        if field.display:
            field.display = False
            self.query_one("#engagements", DataTable).focus()

    def action_new_engagement(self) -> None:
        self.app.push_screen(
            EngagementForm(self.app.settings.auto_log), self._create_engagement
        )

    def _create_engagement(self, value: dict | None) -> None:
        if value is None:
            return
        try:
            scope_specs: list[
                tuple[str, ScopeGroup, str, ScopeAvailability, list[str]]
            ] = []
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
                    scope_specs.append((label, group, network, availability, []))
            for raw_line in value["exclusions"].splitlines():
                exclusion = raw_line.strip()
                if not exclusion:
                    continue
                kind, excluded_network, excluded_domain, _ = classify_scope(exclusion)
                matches: list[int] = []
                for index, (_, _, scope_value, _, _) in enumerate(scope_specs):
                    scope_kind, scope_network, scope_domain, _ = classify_scope(scope_value)
                    if scope_kind != kind:
                        continue
                    if kind == ScopeKind.NETWORK:
                        try:
                            inside = ipaddress.ip_network(excluded_network).subnet_of(
                                ipaddress.ip_network(scope_network)
                            )
                        except TypeError:
                            inside = False
                    else:
                        inside = pattern_inside(excluded_domain, scope_domain)
                    if inside:
                        matches.append(index)
                if len(matches) != 1:
                    raise ValidationError(
                        f"exclusion {exclusion} must be inside exactly one front-loaded scope entry"
                    )
                scope_specs[matches[0]][4].append(exclusion)
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

    def action_restore(self) -> None:
        self.restore_options = _engagement_archives(self.app.settings)
        if not self.restore_options:
            self._prompt_restore_path()
            return
        self.app.push_screen(
            ActionMenu(
                "Restore Engagement Archive",
                [
                    (str(index), str(path))
                    for index, path in enumerate(self.restore_options)
                ]
                + [("path", "Enter a path…")],
            ),
            self._restore_choice,
        )

    def _restore_choice(self, value: str | None) -> None:
        if value == "path":
            self._prompt_restore_path()
        elif value is not None:
            try:
                path = self.restore_options[int(value)]
            except (IndexError, ValueError):
                self.app.show_error("The selected archive is no longer available")
            else:
                self._restore(str(path))

    def _prompt_restore_path(self) -> None:
        self.app.push_screen(
            PromptModal("Restore Engagement Archive", "Path to .tar.gz archive"),
            self._restore,
        )

    def _restore(self, value: str | None) -> None:
        if value is None:
            return
        try:
            archive = Path(value).expanduser()
            document = verify_archive(archive)
            context = document["context"]
            if context["kind"] != "engagements":
                raise ValidationError(
                    "The engagement picker can restore engagement archives only"
                )
            restored = restore_engagement_archive(
                archive, self.app.workspace, context
            )
            self.refresh_table(self.query_one("#engagement-filter", Input).value)
            self.app.push_screen(MessageModal("Engagement Restored", str(restored)))
        except (TacmuxError, OSError, KeyError) as exc:
            self.app.show_error(str(exc))

    def run_operator_command(self, action: str) -> None:
        getattr(self, f"action_{action}")()


class MainScreen(Screen):
    BINDINGS: ClassVar[list[Binding]] = [
        Binding("enter", "default_action", "Attach"),
        Binding("a", "actions", "Actions"),
        Binding("n", "new_target", "New"),
        Binding("d", "discovery", "Scan"),
        Binding("e", "switch_engagement", "Switch"),
        Binding("g", "switch_engagement", "Engagements", show=False),
        Binding("/", "filter", "Find"),
        Binding("escape", "close_filter", show=False),
        Binding("r", "refresh", "Refresh", show=False),
        Binding("1", "tab('targets')", "Targets", show=False),
        Binding("2", "tab('scope')", "Scope", show=False),
        Binding("3", "tab('records')", "Records", show=False),
        Binding("4", "tab('situation')", "Situation", show=False),
        Binding("5", "tab('documents')", "Documents", show=False),
        Binding("q", "app.quit", "Quit"),
    ]
    ACTIVE_ONLY_BINDINGS: ClassVar[set[str]] = {
        "default_action",
        "new_target",
        "discovery",
    }
    ACTIVE_ONLY_COMMANDS: ClassVar[set[str]] = {
        "attach",
        "new_target",
        "add_scope",
        "scan",
        "import_discovery",
        "import_completed",
        "activity",
        "attack_path",
        "ops",
    }
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
            "Run detached discovery",
            "scan",
            "Choose host-only or full TCP service discovery",
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
            "Record activity",
            "activity",
            "Record a confirmed, failed, or no-result activity",
        ),
        (
            "Build confirmed attack path",
            "attack_path",
            "Assemble a path from confirmed records",
        ),
        (
            "Open records",
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
            "Export engagement handoff",
            "export",
            "Create one Markdown file containing records, notes, paths, and evidence context",
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
        self._manifest_mtime = 0
        self._job_statuses: dict[str, tuple[str, str]] = {}
        self.pending_service_copy: tuple[Path, Path] | None = None
        self.restore_options: list[Path] = []
        self._active_tab = "targets"

    @property
    def engagement(self) -> Engagement:
        return self.record.engagement

    @property
    def document_paths(self) -> dict[str, tuple[Path, bool, str]]:
        return self.query_one(DocumentsPane).document_paths

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        if (
            self.engagement.status == EngagementStatus.CLOSED
            and action in self.ACTIVE_ONLY_BINDINGS
        ):
            return False
        return True

    def operator_command_available(self, action: str) -> bool:
        return not (
            self.engagement.status == EngagementStatus.CLOSED
            and action in self.ACTIVE_ONLY_COMMANDS
        )

    def _require_active(self) -> None:
        if self.engagement.status == EngagementStatus.CLOSED:
            raise ConflictError(
                "Engagement is closed — reopen it from the engagement picker"
            )

    def _confirm_window(self, callback: Callable[[], None]) -> bool:
        if self.engagement.authorization.window_state() != "outside":
            return True
        authorization = self.engagement.authorization
        self.app.push_screen(
            ConfirmModal(
                "Outside Authorized Window",
                "Authorized window: "
                f"{authorization.window_start or 'open'} – "
                f"{authorization.window_end or 'open'}\n\nContinue anyway?",
            ),
            lambda confirmed: callback() if confirmed else None,
        )
        return False

    def _confirm_potential_credentials(
        self, value: dict, callback: Callable[[], None]
    ) -> bool:
        labels = {
            "principal": "principal",
            "authority": "authority / realm",
            "method": "method",
        }
        suspicious = [
            label
            for field, label in labels.items()
            if looks_like_credential(str(value.get(field, "")))
        ]
        if not suspicious:
            return True
        field_label = "field" if len(suspicious) == 1 else "fields"
        verb = "looks" if len(suspicious) == 1 else "look"
        pronoun = "it may" if len(suspicious) == 1 else "they may"
        self.app.push_screen(
            ConfirmModal(
                "Potential Credential Material",
                "The "
                + ", ".join(suspicious)
                + f" {field_label} {verb} like {pronoun} contain credential material. "
                "Record the identity and access method, not the secret itself.\n\n"
                "Save this record anyway?",
            ),
            lambda confirmed: callback() if confirmed else None,
        )
        return False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Label(
            plain(f"{self.engagement.client}  /  {self.engagement.name}"),
            id="engagement-banner",
        )
        yield Input(placeholder="Filter targets", id="target-filter")
        with TabbedContent(initial="targets", id="workspace-tabs"):
            with TabPane("1 Targets", id="targets"):
                yield TargetsPane(id="target-layout")
            with TabPane("2 Scope", id="scope"):
                yield ScopeDiscoveryPane()
            with TabPane("3 Records", id="records"):
                yield RecordsPane()
            with TabPane("4 Situation", id="situation"):
                yield SituationPane(id="situation-view")
            with TabPane("5 Documents", id="documents"):
                yield DocumentsPane(id="documents-layout")
        yield Footer()

    def on_mount(self) -> None:
        self.app.title = "TACMUX"
        self.app.sub_title = f"{self.engagement.client}: {self.engagement.name}"
        self.call_after_refresh(self._finish_mount)
        self.set_interval(3.0, self._poll_external_state)

    def _finish_mount(self) -> None:
        if self.app.screen is not self:
            return
        self.refresh_all()
        self.query_one("#target-table", DataTable).focus()

    def on_resize(self, event: events.Resize) -> None:
        self.set_class(event.size.width < 100, "narrow")

    def action_tab(self, tab_id: str) -> None:
        self.query_one("#workspace-tabs", TabbedContent).active = tab_id
        self._handle_tab_change(tab_id)
        focus_target = {
            "targets": "#target-table",
            "scope": "#scope-table",
            "records": "#records-table",
            "situation": "#situation-view",
            "documents": "#documents-table",
        }.get(tab_id)
        if focus_target:
            self.query_one(focus_target).focus()

    @on(TabbedContent.TabActivated, "#workspace-tabs")
    def tab_activated(self) -> None:
        self._handle_tab_change(
            self.query_one("#workspace-tabs", TabbedContent).active
        )

    def _handle_tab_change(self, tab_id: str) -> None:
        if tab_id == self._active_tab:
            return
        self._active_tab = tab_id
        field = self.query_one("#target-filter", Input)
        field.display = False
        if field.value:
            field.value = ""
        if tab_id == "documents":
            self.query_one(DocumentsPane).populate(self.record)

    def selected_target(self, *, required: bool = True) -> Target | None:
        target_id = self.query_one(TargetsPane).selected_target_id(required=required)
        return self.engagement.target_by_id(target_id) if target_id else None

    def _status_line(self, jobs: list[dict]) -> Text:
        active_jobs = sum(
            item.get("state") in {"queued", "running"} for item in jobs
        )
        identity = (f"{self.engagement.client} / {self.engagement.name}", "")
        state = self.engagement.authorization.window_state()
        if self.engagement.status == EngagementStatus.CLOSED:
            parts: list[tuple[str, str]] = [("CLOSED", "bold red"), identity]
        elif state == "outside":
            parts = [("OUTSIDE WINDOW", "bold dark_orange"), identity]
        else:
            parts = [identity]
        parts.extend(
            [
                (
                    f"{len(self.engagement.targets)} "
                    f"{'target' if len(self.engagement.targets) == 1 else 'targets'}",
                    "",
                ),
                (f"{len(self.live_target_ids)} live", ""),
                (
                    f"{active_jobs} "
                    f"{'job' if active_jobs == 1 else 'jobs'} running",
                    "",
                ),
                (
                    "logging on"
                    if self.engagement.logging_enabled
                    else "logging off",
                    "",
                ),
            ]
        )
        if self.engagement.outstanding_cleanup:
            parts.append((f"cleanup {len(self.engagement.outstanding_cleanup)}", ""))
        if self.engagement.status != EngagementStatus.CLOSED and state != "outside":
            if self.engagement.authorization.window_end:
                parts.append(
                    (f"window ends {self.engagement.authorization.window_end}", "")
                )
            else:
                parts.append(("window not set", ""))
        result = Text()
        for index, (value, style) in enumerate(parts):
            if index:
                result.append(" · ")
            result.append(value, style=style)
        return result

    def refresh_all(self) -> bool:
        try:
            record = EngagementRecord(
                self.record.root, self.app.workspace.load(self.record.root)
            )
            live = self.app.tmux.live_target_ids(record.engagement)
            jobs = self.app.jobs.list(record.root)
            statuses = {
                str(item.get("id")): (
                    str(item.get("state")),
                    str(item.get("phase", "")),
                )
                for item in jobs
            }
            manifest_mtime = self.app.workspace.render_documents(
                record.root,
                record.engagement,
                live_target_ids=live,
                jobs=jobs,
            )
            self.record = record
            self.refresh_bindings()
            self.live_target_ids = live
            self._manifest_mtime = manifest_mtime
            self._job_statuses = statuses
            self._populate_panes(
                {"targets", "scope", "records", "situation", "documents"}, jobs
            )
            return True
        except (TacmuxError, OSError, ValueError) as exc:
            self.app.show_error(str(exc))
            return False

    def after_mutation(self, *panes: str) -> bool:
        try:
            live = self.app.tmux.live_target_ids(self.engagement)
            jobs = self.app.jobs.list(self.record.root)
            manifest_mtime = self.app.workspace.render_documents(
                self.record.root,
                self.engagement,
                live_target_ids=live,
                jobs=jobs,
            )
            self.live_target_ids = live
            self._manifest_mtime = manifest_mtime
            self._job_statuses = {
                str(item.get("id")): (
                    str(item.get("state")),
                    str(item.get("phase", "")),
                )
                for item in jobs
            }
            selected = set(panes)
            if self.query_one("#workspace-tabs", TabbedContent).active == "documents":
                selected.add("documents")
            self._populate_panes(selected, jobs)
            return True
        except (TacmuxError, OSError, ValueError) as exc:
            self.app.show_error(
                f"State was saved, but generated documents could not be refreshed: {exc}"
            )
            return False

    def _populate_panes(self, panes: set[str], jobs: list[dict]) -> None:
        active = self.query_one("#workspace-tabs", TabbedContent).active
        query = self.query_one("#target-filter", Input).value
        if "targets" in panes:
            self.query_one(TargetsPane).populate(
                self.engagement,
                self.live_target_ids,
                query if active == "targets" else "",
            )
        if "scope" in panes:
            self.query_one(ScopeDiscoveryPane).populate(self.engagement, jobs)
        if "records" in panes:
            self.query_one(RecordsPane).populate(
                self.engagement,
                query if active == "records" else "",
                root=self.record.root,
            )
        if "situation" in panes:
            self.query_one(SituationPane).populate(self.engagement)
        if "documents" in panes:
            self.query_one(DocumentsPane).populate(
                self.record,
                query if active == "documents" else "",
                include_evidence=active == "documents",
            )
        self.query_one("#engagement-banner", Label).update(self._status_line(jobs))

    def _poll_external_state(self) -> None:
        if self.app.screen is not self:
            return
        try:
            mtime = (
                self.record.root / ".tacmux/engagement.json"
            ).stat().st_mtime_ns
            jobs = self.app.jobs.list(self.record.root)
            statuses = {
                str(item.get("id")): (
                    str(item.get("state")),
                    str(item.get("phase", "")),
                )
                for item in jobs
            }
            live = self.app.tmux.live_target_ids(self.engagement)
            changed_jobs = [
                (job_id, status[0])
                for job_id, status in statuses.items()
                if (
                    self._job_statuses.get(job_id, ("", ""))[0]
                    != status[0]
                )
                and status[0] in {"succeeded", "partial", "failed", "cancelled"}
            ]
            if (
                mtime != self._manifest_mtime
                or statuses != self._job_statuses
                or live != self.live_target_ids
            ):
                self.refresh_all()
            for job_id, state in changed_jobs:
                self.app.notify(f"Discovery {job_id} {state} — press d to import")
        except (TacmuxError, OSError, ValueError) as exc:
            self.app.show_error(str(exc))

    @on(DataTable.RowSelected)
    def row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "target-table":
            self.action_attach()
        elif event.data_table.id == "scope-table":
            self.edit_scope()
        elif event.data_table.id == "jobs-table":
            self.job_actions()
        elif event.data_table.id == "records-table":
            self.edit_selected_record()
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
        elif active == "records":
            self.edit_selected_record()

    def action_filter(self) -> None:
        field = self.query_one("#target-filter", Input)
        active = self.query_one("#workspace-tabs", TabbedContent).active
        if active not in {"targets", "records", "documents"}:
            self.action_tab("targets")
            active = "targets"
        field.placeholder = f"Filter {active}"
        field.display = True
        field.focus()

    def action_close_filter(self) -> None:
        field = self.query_one("#target-filter", Input)
        if not field.display:
            return
        field.display = False
        active = self.query_one("#workspace-tabs", TabbedContent).active
        self.query_one(
            "#records-table"
            if active == "records"
            else "#documents-table"
            if active == "documents"
            else "#target-table",
            DataTable,
        ).focus()

    @on(Input.Changed, "#target-filter")
    def filter_changed(self, event: Input.Changed) -> None:
        active = self.query_one("#workspace-tabs", TabbedContent).active
        if active == "records":
            self.query_one(RecordsPane).populate(
                self.engagement, event.value, root=self.record.root
            )
        elif active == "documents":
            self.query_one(DocumentsPane).populate(self.record, event.value)
        else:
            self.query_one(TargetsPane).populate(
                self.engagement,
                self.live_target_ids,
                event.value,
            )

    @on(Input.Submitted, "#target-filter")
    def filter_submitted(self) -> None:
        active = self.query_one("#workspace-tabs", TabbedContent).active
        self.action_close_filter()
        table = self.query_one(
            "#records-table"
            if active == "records"
            else "#documents-table"
            if active == "documents"
            else "#target-table",
            DataTable,
        )
        if table.row_count:
            self.action_default_action()

    def action_refresh(self) -> None:
        if self.refresh_all():
            self.app.notify("Topology, jobs, live sessions, and SITREP refreshed")

    def action_switch_engagement(self) -> None:
        self.app.switch_screen(EngagementPickerScreen())

    def action_new_target(self) -> None:
        try:
            self._require_active()
            self.app.push_screen(TargetForm(self.engagement), self._create_target)
        except TacmuxError as exc:
            self.app.show_error(str(exc))

    def _create_target(self, value: dict | None) -> None:
        if value is None:
            return
        try:
            addresses = (
                [TargetAddress(value["address"], value["scope_id"])]
                if value["address"]
                else []
            )
            primary = value["address"] or (
                next(
                    (
                        hostname
                        for hostname in value["hostnames"]
                        if not self.engagement.domain_entries
                        or self.engagement.hostname_scope(hostname)
                    ),
                    "",
                )
            )
            self.app.workspace.create_target(
                self.record.root,
                self.engagement,
                value["display_name"],
                addresses=addresses,
                hostnames=value["hostnames"],
                primary_endpoint=primary,
            )
            self.after_mutation("targets", "situation")
        except (TacmuxError, OSError, ValueError) as exc:
            self.app.show_error(str(exc))

    def action_add_scope(self) -> None:
        try:
            self._require_active()
            self.app.push_screen(ScopeForm(self.engagement), self._add_scope)
        except TacmuxError as exc:
            self.app.show_error(str(exc))

    def _add_scope(self, value: dict | None) -> None:
        if value is None:
            return
        try:
            self.app.workspace.add_scope(
                self.record.root, self.engagement, **value
            )
            self.after_mutation("scope", "targets", "situation")
        except (TacmuxError, OSError, ValueError) as exc:
            self.app.show_error(str(exc))

    def selected_scope_id(self) -> str:
        return self.query_one(ScopeDiscoveryPane).selected_scope_id()

    def scope_actions(self) -> None:
        if self.engagement.status == EngagementStatus.CLOSED:
            self.app.show_error(
                "Engagement is closed — reopen it to change scope or discovery"
            )
            return
        actions = [
            ("edit_scope", "Edit selected scope entry"),
            ("delete_scope", "Delete selected unused scope entry"),
            ("add_scope", "Add external or internal scope"),
            ("discovery", "Host discovery actions"),
        ]
        self.app.push_screen(
            ActionMenu("Scope and Discovery", actions), self._scope_action
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
            self._require_active()
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
            self.after_mutation("scope", "targets", "situation")
        except (TacmuxError, OSError, ValueError) as exc:
            self.app.show_error(str(exc))

    def delete_scope(self) -> None:
        try:
            self._require_active()
            scope = self.engagement.scope_by_id(self.selected_scope_id())
        except TacmuxError as exc:
            self.app.show_error(str(exc))
            return
        self.app.push_screen(
            ConfirmModal(
                "Delete Scope Entry",
                f"Delete {scope.label} ({scope.spec})? Referenced scope cannot be deleted.",
            ),
            lambda confirmed: self._delete_scope(scope.id) if confirmed else None,
        )

    def _delete_scope(self, scope_id: str) -> None:
        try:
            self.app.workspace.delete_scope(self.record.root, self.engagement, scope_id)
            self.after_mutation("scope", "targets", "situation")
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))

    def action_attach(self) -> None:
        self._attach_target(window_checked=False)

    def _attach_target(self, *, window_checked: bool) -> None:
        try:
            self._require_active()
            if not window_checked and not self._confirm_window(
                lambda: self._attach_target(window_checked=True)
            ):
                return
            target = self.selected_target()
            intent = self.app.tmux.start_target(
                self.record.root, self.engagement, target
            )
            self.app.exit(intent)
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))

    def action_ops(self) -> None:
        self._open_ops(window_checked=False)

    def _open_ops(self, *, window_checked: bool) -> None:
        try:
            self._require_active()
            if not window_checked and not self._confirm_window(
                lambda: self._open_ops(window_checked=True)
            ):
                return
            self.app.exit(self.app.tmux.start_ops(self.record.root, self.engagement))
        except TacmuxError as exc:
            self.app.show_error(str(exc))

    def action_stop_ops(self) -> None:
        try:
            self.app.tmux.stop_ops(self.engagement)
            self.after_mutation()
            self.app.notify("Engagement operations session stopped")
        except TacmuxError as exc:
            self.app.show_error(str(exc))

    def action_stop_all(self) -> None:
        try:
            jobs = self.app.jobs.cancel_all(self.record.root, self.engagement)
            sessions = self.app.tmux.stop_engagement_sessions(self.engagement)
            self.after_mutation("targets", "scope")
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
        elif active == "records":
            self.records_actions()
        elif active == "documents":
            self.document_actions()
        elif active == "situation":
            actions = [("refresh", "Refresh topology and SITREP")]
            if self.engagement.status != EngagementStatus.CLOSED:
                actions.insert(0, ("attack_path", "Build confirmed attack path"))
            self.app.push_screen(
                ActionMenu(
                    "Situation",
                    actions,
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
        if self.engagement.status == EngagementStatus.CLOSED:
            actions = [
                ("notes", "Edit target notes"),
                ("services", "View services"),
                ("archive", "Archive target"),
            ]
            if self.app.settings.nocap_enabled:
                actions.insert(-1, ("nocap", "View NOCAP timeline"))
            self.app.push_screen(
                ActionMenu(target.display_name, actions), self._target_action
            )
            return
        actions = [("attach", "Attach" if running else "Start and attach")]
        if running:
            actions.append(("stop", "Stop session"))
        actions.extend(
            [
                ("identity", "Edit target identity and addresses"),
                ("notes", "Edit target notes"),
                ("services", "Services"),
                ("access", "Record confirmed access"),
                ("activity", "Record activity"),
                ("finding", "Create finding"),
                ("cleanup", "Record cleanup item"),
                ("archive", "Archive target"),
                ("delete", "Delete target…"),
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
            "services": self.show_services,
            "access": self.record_access,
            "activity": self.action_activity,
            "finding": self.create_finding,
            "cleanup": self.record_cleanup,
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
            self.after_mutation("targets", "situation")
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
            self.after_mutation("targets", "situation")
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
            self.after_mutation("targets", "situation")
        except (TacmuxError, OSError, ValueError) as exc:
            self.app.show_error(str(exc))

    def choose_primary_endpoint(self) -> None:
        target = self.selected_target()
        hostnames = target.hostnames
        if self.engagement.domain_entries:
            hostnames = [
                item for item in hostnames if self.engagement.hostname_scope(item)
            ]
        endpoints = list(
            dict.fromkeys(
                [*hostnames, *(item.value for item in target.addresses)]
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
            self.after_mutation("targets", "situation")
        except (TacmuxError, OSError, ValueError) as exc:
            self.app.show_error(str(exc))

    def stop_target(self) -> None:
        try:
            target = self.selected_target()
            self.app.tmux.stop_target(self.engagement, target)
            self.after_mutation("targets")
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
            warning = self.app.workspace.rename_target(
                self.record.root, self.engagement, target_id, value
            )
            self.after_mutation("targets", "records", "situation")
            if warning:
                self.app.notify(warning, severity="warning")
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))

    def edit_target_notes(self) -> None:
        target = self.selected_target()
        self.app.edit_file(self.record.root / "targets" / target.directory / "NOTES.md")
        self.query_one(DocumentsPane).populate(self.record)

    def show_services(self) -> None:
        target = self.selected_target()
        self.app.push_screen(
            ServicesModal(target),
            lambda action: self._confirm_clear_services(target.id)
            if action == "clear"
            else None,
        )

    def _confirm_clear_services(self, target_id: str) -> None:
        self.app.push_screen(
            ConfirmModal(
                "Clear Services",
                "Remove the imported service snapshot from this target? The source XML is retained.",
            ),
            lambda confirmed: self._clear_services(target_id) if confirmed else None,
        )

    def _clear_services(self, target_id: str) -> None:
        try:
            self.app.workspace.clear_services(
                self.record.root, self.engagement, target_id
            )
            self.after_mutation("targets")
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))

    def record_cleanup(self) -> None:
        try:
            self._require_active()
            target = self.selected_target(required=False)
            self.app.push_screen(
                CleanupForm(self.engagement, target), self._create_cleanup
            )
        except TacmuxError as exc:
            self.app.show_error(str(exc))

    def _create_cleanup(self, value: dict | None) -> None:
        if value is None:
            return
        try:
            self.app.workspace.create_cleanup_item(
                self.record.root, self.engagement, **value
            )
            self.after_mutation("records")
        except (TacmuxError, OSError, ValueError) as exc:
            self.app.show_error(str(exc))

    def record_access(self) -> None:
        try:
            self._require_active()
            target = self.selected_target()
            self.app.push_screen(
                AccessForm(target.display_name),
                lambda value: self._record_access(target.id, value),
            )
        except TacmuxError as exc:
            self.app.show_error(str(exc))

    def _record_access(
        self,
        target_id: str,
        value: dict | None,
        *,
        credential_checked: bool = False,
    ) -> None:
        if value is None:
            return
        if not credential_checked and not self._confirm_potential_credentials(
            value,
            lambda: self._record_access(
                target_id, value, credential_checked=True
            ),
        ):
            return
        try:
            self.app.workspace.create_access(
                self.record.root, self.engagement, target_id, **value
            )
            self.after_mutation("targets", "records", "situation")
        except (TacmuxError, OSError, ValueError) as exc:
            self.app.show_error(str(exc))

    def action_activity(self) -> None:
        try:
            self._require_active()
            target = self.selected_target(required=False)
            self.app.push_screen(
                ActivityForm(self.engagement, target.id if target else ""),
                self._record_activity,
            )
        except TacmuxError as exc:
            self.app.show_error(str(exc))

    def _record_activity(self, value: dict | None) -> None:
        if value is None:
            return
        try:
            self.app.workspace.create_activity(
                self.record.root, self.engagement, **value
            )
            self.after_mutation("targets", "records")
        except (TacmuxError, OSError, ValueError) as exc:
            self.app.show_error(str(exc))

    def create_finding(self) -> None:
        try:
            self._require_active()
            target = self.selected_target(required=False)
            self.app.push_screen(
                FindingForm(self.engagement, target.id if target else ""),
                self._create_finding,
            )
        except TacmuxError as exc:
            self.app.show_error(str(exc))

    def _create_finding(self, value: dict | None) -> None:
        if value is None:
            return
        try:
            finding = self.app.workspace.create_finding(
                self.record.root, self.engagement, **value
            )
            self.app.edit_file(self.record.root / finding.document)
            self.after_mutation("records")
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))

    def action_attack_path(self) -> None:
        try:
            self._require_active()
            self.app.push_screen(
                AttackPathForm(self.engagement), self._create_attack_path
            )
        except TacmuxError as exc:
            self.app.show_error(str(exc))

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
            self.after_mutation("records", "situation")
            self.action_tab("situation")
        except (TacmuxError, OSError, ValueError) as exc:
            self.app.show_error(str(exc))

    def action_records(self) -> None:
        self.action_tab("records")

    def edit_selected_record(self) -> None:
        selected = self.query_one(RecordsPane).selected_record()
        if selected is None:
            self.app.show_error("No engagement record is selected")
            return
        self._edit_record(*selected)

    def records_actions(self) -> None:
        selected = self.query_one(RecordsPane).selected_record()
        actions = [
            ("activity", "Record activity"),
            ("cleanup", "Record cleanup item"),
            ("attack_path", "Build confirmed attack path"),
        ]
        if selected:
            actions[:0] = [("edit", "Edit record"), ("delete", "Delete record")]
            if selected[0] == "cleanup":
                item = self._record(*selected)
                if not item.removed_at:
                    actions.insert(2, ("removed", "Mark cleanup item removed"))
        self.app.push_screen(
            ActionMenu("Records", actions),
            lambda action: self._records_action(selected, action),
        )

    def _records_action(
        self, selected: tuple[str, str] | None, action: str | None
    ) -> None:
        if not action:
            return
        if action in {"activity", "cleanup", "attack_path"}:
            if action == "cleanup":
                self.record_cleanup()
                return
            self.run_operator_command(action)
        elif action == "removed" and selected:
            self._mark_cleanup_removed(selected[1])
        elif selected:
            self._record_action(*selected, action)

    def _mark_cleanup_removed(self, item_id: str) -> None:
        try:
            self.app.workspace.mark_cleanup_removed(
                self.record.root, self.engagement, item_id
            )
            self.after_mutation("records")
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))

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
    ) -> AccessRecord | Activity | Finding | AttackPath | CleanupItem:
        collections = {
            "access": self.engagement.access,
            "activity": self.engagement.activities,
            "finding": self.engagement.findings,
            "attack_path": self.engagement.attack_paths,
            "cleanup": self.engagement.cleanup,
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
            elif kind == "cleanup":
                form = CleanupForm(self.engagement, item=record)
            else:
                form = AttackPathForm(self.engagement, path=record)
            self.app.push_screen(
                form, lambda value: self._save_record(kind, record_id, value)
            )
        except TacmuxError as exc:
            self.app.show_error(str(exc))

    def _save_record(
        self,
        kind: str,
        record_id: str,
        value: dict | None,
        *,
        credential_checked: bool = False,
    ) -> None:
        if value is None:
            return
        if (
            kind == "access"
            and not credential_checked
            and not self._confirm_potential_credentials(
                value,
                lambda: self._save_record(
                    kind, record_id, value, credential_checked=True
                ),
            )
        ):
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
        self.after_mutation("targets", "records", "situation")

    def _delete_record(self, kind: str, record_id: str) -> None:
        try:
            self.app.workspace.delete_record(
                self.record.root, self.engagement, kind, record_id
            )
            self.after_mutation("targets", "records", "situation")
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
            "It is only allowed when no scope, access, activity, finding, attack-path, "
            "or cleanup references remain."
        )
        self.app.push_screen(
            ConfirmModal("Delete Target", message, required),
            lambda confirmed: self._delete_target(target.id) if confirmed else None,
        )

    def _delete_target(self, target_id: str) -> None:
        try:
            self.app.workspace.delete_target(
                self.record.root, self.engagement, target_id
            )
            self.after_mutation("targets", "situation")
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))

    def action_scan(self) -> None:
        try:
            self._require_active()
            self.app.push_screen(ScanForm(self.engagement), self._start_scan)
        except TacmuxError as exc:
            self.app.show_error(str(exc))

    def action_discovery(self) -> None:
        self.app.push_screen(
            ActionMenu(
                "Host Discovery",
                [
                    ("scan", "Run Nmap discovery (detached)"),
                    ("import_discovery", "Import XML or pasted hosts"),
                    ("import_completed", "Review a completed detached scan"),
                ],
            ),
            lambda action: self.run_operator_command(action) if action else None,
        )

    def _start_scan(
        self, value: dict | list[str] | None, *, window_checked: bool = False
    ) -> None:
        if not value:
            return
        if isinstance(value, list):
            scan = {"scope_ids": value, "profile": "hosts", "pace": "careful"}
        else:
            scan = value
        scope_ids = list(scan.get("scope_ids", []))
        if not scope_ids:
            return
        try:
            self._require_active()
            if not window_checked and not self._confirm_window(
                lambda: self._start_scan(scan, window_checked=True)
            ):
                return
            job = self.app.jobs.create(
                self.record.root,
                self.engagement,
                scope_ids,
                profile=str(scan.get("profile", "hosts")),
                pace=str(scan.get("pace", "careful")),
            )
            self.app.notify(f"Discovery {job['id']} started in detached mode")
            self.action_tab("scope")
            self.after_mutation("scope")
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))

    def action_import_discovery(self) -> None:
        self.pending_job_id = ""
        self.app.push_screen(ImportDiscoveryForm(self.engagement), self._prepare_import)

    def action_import_completed(self) -> None:
        jobs = [
            item
            for item in self.app.jobs.list(self.record.root)
            if item.get("state") in {"succeeded", "partial"}
            and not item.get("imported_at")
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
        if (
            job is None
            or job.get("state") not in {"succeeded", "partial"}
            or job.get("imported_at")
        ):
            self.app.show_error(
                "Only a successful or partial, not-yet-imported discovery job can be imported"
            )
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
        if job.get("state") in {"succeeded", "partial"} and not job.get("imported_at"):
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
                self.after_mutation("scope")
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
        try:
            candidates = self.app.jobs.candidates(self.record.root, job_id)
            self.pending_service_copy = None
            self._review_candidates(candidates, list(job.get("scope_ids", [])))
        except (TacmuxError, OSError) as exc:
            self.pending_job_id = ""
            self.app.show_error(str(exc))

    def _prepare_import(self, value: dict | None) -> None:
        if value is None:
            return
        try:
            self.pending_service_copy = None
            if value["xml_path"]:
                source_path = Path(value["xml_path"]).expanduser().resolve(strict=True)
                try:
                    source_reference = str(
                        source_path.relative_to(self.record.root.resolve(strict=True))
                    )
                    external_source = False
                except ValueError:
                    filename = safe_filename(source_path.name, "nmap.xml")
                    source_reference = (
                        ".tacmux/imports/"
                        f"{utc_now().replace(':', '').replace('-', '')}-"
                        f"{uuid4().hex[:6]}-{filename}"
                    )
                    external_source = True
                candidates = parse_nmap_xml(
                    source_path, source=source_reference
                )
                if external_source and any(item.services for item in candidates):
                    self.pending_service_copy = (
                        source_path,
                        self.record.root / source_reference,
                    )
            else:
                candidates = parse_host_lines(value["pasted"])
            self._review_candidates(candidates, list(value["scope_ids"]))
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))

    def _review_candidates(self, candidates: list, scope_ids: list[str]) -> None:
        decisions = reconcile_candidates(
            self.engagement, candidates, allowed_scope_ids=set(scope_ids)
        )
        merge_targets = [
            (
                target.id,
                f"{target.display_name} — "
                f"{', '.join(item.value for item in target.addresses) or 'no address'}",
            )
            for target in self.engagement.targets
        ]
        self.app.push_screen(
            DiscoveryReview(
                decisions,
                merge_targets,
                allowed_scope_ids=scope_ids,
            ),
            self._commit_import,
        )

    def _commit_import(
        self,
        value: tuple[list, bool, set[str]] | None,
        *,
        window_checked: bool = False,
    ) -> None:
        if value is None:
            return
        decisions, create_sessions, allowed_scope_ids = value
        try:
            self._require_active()
            if create_sessions and not window_checked and not self._confirm_window(
                lambda: self._commit_import(value, window_checked=True)
            ):
                return
            targets = apply_reconciliation(
                self.app.workspace,
                self.record.root,
                self.engagement,
                decisions,
                allowed_scope_ids=allowed_scope_ids,
                source_copy=self.pending_service_copy,
            )
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))
            return

        job_id = self.pending_job_id
        self.pending_job_id = ""
        self.pending_service_copy = None
        warnings: list[str] = []
        if job_id:
            try:
                self.app.jobs.mark_imported(self.record.root, job_id)
            except (TacmuxError, OSError) as exc:
                warnings.append(
                    f"job {job_id} could not be marked imported ({exc}); "
                    "its records are already committed and should not be re-imported"
                )
        if create_sessions:
            failed_sessions: list[str] = []
            for target in targets:
                try:
                    self.app.tmux.start_target(
                        self.record.root, self.engagement, target
                    )
                except (TacmuxError, OSError) as exc:
                    failed_sessions.append(f"{target.display_name}: {exc}")
            if failed_sessions:
                warnings.append(
                    "sessions not started for " + "; ".join(failed_sessions)
                )
        self.after_mutation("targets", "scope", "situation")
        self.action_tab("targets")
        count = len(targets)
        message = f"Accepted {count} discovery {'result' if count == 1 else 'results'}"
        if warnings:
            self.app.notify(message + "; " + "; ".join(warnings), severity="warning")
        else:
            self.app.notify(message)

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
            self.action_export()
            return
        path, editable, _ = selected
        actions = [
            ("export", "Create engagement handoff"),
            ("view", "View full file in pager"),
        ]
        if editable:
            actions.append(("edit", "Edit with $VISUAL or $EDITOR"))
        self.app.push_screen(
            ActionMenu(path.name, actions), self._document_action
        )

    def _document_action(self, action: str | None) -> None:
        if action == "export":
            self.action_export()
        elif action == "edit":
            self.edit_selected_document()
        elif action == "view":
            selected = self.query_one(DocumentsPane).selected_document()
            if selected is not None:
                path, _, kind = selected
                self.app.page_file(path, terminal_output=kind == "evidence")

    def action_export(self) -> None:
        self.app.push_screen(ExportForm(), self._choose_export_profile)

    def _choose_export_profile(self, value: str | None) -> None:
        if not value:
            return
        try:
            profile = parse_export_profile(value)
        except TacmuxError as exc:
            self.app.show_error(str(exc))
            return
        if profile == ExportProfile.EVIDENCE:
            self.app.push_screen(
                ConfirmModal(
                    "Export Text Evidence",
                    "This profile embeds readable logs and evidence and may contain "
                    "credentials, tokens, or other sensitive client data. Continue?",
                ),
                lambda confirmed: self._create_handoff(profile) if confirmed else None,
            )
        else:
            self._create_handoff(profile)

    def _create_handoff(self, profile: ExportProfile) -> None:
        try:
            current = EngagementRecord(
                self.record.root, self.app.workspace.load(self.record.root)
            )
            path = create_handoff(
                current,
                profile=profile,
                live_target_ids=self.app.tmux.live_target_ids(current.engagement),
                jobs=self.app.jobs.list(current.root),
                include_mermaid=self.app.settings.include_mermaid,
            )
            self.query_one(DocumentsPane).populate(current)
            self.app.push_screen(MessageModal("Engagement Handoff Created", str(path)))
        except (TacmuxError, OSError, ValueError) as exc:
            self.app.show_error(str(exc))

    def action_archive_engagement(self) -> None:
        try:
            archive = self.app.archive_engagement(self.engagement.id)
            self.app.push_screen(
                MessageModal("Engagement Archive Verified", str(archive))
            )
        except (TacmuxError, OSError) as exc:
            self.app.show_error(str(exc))

    def action_restore(self) -> None:
        self.restore_options = _cockpit_archives(
            self.app.settings, self.engagement.id
        )
        if not self.restore_options:
            self._prompt_restore_path()
            return
        self.app.push_screen(
            ActionMenu(
                "Restore Verified Archive",
                [
                    (str(index), str(path))
                    for index, path in enumerate(self.restore_options)
                ]
                + [("path", "Enter a path…")],
            ),
            self._restore_choice,
        )

    def _restore_choice(self, value: str | None) -> None:
        if value == "path":
            self._prompt_restore_path()
        elif value is not None:
            try:
                path = self.restore_options[int(value)]
            except (IndexError, ValueError):
                self.app.show_error("The selected archive is no longer available")
            else:
                self._restore(str(path))

    def _prompt_restore_path(self) -> None:
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
    BINDINGS: ClassVar[list[Binding]] = [
        Binding("t", "change_theme", "Theme", show=False)
    ]
    CSS = """
    Screen { background: $background; }
    #picker-body { padding: 1 2; }
    #picker-title, #engagement-banner { height: 3; padding: 1 2; text-style: bold; color: $accent; }
    #picker-hint { height: 2; color: $text-muted; }
    #engagement-filter, #target-filter { display: none; margin: 0 2; }
    #target-layout, #documents-layout { height: 1fr; }
    #target-table { width: 62%; }
    #target-detail { width: 38%; padding: 1 2; border-left: solid $panel; overflow-y: auto; }
    ScopeDiscoveryPane { height: 1fr; }
    #scope-table { height: 44%; }
    #jobs-table { height: 36%; }
    #records-table { height: 1fr; }
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

    def notify(self, message: str, *args, **kwargs) -> None:
        kwargs.setdefault("markup", False)
        super().notify(str(message), *args, **kwargs)

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
        self.bootstrap()

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

    def require_idle_engagement(
        self, engagement_id: str, action: str
    ) -> EngagementRecord:
        record = self.workspace.find(engagement_id)
        engagement = record.engagement
        blockers: list[str] = []
        target_sessions = self.tmux.live_target_ids(engagement)
        if target_sessions:
            blockers.append(f"{len(target_sessions)} target session(s)")

        tmux_available = self.tmux.available()
        if tmux_available and self.tmux.has_session(
            self.tmux.session_name(engagement)
        ):
            blockers.append("operations session")

        jobs = self.jobs.list(record.root)
        active_job_ids = {
            str(job["id"])
            for job in jobs
            if job.get("state") in {"queued", "running"}
        }
        if tmux_available:
            active_job_ids.update(
                str(job["id"])
                for job in jobs
                if self.tmux.has_session(
                    self.tmux.job_session_name(engagement, str(job["id"]))
                )
            )
        if active_job_ids:
            blockers.append(f"{len(active_job_ids)} discovery job(s)")

        if blockers:
            raise ConflictError(
                f"Stop or cancel active work before {action}: " + ", ".join(blockers)
            )
        return record

    def render_runtime_documents(
        self,
        record: EngagementRecord,
        *,
        live_target_ids: set[str] | None = None,
    ) -> int:
        live = (
            self.tmux.live_target_ids(record.engagement)
            if live_target_ids is None
            else live_target_ids
        )
        jobs = self.jobs.list(record.root)
        return self.workspace.render_documents(
            record.root,
            record.engagement,
            live_target_ids=live,
            jobs=jobs,
        )

    def archive_engagement(self, engagement_id: str) -> Path:
        record = self.require_idle_engagement(
            engagement_id, "archiving the engagement"
        )
        self.render_runtime_documents(record, live_target_ids=set())
        archive, _ = create_archive(
            record.root,
            self.settings.archive_dir,
            kind="engagements",
            engagement_id=record.engagement.id,
            object_id=record.engagement.id,
        )
        return archive

    def show_error(self, message: str) -> None:
        self.notify(sentence(message), title="TACMUX", severity="error", timeout=8)

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
