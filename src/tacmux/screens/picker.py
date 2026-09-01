"""Engagement picker screen."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import ClassVar

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Input, Label, Static
from textual.widgets.data_table import RowDoesNotExist

from ..archive import engagement_archives, restore_engagement_archive, verify_archive
from ..dialogs import (
    ActionMenu,
    ConfirmModal,
    EngagementDetailsForm,
    EngagementForm,
    MessageModal,
    PromptModal,
)
from ..errors import TacmuxError, ValidationError
from ..model import (
    EngagementStatus,
    ScopeAvailability,
    ScopeGroup,
    ScopeKind,
    classify_scope,
    pattern_inside,
)
from ..ui import plain


class EngagementPickerScreen(Screen):
    BINDINGS: ClassVar[list[Binding]] = [
        Binding("enter", "open_selected", "Open"),
        Binding("a", "actions", "Actions"),
        Binding("n", "new_engagement", "New"),
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
            "Restore verified engagement archive",
            "restore",
            "Restore a deleted or missing engagement from a v2 archive",
        ),
    ]

    def __init__(self):
        super().__init__()
        self.restore_options: list[Path] = []
        self.invalid_rows: dict[str, tuple[Path, str]] = {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="picker-body"):
            yield Label("  ENGAGEMENTS", id="picker-title")
            yield Static(
                "Select an authorized workspace or create the next operation.",
                id="picker-copy",
            )
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
        self.app.title = " TACMUX"
        self.app.sub_title = ""
        self.call_after_refresh(self._finish_mount)

    def _finish_mount(self) -> None:
        if self.app.screen is not self:
            return
        self.refresh_table()
        self.query_one("#engagements", DataTable).focus()

    def refresh_table(self, query: str = "") -> None:
        table = self.query_one("#engagements", DataTable)
        selected = None
        previous_row = table.cursor_coordinate.row
        if table.row_count:
            row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
            selected = str(row_key.value)
        if not table.columns:
            table.add_columns(
                "Client / Lab / Platform", "Engagement", "Type", "Status", "Targets", "Live"
            )
        table.clear()
        query = query.casefold()
        records, problems = self.app.workspace.catalog_engagements()
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
                plain(engagement.client),
                plain(engagement.name),
                plain(engagement.assessment_type.value.replace("_", " ")),
                plain(
                    " closed"
                    if engagement.status == EngagementStatus.CLOSED
                    else " active"
                ),
                plain(len(engagement.targets)),
                plain(len(live.get(engagement.id, set()))),
                key=engagement.id,
            )
        self.invalid_rows.clear()
        for index, (manifest, problem) in enumerate(problems):
            root = manifest.parent.parent
            haystack = f"{root.name} {manifest} {problem}".casefold()
            if query and query not in haystack:
                continue
            key = f"invalid:{index}"
            self.invalid_rows[key] = (manifest, problem)
            table.add_row(
                plain(root.name),
                plain("Manifest could not be loaded"),
                plain("—"),
                plain("INVALID"),
                plain("—"),
                plain("—"),
                key=key,
            )
        if table.row_count:
            try:
                table.move_cursor(row=table.get_row_index(selected))
            except (RowDoesNotExist, TypeError):
                table.move_cursor(row=min(previous_row, table.row_count - 1))
        self.query_one("#picker-hint", Static).update(
            plain(
                f"{self.app.settings.workspace} · {len(records)} "
                f"{'engagement' if len(records) == 1 else 'engagements'}"
                + (f" · {len(problems)} invalid" if problems else "")
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
            engagement_id = self.selected_id()
            if self._show_invalid(engagement_id):
                return
            self.app.open_engagement(self.app.workspace.find(engagement_id))
        except TacmuxError as exc:
            self.app.show_error(str(exc))

    def action_actions(self) -> None:
        try:
            engagement_id = self.selected_id()
            if self._show_invalid(engagement_id):
                return
            record = self.app.workspace.find(engagement_id)
        except TacmuxError as exc:
            self.app.show_error(str(exc))
            return
        actions = [("open", "Open engagement")]
        if record.engagement.status == EngagementStatus.CLOSED:
            actions.append(("reopen", "Reopen engagement"))
        else:
            actions.extend(
                [
                    ("edit", "Edit engagement details"),
                    ("close", "Close engagement"),
                ]
            )
        actions.extend(
            [
                ("archive", "Create verified archive"),
                ("delete", "Delete engagement…"),
            ]
        )
        self.app.push_screen(
            ActionMenu(
                f"{record.engagement.client} / {record.engagement.name}",
                actions,
            ),
            lambda action: self._engagement_action(record.engagement.id, action),
        )

    def _show_invalid(self, row_key: str) -> bool:
        problem = self.invalid_rows.get(row_key)
        if problem is None:
            return False
        manifest, message = problem
        self.app.push_screen(
            MessageModal(
                "Invalid Engagement Workspace",
                f"{manifest}\n\n{message}\n\nRun `tacmux health` for the full workspace check. "
                "TACMUX will not open, archive, or delete an engagement it cannot validate.",
            )
        )
        return True

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
        message = (
            "Close this engagement? Operational changes will be blocked until "
            "it is reopened."
        )
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
                        f"exclusion {exclusion} must be inside exactly one "
                        "front-loaded scope entry"
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

    def action_restore(self) -> None:
        self.restore_options = engagement_archives(self.app.settings.archive_dir)
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
