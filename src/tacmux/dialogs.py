"""Reusable Textual modals for operator decisions and data entry."""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar, Iterable

from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Input,
    Label,
    OptionList,
    Select,
    SelectionList,
    Static,
    TextArea,
)
from textual.widgets.option_list import Option

from .discovery import Reconciliation
from .errors import ValidationError
from .model import (
    AccessRecord,
    AccessLevel,
    Activity,
    ActivityResult,
    AssessmentType,
    AttackPath,
    Engagement,
    Finding,
    FindingState,
    ScopeAvailability,
    ScopeEntry,
    ScopeGroup,
    Severity,
)


class BaseModal(ModalScreen[Any]):
    DEFAULT_CSS = """
    BaseModal { align: center middle; background: $background 70%; }
    BaseModal > Vertical, BaseModal > VerticalScroll {
        width: 86; max-width: 94%; height: auto; max-height: 92%;
        border: round $accent; background: $surface; padding: 1 2;
    }
    BaseModal .title { text-style: bold; color: $accent; margin-bottom: 1; }
    BaseModal .field-label { margin-top: 1; color: $text-muted; }
    BaseModal .buttons { height: auto; margin-top: 1; align-horizontal: right; }
    BaseModal Button { margin-left: 1; }
    BaseModal .error { color: $error; height: auto; margin-top: 1; }
    BaseModal TextArea { height: 8; border: tall $panel; }
    BaseModal SelectionList { height: 12; border: tall $panel; }
    BaseModal DataTable { height: 18; }
    BaseModal .compact-list { height: 10; border: tall $panel; }
    """
    BINDINGS: ClassVar[list[tuple[str, str, str]]] = [("escape", "cancel", "Cancel")]

    def action_cancel(self) -> None:
        self.dismiss(None)

    def error(self, message: str) -> None:
        self.query_one(".error", Static).update(message)


class MessageModal(BaseModal):
    def __init__(self, title: str, message: str):
        super().__init__()
        self.modal_title = title
        self.message = message

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(self.modal_title, classes="title")
            yield Static(self.message)
            yield Static("", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("Close", id="close", variant="primary")

    @on(Button.Pressed)
    def close(self) -> None:
        self.dismiss(True)


class PromptModal(BaseModal):
    def __init__(self, title: str, label: str, initial: str = ""):
        super().__init__()
        self.modal_title = title
        self.label = label
        self.initial = initial

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(self.modal_title, classes="title")
            yield Label(self.label, classes="field-label")
            yield Input(value=self.initial, id="value")
            yield Static("", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Save", id="save", variant="primary")

    @on(Input.Submitted)
    def submitted(self) -> None:
        self._save()

    @on(Button.Pressed)
    def pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
        else:
            self._save()

    def _save(self) -> None:
        value = self.query_one("#value", Input).value.strip()
        if not value:
            self.error(f"{self.label} is required")
            return
        self.dismiss(value)


class ConfirmModal(BaseModal):
    def __init__(self, title: str, message: str, required_text: str = ""):
        super().__init__()
        self.modal_title = title
        self.message = message
        self.required_text = required_text

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(self.modal_title, classes="title")
            yield Static(self.message)
            if self.required_text:
                yield Label(
                    f"Type exactly: {self.required_text}", classes="field-label"
                )
                yield Input(id="confirmation")
            yield Static("", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Confirm", id="confirm", variant="error")

    @on(Button.Pressed)
    def pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(False)
            return
        if self.required_text:
            value = self.query_one("#confirmation", Input).value
            if value != self.required_text:
                self.error("Confirmation text does not match")
                return
        self.dismiss(True)


class ActionMenu(BaseModal):
    def __init__(self, title: str, actions: Iterable[tuple[str, str]]):
        super().__init__()
        self.modal_title = title
        self.actions = list(actions)

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(self.modal_title, classes="title")
            yield OptionList(
                *(Option(label, id=identifier) for identifier, label in self.actions),
                id="actions",
            )
            yield Static("", classes="error")

    @on(OptionList.OptionSelected)
    def selected(self, event: OptionList.OptionSelected) -> None:
        self.dismiss(event.option.id)


class EngagementForm(BaseModal):
    def __init__(self, logging_default: bool = True):
        super().__init__()
        self.logging_default = logging_default

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Label("Create Engagement", classes="title")
            yield Label("Client, Lab, or Platform", classes="field-label")
            yield Input(placeholder="Who this work belongs to", id="client")
            yield Static(
                "Use a customer, organization, private lab, certification "
                "environment, or training platform."
            )
            yield Label("Engagement Name", classes="field-label")
            yield Input(
                placeholder="Assessment name, project code, or lab name", id="name"
            )
            yield Label("Assessment Type", classes="field-label")
            yield Select(
                [
                    ("External", AssessmentType.EXTERNAL.value),
                    ("Internal", AssessmentType.INTERNAL.value),
                    ("External + Internal", AssessmentType.BOTH.value),
                    ("Single-machine Lab", AssessmentType.SINGLE_MACHINE.value),
                ],
                value=AssessmentType.BOTH.value,
                allow_blank=False,
                id="assessment",
            )
            yield Checkbox(
                "Automatically log TACMUX panes",
                value=self.logging_default,
                id="logging",
            )
            yield Label(
                "External scope now (optional, one IP/CIDR per line)",
                classes="field-label",
            )
            yield TextArea(
                placeholder=(
                    "198.51.100.25/32\n"
                    "External DMZ = 198.51.100.0/24"
                ),
                id="external",
            )
            yield Static("Optional format: Label = IP/CIDR")
            yield Label(
                "Internal scope now (optional, one IP/CIDR per line)",
                classes="field-label",
            )
            yield TextArea(
                placeholder="10.20.0.0/24\nDomain Controller = 10.20.0.10/32",
                id="internal",
            )
            yield Static("Optional format: Label = IP/CIDR")
            yield Label("Internal scope reachability", classes="field-label")
            yield Select(
                [
                    ("Reachable now (direct, on-site, or VPN)", "ready"),
                    (
                        "Not reachable yet (requires access or pivot)",
                        "unavailable",
                    ),
                ],
                value="unavailable",
                allow_blank=False,
                id="internal-availability",
            )
            yield Static("Applies only to the internal scope entered above.")
            yield Static("", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Create", id="create", variant="primary")

    @on(Button.Pressed)
    def pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        client = self.query_one("#client", Input).value.strip()
        name = self.query_one("#name", Input).value.strip()
        if not client or not name:
            self.error("Enter who the work belongs to and an Engagement Name")
            return
        self.dismiss(
            {
                "client": client,
                "name": name,
                "assessment_type": AssessmentType(
                    str(self.query_one("#assessment", Select).value)
                ),
                "logging_enabled": self.query_one("#logging", Checkbox).value,
                "external": self.query_one("#external", TextArea).text,
                "internal": self.query_one("#internal", TextArea).text,
                "internal_availability": ScopeAvailability(
                    str(self.query_one("#internal-availability", Select).value)
                ),
            }
        )


class LegacyImportForm(BaseModal):
    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Copy v1 Workspace", classes="title")
            yield Label(
                "Existing engagement or flat workspace directory", classes="field-label"
            )
            yield Input(placeholder="~/legacy-engagement", id="source")
            yield Label("Client, Lab, or Platform", classes="field-label")
            yield Input(placeholder="Who this work belongs to", id="client")
            yield Label("New Engagement Name", classes="field-label")
            yield Input(
                placeholder="Assessment name, project code, or lab name", id="name"
            )
            yield Label("Assessment Type", classes="field-label")
            yield Select(
                [
                    (item.value.replace("_", " ").title(), item.value)
                    for item in AssessmentType
                ],
                value=AssessmentType.BOTH.value,
                allow_blank=False,
                id="assessment",
            )
            yield Static("", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Copy Import", id="import", variant="primary")

    @on(Button.Pressed)
    def pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        source = self.query_one("#source", Input).value.strip()
        client = self.query_one("#client", Input).value.strip()
        name = self.query_one("#name", Input).value.strip()
        if not source or not client or not name:
            self.error(
                "Source, who the work belongs to, and Engagement Name are required"
            )
            return
        self.dismiss(
            {
                "source": Path(source),
                "client": client,
                "name": name,
                "assessment_type": AssessmentType(
                    str(self.query_one("#assessment", Select).value)
                ),
            }
        )


class ScopeForm(BaseModal):
    def __init__(self, engagement: Engagement, scope: ScopeEntry | None = None):
        super().__init__()
        self.engagement = engagement
        self.scope = scope

    def compose(self) -> ComposeResult:
        target_options = [
            (item.display_name, item.id) for item in self.engagement.targets
        ]
        with Vertical():
            yield Label(
                "Edit Scope Entry" if self.scope else "Add Scope Entry",
                classes="title",
            )
            yield Label("Label", classes="field-label")
            yield Input(
                value=self.scope.label if self.scope else "",
                placeholder="External DMZ or Corp LAN",
                id="label",
            )
            yield Label("IP or CIDR", classes="field-label")
            yield Input(
                value=self.scope.network if self.scope else "",
                placeholder="198.51.100.10/32 or 10.20.0.0/24",
                id="network",
            )
            yield Label("Group", classes="field-label")
            yield Select(
                [("External", "external"), ("Internal", "internal")],
                value=self.scope.group.value if self.scope else "external",
                allow_blank=False,
                id="group",
            )
            yield Label("Availability", classes="field-label")
            yield Select(
                [
                    ("Reachable now", "ready"),
                    ("Not reachable yet", "unavailable"),
                ],
                value=self.scope.availability.value if self.scope else "ready",
                allow_blank=False,
                id="availability",
            )
            yield Label("Reachable via target (optional)", classes="field-label")
            yield Select(
                target_options,
                value=(
                    self.scope.via_target_id
                    if self.scope and self.scope.via_target_id
                    else Select.NULL
                ),
                prompt="No pivot target",
                allow_blank=True,
                id="via",
            )
            yield Static("", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button(
                    "Save" if self.scope else "Add", id="add", variant="primary"
                )

    @on(Button.Pressed)
    def pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        network = self.query_one("#network", Input).value.strip()
        if not network:
            self.error("IP or CIDR is required")
            return
        via_value = self.query_one("#via", Select).value
        self.dismiss(
            {
                "label": self.query_one("#label", Input).value.strip() or network,
                "network": network,
                "group": ScopeGroup(str(self.query_one("#group", Select).value)),
                "availability": ScopeAvailability(
                    str(self.query_one("#availability", Select).value)
                ),
                "via_target_id": "" if Select.is_blank(via_value) else str(via_value),
            }
        )


class TargetAddressForm(BaseModal):
    """Add one explicitly scope-qualified address to an existing target."""

    def __init__(self, engagement: Engagement, target_name: str):
        super().__init__()
        self.engagement = engagement
        self.target_name = target_name

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(f"Add Address — {self.target_name}", classes="title")
            yield Label("IP address", classes="field-label")
            yield Input(placeholder="10.20.0.25", id="address")
            yield Label("Network / scope", classes="field-label")
            yield Select(
                [
                    (f"{item.group.value}: {item.label} ({item.network})", item.id)
                    for item in self.engagement.scope
                ],
                prompt="Select scope",
                allow_blank=True,
                id="scope",
            )
            yield Checkbox("Make this the primary endpoint", value=False, id="primary")
            yield Static("", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Add", id="add", variant="primary")

    @on(Button.Pressed)
    def pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        address = self.query_one("#address", Input).value.strip()
        scope_value = self.query_one("#scope", Select).value
        if not address or Select.is_blank(scope_value):
            self.error("IP address and network / scope are required")
            return
        self.dismiss(
            {
                "address": address,
                "scope_id": str(scope_value),
                "primary": self.query_one("#primary", Checkbox).value,
            }
        )


class TargetForm(BaseModal):
    def __init__(self, engagement: Engagement):
        super().__init__()
        self.engagement = engagement

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Add Target", classes="title")
            yield Static(
                "An IP address or hostname is optional. Leave both blank to create "
                "an unresolved target workspace."
            )
            yield Label("Display Name", classes="field-label")
            yield Input(placeholder="mail01", id="name")
            yield Label("IP address (optional)", classes="field-label")
            yield Input(placeholder="198.51.100.25", id="address")
            yield Label("Scope entry for this address", classes="field-label")
            yield Select(
                [
                    (f"{item.group.value}: {item.label} ({item.network})", item.id)
                    for item in self.engagement.scope
                ],
                prompt="Select scope when entering an IP",
                allow_blank=True,
                id="scope",
            )
            yield Label("Hostnames (optional, comma-separated)", classes="field-label")
            yield Input(
                placeholder="mail01.acme.test, smtp.acme.test", id="hostnames"
            )
            yield Static("", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Add", id="add", variant="primary")

    @on(Button.Pressed)
    def pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        name = self.query_one("#name", Input).value.strip()
        address = self.query_one("#address", Input).value.strip()
        scope_value = self.query_one("#scope", Select).value
        if not name:
            self.error("Display Name is required")
            return
        if address and Select.is_blank(scope_value):
            self.error("Select a scope entry for the address")
            return
        hostnames = [
            item.strip()
            for item in self.query_one("#hostnames", Input).value.split(",")
            if item.strip()
        ]
        self.dismiss(
            {
                "display_name": name,
                "address": address,
                "scope_id": "" if Select.is_blank(scope_value) else str(scope_value),
                "hostnames": hostnames,
            }
        )


class AccessForm(BaseModal):
    def __init__(self, target_name: str, record: AccessRecord | None = None):
        super().__init__()
        self.target_name = target_name
        self.record = record

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(
                f"{'Edit' if self.record else 'Record'} Confirmed Access — {self.target_name}",
                classes="title",
            )
            yield Label("Principal", classes="field-label")
            yield Input(
                value=self.record.principal if self.record else "",
                placeholder="adminuser",
                id="principal",
            )
            yield Label("Authority / realm (optional)", classes="field-label")
            yield Input(
                value=self.record.authority if self.record else "",
                placeholder="ACME or local",
                id="authority",
            )
            yield Label("Method / protocol", classes="field-label")
            yield Input(
                value=self.record.method if self.record else "",
                placeholder="SSH, SMB, WinRM, web session",
                id="method",
            )
            yield Label("Access level", classes="field-label")
            yield Select(
                [
                    (item.value.replace("_", " ").title(), item.value)
                    for item in AccessLevel
                ],
                value=(
                    self.record.level.value
                    if self.record
                    else AccessLevel.AUTHENTICATED.value
                ),
                allow_blank=False,
                id="level",
            )
            yield Label("Relative evidence reference (optional)", classes="field-label")
            yield Input(
                value=self.record.evidence if self.record else "",
                placeholder="targets/T0001-mail/recon/ssh.txt",
                id="evidence",
            )
            yield Static("", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button(
                    "Save" if self.record else "Record", id="record", variant="primary"
                )

    @on(Button.Pressed)
    def pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        principal = self.query_one("#principal", Input).value.strip()
        if not principal:
            self.error("Principal is required")
            return
        self.dismiss(
            {
                "principal": principal,
                "authority": self.query_one("#authority", Input).value.strip(),
                "method": self.query_one("#method", Input).value.strip(),
                "level": AccessLevel(str(self.query_one("#level", Select).value)),
                "evidence": self.query_one("#evidence", Input).value.strip(),
            }
        )


class ActivityForm(BaseModal):
    def __init__(
        self,
        engagement: Engagement,
        default_target_id: str = "",
        activity: Activity | None = None,
    ):
        super().__init__()
        self.engagement = engagement
        self.default_target_id = default_target_id
        self.activity = activity

    def compose(self) -> ComposeResult:
        options = [(item.display_name, item.id) for item in self.engagement.targets]
        with Vertical():
            yield Label(
                "Edit Curated Activity" if self.activity else "Record Curated Activity",
                classes="title",
            )
            yield Label("Summary", classes="field-label")
            yield Input(
                value=self.activity.summary if self.activity else "",
                placeholder="Obtained user shell through confirmed initial access",
                id="summary",
            )
            yield Label("Result", classes="field-label")
            yield Select(
                [
                    ("Confirmed", "confirmed"),
                    ("Failed", "failed"),
                    ("No Result", "no_result"),
                ],
                value=self.activity.result.value if self.activity else "confirmed",
                allow_blank=False,
                id="result",
            )
            yield Label("Target (optional)", classes="field-label")
            yield Select(
                options,
                value=(
                    self.activity.target_id if self.activity else self.default_target_id
                )
                or Select.NULL,
                prompt="Engagement-level activity",
                allow_blank=True,
                id="target",
            )
            yield Label("Relative evidence reference (optional)", classes="field-label")
            yield Input(
                value=self.activity.evidence if self.activity else "",
                placeholder="targets/T0001-mail/recon/initial-access.txt",
                id="evidence",
            )
            yield Static("", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button(
                    "Save" if self.activity else "Record",
                    id="record",
                    variant="primary",
                )

    @on(Button.Pressed)
    def pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        summary = self.query_one("#summary", Input).value.strip()
        if not summary:
            self.error("Summary is required")
            return
        target_value = self.query_one("#target", Select).value
        self.dismiss(
            {
                "summary": summary,
                "result": ActivityResult(str(self.query_one("#result", Select).value)),
                "target_id": "" if Select.is_blank(target_value) else str(target_value),
                "evidence": self.query_one("#evidence", Input).value.strip(),
            }
        )


class FindingForm(BaseModal):
    def __init__(
        self,
        engagement: Engagement,
        default_target_id: str = "",
        finding: Finding | None = None,
    ):
        super().__init__()
        self.engagement = engagement
        self.default_target_id = default_target_id
        self.finding = finding

    def compose(self) -> ComposeResult:
        selections = [
            (
                item.display_name,
                item.id,
                item.id in self.finding.target_ids
                if self.finding
                else item.id == self.default_target_id,
            )
            for item in self.engagement.targets
        ]
        with Vertical():
            yield Label(
                "Edit Finding" if self.finding else "Create Finding", classes="title"
            )
            yield Label("Title", classes="field-label")
            yield Input(
                value=self.finding.title if self.finding else "",
                placeholder="Open SMB share exposes sensitive data",
                id="title",
            )
            yield Label("Severity", classes="field-label")
            yield Select(
                [(item.value.title(), item.value) for item in Severity],
                value=self.finding.severity.value
                if self.finding
                else Severity.MEDIUM.value,
                allow_blank=False,
                id="severity",
            )
            yield Label("State", classes="field-label")
            yield Select(
                [(item.value.title(), item.value) for item in FindingState],
                value=self.finding.state.value
                if self.finding
                else FindingState.CONFIRMED.value,
                allow_blank=False,
                id="state",
            )
            yield Label("Affected targets", classes="field-label")
            yield SelectionList(*selections, id="targets")
            yield Label(
                "Evidence references (optional, one per line)", classes="field-label"
            )
            yield TextArea(
                "\n".join(self.finding.evidence) if self.finding else "",
                placeholder=(
                    "targets/T0002-filesrv/recon/smb-share.txt\n"
                    "targets/T0002-filesrv/screenshots/share.png"
                ),
                id="evidence",
            )
            yield Static("", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button(
                    "Save" if self.finding else "Create and Edit",
                    id="create",
                    variant="primary",
                )

    @on(Button.Pressed)
    def pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        title = self.query_one("#title", Input).value.strip()
        targets = list(self.query_one("#targets", SelectionList).selected)
        if not title or not targets:
            self.error("Title and at least one affected target are required")
            return
        self.dismiss(
            {
                "title": title,
                "severity": Severity(str(self.query_one("#severity", Select).value)),
                "state": FindingState(str(self.query_one("#state", Select).value)),
                "target_ids": [str(item) for item in targets],
                "evidence": [
                    line.strip()
                    for line in self.query_one("#evidence", TextArea).text.splitlines()
                    if line.strip()
                ],
            }
        )


class AttackPathForm(BaseModal):
    BINDINGS: ClassVar[list[tuple[str, str, str]]] = [
        *BaseModal.BINDINGS,
        ("delete", "remove_step", "Remove Step"),
        ("ctrl+up", "move_up", "Move Up"),
        ("ctrl+down", "move_down", "Move Down"),
    ]

    def __init__(self, engagement: Engagement, path: AttackPath | None = None):
        super().__init__()
        self.engagement = engagement
        self.path = path
        self.eligible: list[tuple[str, str]] = []
        self.chosen: list[str] = (
            [f"{step.ref_type}:{step.ref_id}" for step in path.steps] if path else []
        )
        self.step_notes = (
            {f"{step.ref_type}:{step.ref_id}": step.narrative for step in path.steps}
            if path
            else {}
        )

    def compose(self) -> ComposeResult:
        for activity in self.engagement.activities:
            if activity.result == ActivityResult.CONFIRMED:
                self.eligible.append(
                    (
                        f"activity:{activity.id}",
                        f"Activity {activity.id}: {activity.summary}",
                    )
                )
        for record in self.engagement.access:
            target = self.engagement.target_by_id(record.target_id)
            self.eligible.append(
                (
                    f"access:{record.id}",
                    f"Access {record.id}: {record.principal} → {target.display_name} ({record.level.value})",
                )
            )
        for finding in self.engagement.findings:
            if finding.state in {FindingState.CONFIRMED, FindingState.CLOSED}:
                self.eligible.append(
                    (f"finding:{finding.id}", f"Finding {finding.id}: {finding.title}")
                )
        with VerticalScroll():
            yield Label("Build Confirmed Attack Path", classes="title")
            yield Label("Path Name", classes="field-label")
            yield Input(
                value=self.path.name if self.path else "",
                placeholder="External foothold to internal administrative access",
                id="name",
            )
            yield Label(
                "Available confirmed records (Enter adds)", classes="field-label"
            )
            yield OptionList(
                *(Option(label, id=identifier) for identifier, label in self.eligible),
                id="eligible-steps",
                classes="compact-list",
            )
            yield Label(
                "Path order (Delete removes; Ctrl+↑/↓ reorders)", classes="field-label"
            )
            yield DataTable(id="chosen-steps", cursor_type="row", zebra_stripes=True)
            yield Label(
                "Optional step notes (one line per chosen step)", classes="field-label"
            )
            yield TextArea(
                "\n".join(self.step_notes.get(item, "") for item in self.chosen),
                id="narratives",
            )
            yield Static("", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Create", id="create", variant="primary")

    def on_mount(self) -> None:
        self.query_one("#chosen-steps", DataTable).add_columns("#", "Confirmed step")
        self.refresh_chosen()

    @on(OptionList.OptionSelected, "#eligible-steps")
    def add_step(self, event: OptionList.OptionSelected) -> None:
        identifier = str(event.option.id)
        if identifier not in self.chosen:
            self._capture_notes()
            self.chosen.append(identifier)
            self.step_notes[identifier] = ""
            self.refresh_chosen(len(self.chosen) - 1)
            self._render_notes()

    def _capture_notes(self) -> None:
        notes = self.query_one("#narratives", TextArea).text.splitlines()
        for index, identifier in enumerate(self.chosen):
            self.step_notes[identifier] = (
                notes[index].strip() if index < len(notes) else ""
            )

    def _render_notes(self) -> None:
        self.query_one("#narratives", TextArea).text = "\n".join(
            self.step_notes.get(item, "") for item in self.chosen
        )

    def refresh_chosen(self, cursor_row: int | None = None) -> None:
        labels = dict(self.eligible)
        table = self.query_one("#chosen-steps", DataTable)
        table.clear()
        for index, identifier in enumerate(self.chosen, 1):
            table.add_row(str(index), labels[identifier], key=identifier)
        if cursor_row is not None and self.chosen:
            table.move_cursor(row=max(0, min(cursor_row, len(self.chosen) - 1)))

    def _chosen_index(self) -> int | None:
        table = self.query_one("#chosen-steps", DataTable)
        return table.cursor_row if table.row_count else None

    def action_remove_step(self) -> None:
        index = self._chosen_index()
        if index is not None:
            self._capture_notes()
            identifier = self.chosen.pop(index)
            self.step_notes.pop(identifier, None)
            self.refresh_chosen(index)
            self._render_notes()

    def _move_step(self, offset: int) -> None:
        index = self._chosen_index()
        if index is None:
            return
        destination = index + offset
        if 0 <= destination < len(self.chosen):
            self._capture_notes()
            self.chosen[index], self.chosen[destination] = (
                self.chosen[destination],
                self.chosen[index],
            )
            self.refresh_chosen(destination)
            self._render_notes()

    def action_move_up(self) -> None:
        self._move_step(-1)

    def action_move_down(self) -> None:
        self._move_step(1)

    @on(Button.Pressed)
    def pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        name = self.query_one("#name", Input).value.strip()
        if not name or not self.chosen:
            self.error("Path Name and at least one confirmed step are required")
            return
        self._capture_notes()
        steps = []
        for item in self.chosen:
            ref_type, ref_id = item.split(":", 1)
            steps.append((ref_type, ref_id, self.step_notes.get(item, "")))
        self.dismiss({"name": name, "steps": steps})


class ScanForm(BaseModal):
    def __init__(self, engagement: Engagement):
        super().__init__()
        self.engagement = engagement

    def compose(self) -> ComposeResult:
        ready_scope = [
            item
            for item in self.engagement.scope
            if item.availability == ScopeAvailability.READY
        ]
        selections = [
            (
                f"{item.group.value}: {item.label} — {item.network}",
                item.id,
                False,
            )
            for item in ready_scope
        ]
        with Vertical():
            yield Label("Run Detached Host Discovery", classes="title")
            yield Static("Command profile: nmap -sn --reason -oX <job>/results.xml")
            yield Label("Select declared, ready scope entries", classes="field-label")
            yield SelectionList(*selections, id="scope")
            if not ready_scope:
                yield Static(
                    "No scope entries are ready for scanning. Mark an entry ready first."
                )
            yield Static("", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Start Detached", id="start", variant="primary")

    @on(Button.Pressed)
    def pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        selected = [
            str(item) for item in self.query_one("#scope", SelectionList).selected
        ]
        if not selected:
            self.error("Select at least one scope entry")
            return
        self.dismiss(selected)


class ImportDiscoveryForm(BaseModal):
    def __init__(
        self,
        engagement: Engagement,
        xml_path: str = "",
        selected_scope_ids: list[str] | None = None,
    ):
        super().__init__()
        self.engagement = engagement
        self.xml_path = xml_path
        self.selected_scope_ids = set(selected_scope_ids or [])

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Label("Import Host Discovery", classes="title")
            yield Label(
                "Nmap XML path (leave blank when pasting hosts)", classes="field-label"
            )
            yield Input(
                value=self.xml_path,
                placeholder="~/scans/host-discovery.xml",
                id="xml",
            )
            yield Label("Or paste one `IP [hostname]` per line", classes="field-label")
            yield TextArea(
                placeholder=(
                    "198.51.100.25 web01.acme.test\n"
                    "10.20.0.15 filesrv.acme.test"
                ),
                id="paste",
            )
            yield Label(
                "Scope entries permitted for this import", classes="field-label"
            )
            yield SelectionList(
                *[
                    (
                        f"{item.group.value}: {item.label} — {item.network}",
                        item.id,
                        not self.selected_scope_ids
                        or item.id in self.selected_scope_ids,
                    )
                    for item in self.engagement.scope
                ],
                id="scope",
            )
            yield Static("", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Review", id="review", variant="primary")

    @on(Button.Pressed)
    def pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        xml_path = self.query_one("#xml", Input).value.strip()
        pasted = self.query_one("#paste", TextArea).text.strip()
        scopes = [
            str(item) for item in self.query_one("#scope", SelectionList).selected
        ]
        if (not xml_path and not pasted) or not scopes:
            self.error(
                "Provide XML or pasted hosts and select at least one scope entry"
            )
            return
        if xml_path and pasted:
            self.error("Choose either Nmap XML or pasted hosts, not both")
            return
        self.dismiss({"xml_path": xml_path, "pasted": pasted, "scope_ids": scopes})


class DiscoveryReview(BaseModal):
    BINDINGS: ClassVar[list[tuple[str, str, str]]] = [
        *BaseModal.BINDINGS,
        ("space", "cycle", "Add/Merge/Ignore"),
        ("m", "choose_merge", "Choose Merge Target"),
        ("ctrl+s", "commit", "Commit"),
    ]

    def __init__(
        self,
        decisions: list[Reconciliation],
        merge_targets: Iterable[tuple[str, str]] = (),
        allowed_scope_ids: Iterable[str] = (),
    ):
        super().__init__()
        self.decisions = decisions
        self.merge_targets = list(merge_targets)
        self.allowed_scope_ids = frozenset(allowed_scope_ids)

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Review Discovery Results", classes="title")
            yield Static(
                "Space cycles Add / Merge / Ignore. Press m to select an existing host for a second interface. "
                "No target changes occur until Commit."
            )
            yield DataTable(id="review", cursor_type="row", zebra_stripes=True)
            yield Checkbox(
                "Create detached sessions for accepted targets",
                value=True,
                id="sessions",
            )
            yield Static("", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Commit", id="commit", variant="primary")

    def on_mount(self) -> None:
        table = self.query_one("#review", DataTable)
        columns = table.add_columns("Action", "Host", "Addresses", "Reason")
        self.action_column = columns[0]
        self.reason_column = columns[3]
        for index, decision in enumerate(self.decisions):
            table.add_row(
                decision.action.upper(),
                decision.candidate.display_name,
                ", ".join(item.value for item in decision.addresses) or "—",
                decision.note or decision.candidate.reason,
                key=str(index),
            )

    def action_cycle(self) -> None:
        table = self.query_one("#review", DataTable)
        if table.row_count == 0:
            return
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        index = int(str(row_key.value))
        decision = self.decisions[index]
        allowed = [
            action
            for action in ("add", "merge", "ignore")
            if action in decision.allowed_actions
            and (action != "merge" or decision.merge_target_id)
        ]
        if len(allowed) == 1:
            self.error(decision.note or "This discovery result can only be ignored")
            return
        decision.action = (
            allowed[0]
            if decision.action not in allowed
            else allowed[(allowed.index(decision.action) + 1) % len(allowed)]
        )
        table.update_cell(row_key, self.action_column, decision.action.upper())

    def action_choose_merge(self) -> None:
        table = self.query_one("#review", DataTable)
        if table.row_count == 0 or not self.merge_targets:
            self.error("There are no existing targets available for merge")
            return
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        index = int(str(row_key.value))
        if "merge" not in self.decisions[index].allowed_actions:
            self.error(
                self.decisions[index].note
                or "This discovery result cannot be merged"
            )
            return
        self.app.push_screen(
            ActionMenu("Merge Discovered Host Into", self.merge_targets),
            lambda target_id: self._set_merge(index, target_id),
        )

    def _set_merge(self, index: int, target_id: str | None) -> None:
        if not target_id:
            return
        decision = self.decisions[index]
        decision.merge_target_id = target_id
        decision.action = "merge"
        target_name = dict(self.merge_targets)[target_id]
        decision.note = f"operator-selected merge into {target_name}"
        table = self.query_one("#review", DataTable)
        row_key = str(index)
        table.update_cell(row_key, self.action_column, "MERGE")
        table.update_cell(row_key, self.reason_column, decision.note)

    def action_commit(self) -> None:
        try:
            for decision in self.decisions:
                decision.validate_action()
        except ValidationError as exc:
            self.error(str(exc))
            return
        self.dismiss(
            (
                self.decisions,
                self.query_one("#sessions", Checkbox).value,
                set(self.allowed_scope_ids),
            )
        )

    @on(Button.Pressed)
    def pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
        else:
            self.action_commit()
