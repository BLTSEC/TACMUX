"""Reusable Textual modals for operator decisions and data entry."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
import re
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

from .discovery import Reconciliation, ScanPace, ScanProfile
from .errors import ValidationError
from .export import ExportProfile
from .model import (
    AccessRecord,
    AccessLevel,
    Activity,
    ActivityResult,
    AssessmentType,
    AttackPath,
    Authorization,
    CleanupItem,
    CleanupKind,
    Engagement,
    Finding,
    FindingState,
    ScopeAvailability,
    ScopeEntry,
    ScopeGroup,
    ScopeKind,
    Severity,
    Target,
    parse_utc,
)
from .ui import plain


class BaseModal(ModalScreen[Any]):
    BINDINGS: ClassVar[list[tuple[str, str, str]]] = [("escape", "cancel", "Cancel")]

    def action_cancel(self) -> None:
        self.dismiss(None)

    def error(self, message: str) -> None:
        self.query_one(".error", Static).update(plain(message))


class MessageModal(BaseModal):
    def __init__(self, title: str, message: str):
        super().__init__()
        self.modal_title = title
        self.message = message

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Label(plain(self.modal_title), classes="title")
            yield Static(plain(self.message))
            yield Static("", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("Close", id="close", variant="primary")

    @on(Button.Pressed)
    def close(self) -> None:
        self.dismiss(True)


class ExportForm(BaseModal):
    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Create Engagement Handoff", classes="title")
            yield Static(
                "Both profiles create one readable, standalone engagement record. "
                "Full context also embeds prioritized text evidence; every source "
                "file remains indexed with its SHA-256."
            )
            yield Label("Export Profile", classes="field-label")
            yield Select(
                [
                    (
                        "Handoff — readable records, notes, and evidence index",
                        ExportProfile.HANDOFF.value,
                    ),
                    (
                        "Full context — also include prioritized text evidence",
                        ExportProfile.FULL.value,
                    ),
                ],
                value=ExportProfile.HANDOFF.value,
                allow_blank=False,
                id="profile",
            )
            yield Static(
                "The generated Markdown may contain sensitive client data. Full "
                "context is limited to 1 MiB of excerpts and normalizes the local "
                "engagement path, but it does not redact secrets or identities."
            )
            yield Static("", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Export", id="export", variant="primary")

    @on(Button.Pressed)
    def pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        self.dismiss(str(self.query_one("#profile", Select).value))


class PromptModal(BaseModal):
    def __init__(self, title: str, label: str, initial: str = ""):
        super().__init__()
        self.modal_title = title
        self.label = label
        self.initial = initial

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(plain(self.modal_title), classes="title")
            yield Label(plain(self.label), classes="field-label")
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
            yield Label(plain(self.modal_title), classes="title")
            yield Static(plain(self.message))
            if self.required_text:
                yield Label(
                    plain(f"Type exactly: {self.required_text}"), classes="field-label"
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
        self._confirm()

    @on(Input.Submitted, "#confirmation")
    def submitted(self) -> None:
        self._confirm()

    def _confirm(self) -> None:
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
            yield Label(plain(self.modal_title), classes="title")
            yield OptionList(
                *(
                    Option(plain(label), id=identifier)
                    for identifier, label in self.actions
                ),
                id="actions",
            )
            yield Static("Esc cancels", classes="menu-hint")
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
            yield Label("Authorization (optional)", classes="field-label")
            yield Input(
                placeholder="Authorizing party",
                id="authorized-by",
            )
            yield Input(
                placeholder="SOW, ticket, or contract reference",
                id="reference",
            )
            yield Label("Testing window (UTC, optional)", classes="field-label")
            yield Input(
                placeholder="Start: 2026-09-01 13:00",
                id="window-start",
            )
            yield Input(
                placeholder="End: 2026-09-05 23:00",
                id="window-end",
            )
            yield Input(
                placeholder="Emergency contact",
                id="emergency-contact",
            )
            yield Label(
                "Known external scope (optional, one IP/CIDR or domain per line)",
                classes="field-label",
            )
            yield TextArea(
                placeholder=(
                    "198.51.100.25/32\n"
                    "External DMZ = 198.51.100.0/24\n"
                    "Web apps = *.acme.test"
                ),
                id="external",
            )
            yield Static("Optional format: Label = IP/CIDR/domain")
            yield Label(
                "Known internal scope (optional, one IP/CIDR or domain per line)",
                classes="field-label",
            )
            yield TextArea(
                placeholder="10.20.0.0/24\nDomain Controller = 10.20.0.10/32",
                id="internal",
            )
            yield Static("Optional format: Label = IP/CIDR/domain")
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
            yield Label(
                "Known exclusions (optional, one IP/CIDR or domain per line)",
                classes="field-label",
            )
            yield TextArea(
                placeholder="10.20.0.250/32\nadmin.acme.test",
                id="exclusions",
            )
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
            self.error("Client/Lab and Engagement Name are required")
            return
        try:
            authorization = _authorization_from_form(self)
        except ValidationError as exc:
            self.error(str(exc))
            return
        self.dismiss(
            {
                "client": client,
                "name": name,
                "assessment_type": AssessmentType(
                    str(self.query_one("#assessment", Select).value)
                ),
                "logging_enabled": self.query_one("#logging", Checkbox).value,
                "authorization": authorization,
                "external": self.query_one("#external", TextArea).text,
                "internal": self.query_one("#internal", TextArea).text,
                "internal_availability": ScopeAvailability(
                    str(self.query_one("#internal-availability", Select).value)
                ),
                "exclusions": self.query_one("#exclusions", TextArea).text,
            }
        )


def _window_input(value: str) -> str:
    return parse_utc(value).strftime("%Y-%m-%d %H:%M") if value else ""


def _window_value(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", value):
        raise ValidationError("Use YYYY-MM-DD HH:MM in UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%d %H:%M").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ValidationError("Use a valid UTC date and time") from exc
    return parsed.isoformat(timespec="seconds").replace("+00:00", "Z")


def _authorization_from_form(form: BaseModal) -> Authorization:
    authorization = Authorization(
        authorized_by=form.query_one("#authorized-by", Input).value.strip(),
        reference=form.query_one("#reference", Input).value.strip(),
        window_start=_window_value(form.query_one("#window-start", Input).value),
        window_end=_window_value(form.query_one("#window-end", Input).value),
        emergency_contact=form.query_one("#emergency-contact", Input).value.strip(),
    )
    if authorization.window_start and authorization.window_end:
        if parse_utc(authorization.window_start) > parse_utc(
            authorization.window_end
        ):
            raise ValidationError(
                "Authorization window start must not be after its end"
            )
    return authorization


class EngagementDetailsForm(BaseModal):
    def __init__(self, engagement: Engagement):
        super().__init__()
        self.engagement = engagement

    def compose(self) -> ComposeResult:
        auth = self.engagement.authorization
        with VerticalScroll():
            yield Label("Edit Engagement Details", classes="title")
            yield Label("Client, lab, or platform", classes="field-label")
            yield Input(value=self.engagement.client, id="client")
            yield Label("Engagement name", classes="field-label")
            yield Input(value=self.engagement.name, id="name")
            yield Label("Assessment type", classes="field-label")
            yield Select(
                [(item.value.replace("_", " ").title(), item.value) for item in AssessmentType],
                value=self.engagement.assessment_type.value,
                allow_blank=False,
                id="assessment",
            )
            yield Checkbox(
                "Automatically log TACMUX panes",
                value=self.engagement.logging_enabled,
                id="logging",
            )
            yield Label("Authorization", classes="field-label")
            yield Input(
                value=auth.authorized_by,
                placeholder="Authorizing party",
                id="authorized-by",
            )
            yield Input(
                value=auth.reference,
                placeholder="SOW, ticket, or contract reference",
                id="reference",
            )
            yield Label("Window start (UTC)", classes="field-label")
            yield Input(
                value=_window_input(auth.window_start),
                placeholder="2026-09-01 13:00",
                id="window-start",
            )
            yield Label("Window end (UTC)", classes="field-label")
            yield Input(
                value=_window_input(auth.window_end),
                placeholder="2026-09-05 23:00",
                id="window-end",
            )
            yield Input(
                value=auth.emergency_contact,
                placeholder="Emergency contact",
                id="emergency-contact",
            )
            yield Static("", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Save", id="save", variant="primary")

    @on(Button.Pressed)
    def pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        client = self.query_one("#client", Input).value.strip()
        name = self.query_one("#name", Input).value.strip()
        if not client or not name:
            self.error("Client/Lab and Engagement Name are required")
            return
        try:
            authorization = _authorization_from_form(self)
        except ValidationError as exc:
            self.error(str(exc))
            return
        self.dismiss(
            {
                "client": client,
                "name": name,
                "assessment_type": AssessmentType(
                    str(self.query_one("#assessment", Select).value)
                ),
                "logging_enabled": self.query_one("#logging", Checkbox).value,
                "authorization": authorization,
            }
        )


class CleanupForm(BaseModal):
    def __init__(
        self,
        engagement: Engagement,
        target: Target | None = None,
        item: CleanupItem | None = None,
    ):
        super().__init__()
        self.engagement = engagement
        self.target = target
        self.item = item

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(
                "Edit Cleanup Item" if self.item else "Record Cleanup Item",
                classes="title",
            )
            yield Label("Target", classes="field-label")
            yield Select(
                [(plain(target.display_name), target.id) for target in self.engagement.targets],
                value=(
                    self.item.target_id
                    if self.item
                    else self.target.id
                    if self.target
                    else Select.NULL
                ),
                allow_blank=self.target is None and self.item is None,
                id="target",
            )
            yield Label("Kind", classes="field-label")
            yield Select(
                [(kind.value.replace("_", " ").title(), kind.value) for kind in CleanupKind],
                value=self.item.kind.value if self.item else CleanupKind.FILE.value,
                allow_blank=False,
                id="kind",
            )
            yield Label("Location or identifier", classes="field-label")
            yield Input(
                value=self.item.location if self.item else "",
                placeholder="/tmp/agent or svc_backup",
                id="location",
            )
            yield Label("SHA-256 (optional)", classes="field-label")
            yield Input(value=self.item.sha256 if self.item else "", id="sha256")
            yield Label("Note (optional)", classes="field-label")
            yield Input(value=self.item.note if self.item else "", id="note")
            yield Static("", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Save" if self.item else "Record", id="save", variant="primary")

    @on(Button.Pressed)
    def pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        target_select = self.query_one("#target", Select)
        target = target_select.value
        location = self.query_one("#location", Input).value.strip()
        sha256 = self.query_one("#sha256", Input).value.strip()
        if target_select.is_blank() or not location:
            self.error("Target and location are required")
            return
        if sha256 and not re.fullmatch(r"[0-9a-fA-F]{64}", sha256):
            self.error("SHA-256 must be 64 hexadecimal characters")
            return
        self.dismiss(
            {
                "target_id": str(target),
                "kind": CleanupKind(str(self.query_one("#kind", Select).value)),
                "location": location,
                "sha256": sha256,
                "note": self.query_one("#note", Input).value.strip(),
                **({"removed_at": self.item.removed_at} if self.item else {}),
            }
        )


class ServicesModal(BaseModal):
    def __init__(self, target: Target):
        super().__init__()
        self.target = target

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(
                plain(f"Observed Services — {self.target.display_name}"),
                classes="title",
            )
            yield DataTable(id="services", cursor_type="row", zebra_stripes=True)
            yield Static("", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("Close", id="close")
                if self.target.services:
                    yield Button("Clear services", id="clear", variant="error")

    def on_mount(self) -> None:
        table = self.query_one("#services", DataTable)
        table.add_columns(
            "Port", "Proto", "State", "Service", "Product / version", "Observed", "Source"
        )
        for item in self.target.services:
            table.add_row(
                plain(item.port), plain(item.protocol), plain(item.state), plain(item.name or "—"),
                plain(
                    " ".join(
                        value
                        for value in (item.product, item.version, item.extra)
                        if value
                    )
                    or "—"
                ),
                plain(item.observed_at[:16]), plain(item.source or "—"),
            )

    @on(Button.Pressed)
    def pressed(self, event: Button.Pressed) -> None:
        self.dismiss("clear" if event.button.id == "clear" else None)


class ScopeForm(BaseModal):
    def __init__(self, engagement: Engagement, scope: ScopeEntry | None = None):
        super().__init__()
        self.engagement = engagement
        self.scope = scope

    def compose(self) -> ComposeResult:
        target_options = [
            (plain(item.display_name), item.id) for item in self.engagement.targets
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
            yield Label("IP, CIDR, or domain", classes="field-label")
            yield Input(
                value=self.scope.spec if self.scope else "",
                placeholder="198.51.100.10/32 · 10.20.0.0/24 · *.acme.test",
                id="network",
            )
            yield Label(
                "Exclusions (optional, one per line, inside this entry)",
                classes="field-label",
            )
            yield TextArea(
                "\n".join(self.scope.exclusions) if self.scope else "",
                id="exclusions",
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
            self.error("IP, CIDR, or domain is required")
            return
        via_select = self.query_one("#via", Select)
        via_value = via_select.value
        self.dismiss(
            {
                "label": self.query_one("#label", Input).value.strip() or network,
                "network": network,
                "exclusions": [
                    item.strip()
                    for item in self.query_one("#exclusions", TextArea).text.splitlines()
                    if item.strip()
                ],
                "group": ScopeGroup(str(self.query_one("#group", Select).value)),
                "availability": ScopeAvailability(
                    str(self.query_one("#availability", Select).value)
                ),
                "via_target_id": "" if via_select.is_blank() else str(via_value),
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
            yield Label(plain(f"Add Address — {self.target_name}"), classes="title")
            yield Label("IP address", classes="field-label")
            yield Input(placeholder="10.20.0.25", id="address")
            yield Label("Network / scope", classes="field-label")
            yield Select(
                [
                    (plain(f"{item.group.value}: {item.label} ({item.network})"), item.id)
                    for item in self.engagement.network_entries
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
        scope_select = self.query_one("#scope", Select)
        scope_value = scope_select.value
        if not address:
            self.error("IP address is required")
            return
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            self.error("Enter a valid IP address")
            return
        matches = [item for item in self.engagement.network_entries if item.contains(parsed)]
        if len(matches) == 1:
            scope_value = matches[0].id
        elif not matches:
            self.error("Address is not inside any declared scope entry")
            return
        elif scope_select.is_blank():
            self.error("Address matches more than one scope entry — choose one")
            return
        elif str(scope_value) not in {item.id for item in matches}:
            self.error("Selected scope does not contain this address")
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
                    (plain(f"{item.group.value}: {item.label} ({item.network})"), item.id)
                    for item in self.engagement.network_entries
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
        scope_select = self.query_one("#scope", Select)
        scope_value = scope_select.value
        if not name:
            self.error("Display Name is required")
            return
        if address:
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError:
                self.error("Enter a valid IP address")
                return
            matches = [
                item for item in self.engagement.network_entries if item.contains(parsed)
            ]
            if len(matches) == 1:
                scope_value = matches[0].id
            elif not matches:
                self.error("Address is not inside any declared scope entry")
                return
            elif scope_select.is_blank():
                self.error("Address matches more than one scope entry — choose one")
                return
            elif str(scope_value) not in {item.id for item in matches}:
                self.error("Selected scope does not contain this address")
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
                "scope_id": str(scope_value) if address else "",
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
                plain(
                    f"{'Edit' if self.record else 'Record'} Confirmed Access — {self.target_name}"
                ),
                classes="title",
            )
            yield Static("Record who and how — never the credential itself")
            yield Label("Principal", classes="field-label")
            yield Input(
                value=self.record.principal if self.record else "",
                placeholder="web_operator",
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
        options = [(plain(item.display_name), item.id) for item in self.engagement.targets]
        with Vertical():
            yield Label(
                "Edit Activity" if self.activity else "Record Activity",
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
        target_select = self.query_one("#target", Select)
        target_value = target_select.value
        self.dismiss(
            {
                "summary": summary,
                "result": ActivityResult(str(self.query_one("#result", Select).value)),
                "target_id": "" if target_select.is_blank() else str(target_value),
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
                plain(item.display_name),
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
                else FindingState.DRAFT.value,
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
        self.note_identifier = ""

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
                    f"Access {record.id}: {record.principal} → "
                    f"{target.display_name} ({record.level.value})",
                )
            )
        for finding in self.engagement.findings:
            if finding.state in {FindingState.CONFIRMED, FindingState.CLOSED}:
                self.eligible.append(
                    (f"finding:{finding.id}", f"Finding {finding.id}: {finding.title}")
                )
        with VerticalScroll():
            yield Label(
                "Edit Attack Path" if self.path else "Build Confirmed Attack Path",
                classes="title",
            )
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
                *(Option(plain(label), id=identifier) for identifier, label in self.eligible),
                id="eligible-steps",
                classes="compact-list",
            )
            yield Label(
                "Path order (Delete removes; Ctrl+↑/↓ reorders)", classes="field-label"
            )
            yield DataTable(id="chosen-steps", cursor_type="row", zebra_stripes=True)
            yield Label(
                "Optional note for the highlighted step", classes="field-label"
            )
            yield Input(
                placeholder="Why this confirmed record advances the path",
                id="step-note",
            )
            yield Static("", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Save" if self.path else "Create", id="create", variant="primary")

    def on_mount(self) -> None:
        self.query_one("#chosen-steps", DataTable).add_columns("#", "Confirmed step")
        self.refresh_chosen(0 if self.chosen else None)

    @on(OptionList.OptionSelected, "#eligible-steps")
    def add_step(self, event: OptionList.OptionSelected) -> None:
        identifier = str(event.option.id)
        if identifier not in self.chosen:
            self._capture_note()
            self.chosen.append(identifier)
            self.step_notes[identifier] = ""
            self.refresh_chosen(len(self.chosen) - 1)

    def _capture_note(self) -> None:
        if self.note_identifier:
            self.step_notes[self.note_identifier] = self.query_one(
                "#step-note", Input
            ).value.strip()

    def _show_note(self, identifier: str) -> None:
        self.note_identifier = identifier
        self.query_one("#step-note", Input).value = self.step_notes.get(identifier, "")

    def refresh_chosen(self, cursor_row: int | None = None) -> None:
        labels = dict(self.eligible)
        table = self.query_one("#chosen-steps", DataTable)
        table.clear()
        for index, identifier in enumerate(self.chosen, 1):
            table.add_row(plain(index), plain(labels[identifier]), key=identifier)
        if self.chosen:
            selected_row = max(
                0,
                min(cursor_row if cursor_row is not None else 0, len(self.chosen) - 1),
            )
            table.move_cursor(row=selected_row)
            self._show_note(self.chosen[selected_row])
        else:
            self.note_identifier = ""
            self.query_one("#step-note", Input).value = ""

    @on(DataTable.RowHighlighted, "#chosen-steps")
    def chosen_step_highlighted(self, event: DataTable.RowHighlighted) -> None:
        identifier = str(event.row_key.value)
        if identifier == self.note_identifier:
            return
        self._capture_note()
        self._show_note(identifier)

    def _chosen_index(self) -> int | None:
        table = self.query_one("#chosen-steps", DataTable)
        return table.cursor_row if table.row_count else None

    def action_remove_step(self) -> None:
        index = self._chosen_index()
        if index is not None:
            self._capture_note()
            identifier = self.chosen.pop(index)
            self.step_notes.pop(identifier, None)
            if self.note_identifier == identifier:
                self.note_identifier = ""
            self.refresh_chosen(index)

    def _move_step(self, offset: int) -> None:
        index = self._chosen_index()
        if index is None:
            return
        destination = index + offset
        if 0 <= destination < len(self.chosen):
            self._capture_note()
            self.chosen[index], self.chosen[destination] = (
                self.chosen[destination],
                self.chosen[index],
            )
            self.refresh_chosen(destination)

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
        self._capture_note()
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
            and item.kind == ScopeKind.NETWORK
        ]
        selections = [
            (
                plain(f"{item.group.value}: {item.label} — {item.network}"),
                item.id,
                False,
            )
            for item in ready_scope
        ]
        with Vertical():
            yield Label("Run Detached Discovery", classes="title")
            yield Label("Scan profile", classes="field-label")
            yield Select(
                [
                    ("Host discovery only", ScanProfile.HOSTS.value),
                    ("Hosts + all TCP ports + service versions", ScanProfile.TCP_SERVICES.value),
                ],
                value=ScanProfile.HOSTS.value,
                allow_blank=False,
                id="profile",
            )
            yield Label("Enhanced scan pace", classes="field-label")
            yield Select(
                [
                    ("Careful — Nmap default timing", ScanPace.CAREFUL.value),
                    ("Fast — use -T4", ScanPace.FAST.value),
                ],
                value=ScanPace.CAREFUL.value,
                allow_blank=False,
                id="pace",
            )
            yield Static("", id="scan-profile")
            yield Static(
                "Only ready network scope can be scanned. Domain scope is import-only."
            )
            yield Label("Select declared, ready scope entries", classes="field-label")
            yield SelectionList(*selections, id="scope")
            if not ready_scope:
                yield Static(
                    "No scope entries are ready for scanning. Mark an entry ready first."
                )
            yield Static("", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Start", id="start", variant="primary")

    def on_mount(self) -> None:
        self._update_profile()

    @on(SelectionList.SelectedChanged, "#scope")
    def selected_scope_changed(self) -> None:
        self._update_profile()

    @on(Select.Changed)
    def scan_option_changed(self) -> None:
        self._update_profile()

    def _update_profile(self) -> None:
        selected = {
            str(item) for item in self.query_one("#scope", SelectionList).selected
        }
        exclusions = sorted(
            {
                exclusion
                for scope in self.engagement.network_entries
                if scope.id in selected
                for exclusion in scope.exclusions
            }
        )
        exclude = f" --exclude {','.join(exclusions)}" if exclusions else ""
        profile = str(self.query_one("#profile", Select).value)
        pace = str(self.query_one("#pace", Select).value)
        if profile == ScanProfile.TCP_SERVICES.value:
            timing = " -T4" if pace == ScanPace.FAST.value else ""
            description = (
                "Stages: nmap -sn --reason"
                f"{exclude} <scope> → nmap -Pn -p- --open --reason{timing} "
                "<live IPs> → nmap -Pn -sV --open -p <open ports>"
                f"{timing} <matching live IPs>"
            )
        else:
            description = (
                "Command profile: nmap -sn --reason"
                f"{exclude} -oX <job>/results.xml <selected scope>"
            )
        self.query_one("#scan-profile", Static).update(plain(description))

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
        self.dismiss(
            {
                "scope_ids": selected,
                "profile": str(self.query_one("#profile", Select).value),
                "pace": str(self.query_one("#pace", Select).value),
            }
        )


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
            yield Label(
                plain("Or paste one IP [hostname] or hostname per line"),
                classes="field-label",
            )
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
                        plain(f"{item.group.value}: {item.label} — {item.spec}"),
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
        accepted = sum(
            decision.action in {"add", "merge"} for decision in self.decisions
        )
        bulk = accepted > 10
        with Vertical():
            yield Label("Review Discovery Results", classes="title")
            yield Static(
                "Space cycles Add / Merge / Ignore. Press m to select an "
                "existing host for a second interface. "
                "No target changes occur until Commit."
            )
            yield Static("", id="review-tally")
            yield DataTable(id="review", cursor_type="row", zebra_stripes=True)
            yield Checkbox(
                "Create detached sessions for accepted targets",
                value=not bulk,
                id="sessions",
            )
            if bulk:
                yield Static(
                    plain(
                        f"{accepted} targets are currently accepted. Detached sessions "
                        "default off above 10; enable the checkbox deliberately if needed."
                    ),
                    classes="warning",
                )
            yield Static("", classes="error")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Commit", id="commit", variant="primary")

    def on_mount(self) -> None:
        table = self.query_one("#review", DataTable)
        columns = table.add_columns("Action", "Host", "Addresses", "Services", "Reason")
        self.action_column = columns[0]
        self.reason_column = columns[4]
        for index, decision in enumerate(self.decisions):
            table.add_row(
                plain(decision.action.upper()),
                plain(decision.candidate.display_name),
                plain(", ".join(item.value for item in decision.addresses) or "—"),
                plain(
                    str(len(decision.candidate.services))
                    if decision.candidate.services
                    else "—"
                ),
                plain(decision.note or decision.candidate.reason),
                key=str(index),
            )
        self._update_tally()

    def _update_tally(self) -> None:
        counts = {
            action: sum(item.action == action for item in self.decisions)
            for action in ("add", "merge", "ignore")
        }
        services = sum(len(item.candidate.services) for item in self.decisions)
        self.query_one("#review-tally", Static).update(
            plain(
                f"ADD {counts['add']} · MERGE {counts['merge']} · "
                f"IGNORE {counts['ignore']} · {services} services"
            )
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
        table.update_cell(row_key, self.action_column, plain(decision.action.upper()))
        self._update_tally()

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
        table.update_cell(row_key, self.action_column, plain("MERGE"))
        table.update_cell(row_key, self.reason_column, plain(decision.note))
        self._update_tally()

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
