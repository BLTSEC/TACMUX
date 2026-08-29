from __future__ import annotations

from dataclasses import replace

import pytest

from tacmux.app import EngagementPickerScreen, MainScreen, TacmuxApp
from textual.widgets import Checkbox, OptionList

from tacmux.dialogs import ActionMenu, AttackPathForm, EngagementForm
from tacmux.model import (
    AccessLevel,
    AccessRecord,
    Activity,
    ActivityResult,
    ScopeAvailability,
    ScopeGroup,
    TargetAddress,
)


@pytest.mark.asyncio
async def test_picker_is_usable_at_minimum_terminal_size(settings, workspace, record):
    app = TacmuxApp(settings)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        assert isinstance(app.screen, EngagementPickerScreen)
        assert app.screen.query_one("#engagements").row_count == 1


@pytest.mark.asyncio
async def test_main_cockpit_is_responsive_and_lists_evidence(
    settings, workspace, record
):
    scope = record.engagement.add_scope(
        "Internal LAN",
        ScopeGroup.INTERNAL,
        "10.77.10.0/24",
        ScopeAvailability.UNAVAILABLE,
    )
    target = workspace.create_target(
        record.root,
        record.engagement,
        "mail01",
        addresses=[TargetAddress("10.77.10.5", scope.id)],
        primary_endpoint="10.77.10.5",
    )
    evidence = record.root / "targets" / target.directory / "recon/scan.txt"
    evidence.write_text("\x1b[32mhost is up\x1b[0m\n")
    workspace.save(record.root, record.engagement)
    workspace.set_last_engagement(record.engagement.id)
    app = TacmuxApp(replace(settings, startup="resume_last"))
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        assert isinstance(app.screen, MainScreen)
        assert app.screen.has_class("narrow")
        assert app.screen.query_one("#target-table").row_count == 1
        assert app.screen.query_one("#scope-table").row_count == 1
        assert any(
            path == evidence for path, _, _ in app.screen.document_paths.values()
        )
        await pilot.press("2")
        await pilot.pause()
        assert app.focused is not None
        assert app.focused.id == "scope-table"
        await pilot.press("1")
        await pilot.pause()
        assert app.focused is not None
        assert app.focused.id == "target-table"
        await pilot.press("d")
        await pilot.pause()
        assert isinstance(app.screen, ActionMenu)
        await pilot.press("escape")
        await pilot.pause()
        assert isinstance(app.screen, MainScreen)


@pytest.mark.asyncio
async def test_attack_path_form_keeps_operator_selected_order(
    settings, workspace, record
):
    scope = record.engagement.add_scope("LAN", ScopeGroup.INTERNAL, "10.0.0.0/24")
    target = workspace.create_target(
        record.root,
        record.engagement,
        "host",
        addresses=[TargetAddress("10.0.0.5", scope.id)],
        primary_endpoint="10.0.0.5",
    )
    record.engagement.activities.append(
        Activity("A0001", "Confirmed route", ActivityResult.CONFIRMED, target.id)
    )
    record.engagement.access.append(
        AccessRecord(
            "AR0001",
            "operator",
            "ACME",
            target.id,
            "SSH",
            AccessLevel.USER_EXECUTION,
        )
    )
    workspace.save(record.root, record.engagement)
    workspace.set_last_engagement(record.engagement.id)
    app = TacmuxApp(replace(settings, startup="resume_last"))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        main = app.screen
        assert isinstance(main, MainScreen)
        main.action_attack_path()
        await pilot.pause()
        form = app.screen
        assert isinstance(form, AttackPathForm)
        form.chosen = ["access:AR0001", "activity:A0001"]
        form.refresh_chosen()
        assert form.chosen == ["access:AR0001", "activity:A0001"]


@pytest.mark.asyncio
async def test_record_manager_is_visible_and_logging_uses_config_default(
    settings, workspace, record
):
    scope = record.engagement.add_scope("LAN", ScopeGroup.INTERNAL, "10.70.0.0/24")
    target = workspace.create_target(
        record.root,
        record.engagement,
        "host",
        addresses=[TargetAddress("10.70.0.10", scope.id)],
        primary_endpoint="10.70.0.10",
    )
    record.engagement.access.append(
        AccessRecord(
            "AR0001",
            "operator",
            "ACME",
            target.id,
            "SSH",
            AccessLevel.USER_EXECUTION,
        )
    )
    workspace.save(record.root, record.engagement)
    workspace.set_last_engagement(record.engagement.id)
    app = TacmuxApp(replace(settings, startup="resume_last", auto_log=False))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        main = app.screen
        assert isinstance(main, MainScreen)
        main.action_records()
        await pilot.pause()
        assert isinstance(app.screen, ActionMenu)
        assert app.screen.query_one(OptionList).option_count == 1
        await pilot.press("escape")
        app.push_screen(EngagementForm(app.settings.auto_log))
        await pilot.pause()
        assert not app.screen.query_one("#logging", Checkbox).value
