from __future__ import annotations

from dataclasses import replace

import pytest
from textual.command import CommandPalette
from textual.widgets import (
    Button,
    Checkbox,
    Input,
    Label,
    OptionList,
    Select,
    SelectionList,
    Static,
    TextArea,
)

from tacmux.app import EngagementPickerScreen, MainScreen, TacmuxApp
from tacmux.archive import create_archive
from tacmux.dialogs import (
    ActionMenu,
    AttackPathForm,
    ConfirmModal,
    DiscoveryReview,
    EngagementForm,
    MessageModal,
    ScanForm,
    TargetAddressForm,
    TargetForm,
)
from tacmux.discovery import DiscoveryCandidate, Reconciliation
from tacmux.errors import ConflictError
from tacmux.model import (
    AccessLevel,
    AccessRecord,
    Activity,
    ActivityResult,
    Authorization,
    EngagementStatus,
    ScopeAvailability,
    ScopeGroup,
    TargetAddress,
    CleanupKind,
)
from tacmux.themes import CURATED_THEME_NAMES, DEFAULT_THEME


@pytest.mark.asyncio
async def test_picker_is_usable_at_minimum_terminal_size(settings, workspace, record):
    app = TacmuxApp(settings)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        assert isinstance(app.screen, EngagementPickerScreen)
        assert app.screen.query_one("#engagements").row_count == 1
        assert app.theme == DEFAULT_THEME
        assert set(app.available_themes) == CURATED_THEME_NAMES
        await pilot.press("t")
        await pilot.pause()
        assert isinstance(app.screen, CommandPalette)


@pytest.mark.asyncio
async def test_picker_actions_permanently_delete_selected_engagement(
    settings, workspace, record, monkeypatch
):
    app = TacmuxApp(settings)
    monkeypatch.setattr(app.tmux, "available", lambda: False)
    monkeypatch.setattr(app.tmux, "live_target_ids", lambda _engagement: set())
    async with app.run_test(size=(100, 32)) as pilot:
        await pilot.pause()
        picker = app.screen
        assert isinstance(picker, EngagementPickerScreen)

        await pilot.press("a")
        await pilot.pause()
        assert isinstance(app.screen, ActionMenu)
        actions = app.screen.query_one(OptionList)
        assert actions.option_count == 5
        actions.highlighted = 4
        await pilot.press("enter")
        await pilot.pause()

        assert isinstance(app.screen, ConfirmModal)
        confirmation = app.screen.query_one("#confirmation", Input)
        required = f"DELETE {record.engagement.id}"
        assert app.screen.required_text == required
        assert str(record.root) in app.screen.message

        confirmation.value = "DELETE wrong-engagement"
        app.screen.query_one("#confirm", Button).press()
        await pilot.pause()
        assert isinstance(app.screen, ConfirmModal)
        assert "does not match" in str(app.screen.query_one(".error", Static).render())
        assert record.root.is_dir()

        confirmation.value = required
        app.screen.query_one("#confirm", Button).press()
        await pilot.pause()
        assert isinstance(app.screen, EngagementPickerScreen)
        assert app.screen.query_one("#engagements").row_count == 0
        assert not record.root.exists()


@pytest.mark.asyncio
async def test_picker_restores_the_only_deleted_engagement(
    settings, workspace, record
):
    archive, _ = create_archive(
        record.root,
        settings.archive_dir,
        kind="engagements",
        engagement_id=record.engagement.id,
        object_id=record.engagement.id,
    )
    workspace.delete_engagement(record.engagement.id)
    assert archive.is_file() and workspace.list_engagements() == []

    app = TacmuxApp(settings)
    async with app.run_test(size=(100, 32)) as pilot:
        await pilot.pause()
        assert isinstance(app.screen, EngagementPickerScreen)
        assert app.screen.query_one("#engagements").row_count == 0
        await pilot.press("r")
        await pilot.pause()
        assert isinstance(app.screen, ActionMenu)
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, MessageModal)
        await pilot.press("escape")
        await pilot.pause()
        assert isinstance(app.screen, EngagementPickerScreen)
        assert app.screen.query_one("#engagements").row_count == 1


def test_engagement_lifecycle_reports_all_active_work(
    settings, workspace, record, monkeypatch
):
    app = TacmuxApp(settings)
    ops_session = app.tmux.session_name(record.engagement)
    monkeypatch.setattr(app.tmux, "available", lambda: True)
    monkeypatch.setattr(
        app.tmux, "live_target_ids", lambda _engagement: {"T0001"}
    )
    monkeypatch.setattr(
        app.tmux, "has_session", lambda session: session == ops_session
    )
    monkeypatch.setattr(
        app.jobs,
        "list",
        lambda _root: [{"id": "J0001", "state": "running"}],
    )

    with pytest.raises(ConflictError) as raised:
        app.require_idle_engagement(record.engagement.id, "deleting the engagement")
    message = str(raised.value)
    assert "1 target session(s)" in message
    assert "operations session" in message
    assert "1 discovery job(s)" in message


def test_completed_discovery_job_does_not_block_engagement_lifecycle(
    settings, workspace, record, monkeypatch
):
    app = TacmuxApp(settings)
    monkeypatch.setattr(app.tmux, "available", lambda: False)
    monkeypatch.setattr(app.tmux, "live_target_ids", lambda _engagement: set())
    monkeypatch.setattr(
        app.jobs,
        "list",
        lambda _root: [{"id": "J0001", "state": "completed"}],
    )

    idle = app.require_idle_engagement(
        record.engagement.id, "archiving the engagement"
    )
    assert idle.engagement.id == record.engagement.id


@pytest.mark.asyncio
async def test_new_engagement_copy_explains_grouping_and_internal_reachability(
    settings, workspace
):
    app = TacmuxApp(settings)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.push_screen(EngagementForm())
        await pilot.pause()

        client = app.screen.query_one("#client", Input)
        name = app.screen.query_one("#name", Input)
        external = app.screen.query_one("#external", TextArea)
        internal = app.screen.query_one("#internal", TextArea)
        reachability = app.screen.query_one("#internal-availability", Select)
        labels = {str(label.render()) for label in app.screen.query(Label)}

        assert client.placeholder == "Who this work belongs to"
        assert name.placeholder == "Assessment name, project code, or lab name"
        assert "External DMZ = 198.51.100.0/24" in str(external.placeholder)
        assert "Domain Controller = 10.20.0.10/32" in str(internal.placeholder)
        assert "Internal scope reachability" in labels
        assert reachability._options == [
            ("Reachable now (direct, on-site, or VPN)", "ready"),
            ("Not reachable yet (requires access or pivot)", "unavailable"),
        ]
        assert reachability.value == "unavailable"


@pytest.mark.asyncio
@pytest.mark.parametrize("theme_name", sorted(CURATED_THEME_NAMES))
async def test_curated_theme_renders_picker_at_minimum_size(
    settings, workspace, theme_name
):
    workspace.set_theme(theme_name)
    app = TacmuxApp(settings)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        assert isinstance(app.screen, EngagementPickerScreen)
        assert app.theme == theme_name
        assert app.current_theme.dark


@pytest.mark.asyncio
async def test_theme_selection_persists_across_launches(settings, workspace):
    first = TacmuxApp(settings)
    async with first.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        first.theme = "nord"
        await pilot.pause()
        assert workspace.get_theme() == "nord"

    second = TacmuxApp(settings)
    async with second.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        assert second.theme == "nord"


@pytest.mark.asyncio
async def test_unknown_saved_theme_falls_back_and_repairs_state(settings, workspace):
    workspace.set_theme("removed-theme")
    app = TacmuxApp(settings)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        assert app.theme == DEFAULT_THEME
        assert workspace.get_theme() == DEFAULT_THEME


@pytest.mark.asyncio
async def test_theme_remains_active_when_persistence_fails(
    settings, workspace, monkeypatch
):
    app = TacmuxApp(settings)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()

        def fail_save(_theme_name: str) -> None:
            raise OSError("read-only state")

        monkeypatch.setattr(app.workspace, "set_theme", fail_save)
        app.theme = "dracula"
        await pilot.pause()
        assert app.theme == "dracula"


@pytest.mark.asyncio
async def test_blocked_discovery_result_cannot_cycle_or_merge(settings, workspace):
    decision = Reconciliation(
        DiscoveryCandidate(["203.0.113.10"], ["outside.example.test"]),
        [],
        "ignore",
        note="out of scope",
    )
    app = TacmuxApp(settings)
    async with app.run_test(size=(100, 32)) as pilot:
        await pilot.pause()
        app.push_screen(
            DiscoveryReview(decisions=[decision], merge_targets=[("T0001", "host")])
        )
        await pilot.pause()
        await pilot.press("space")
        await pilot.pause()
        assert decision.action == "ignore"
        assert isinstance(app.screen, DiscoveryReview)

        await pilot.press("m")
        await pilot.pause()
        assert decision.action == "ignore"
        assert isinstance(app.screen, DiscoveryReview)


@pytest.mark.asyncio
async def test_scan_form_lists_only_ready_scope(settings, workspace, record):
    record.engagement.add_scope("Ready", ScopeGroup.EXTERNAL, "198.51.100.0/24")
    record.engagement.add_scope(
        "Unavailable",
        ScopeGroup.INTERNAL,
        "10.10.0.0/24",
        ScopeAvailability.UNAVAILABLE,
    )
    workspace.save(record.root, record.engagement)
    app = TacmuxApp(settings)
    async with app.run_test(size=(100, 32)) as pilot:
        await pilot.pause()
        app.push_screen(ScanForm(record.engagement))
        await pilot.pause()
        assert app.screen.query_one(SelectionList).option_count == 1


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
        assert not any(
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
        await pilot.press("4")
        await pilot.press("a")
        await pilot.pause()
        assert isinstance(app.screen, ActionMenu)
        assert app.screen.query_one(OptionList).option_count == 2
        await pilot.press("escape")
        await pilot.pause()
        await pilot.press("5")
        await pilot.pause()
        assert any(
            path == evidence for path, _, _ in app.screen.document_paths.values()
        )
        await pilot.press("d")
        await pilot.pause()
        assert isinstance(app.screen, ActionMenu)
        await pilot.press("escape")
        await pilot.pause()
        assert isinstance(app.screen, MainScreen)


@pytest.mark.asyncio
async def test_unresolved_target_is_explicit_in_cockpit(
    settings, workspace, record
):
    workspace.create_target(record.root, record.engagement, "identity pending")
    workspace.set_last_engagement(record.engagement.id)
    app = TacmuxApp(replace(settings, startup="resume_last"))
    async with app.run_test(size=(100, 32)) as pilot:
        await pilot.pause()
        assert isinstance(app.screen, MainScreen)
        detail = app.screen.query_one("#target-detail", Static)
        assert "Identity: unresolved" in str(detail.render())


@pytest.mark.asyncio
async def test_disappearing_discovery_job_surfaces_error(
    settings, workspace, record, monkeypatch
):
    workspace.set_last_engagement(record.engagement.id)
    app = TacmuxApp(replace(settings, startup="resume_last"))
    errors: list[str] = []
    monkeypatch.setattr(app, "show_error", errors.append)
    async with app.run_test(size=(100, 32)) as pilot:
        await pilot.pause()
        main = app.screen
        assert isinstance(main, MainScreen)
        main._open_job_import([], "J0001")
        assert errors == ["The selected discovery job no longer exists"]


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
            evidence="logs/missing-proof.txt",
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
        assert isinstance(app.screen, MainScreen)
        records = app.screen.query_one("#records-table")
        assert records.row_count == 1
        assert "missing evidence" in str(records.get_row("access:AR0001")[3])
        app.push_screen(EngagementForm(app.settings.auto_log))
        await pilot.pause()
        assert not app.screen.query_one("#logging", Checkbox).value


@pytest.mark.asyncio
async def test_operator_text_is_literal_and_records_are_first_class(
    settings, workspace, record
):
    record.engagement.client = "ACME [prod]"
    record.engagement.name = "Assessment [Q3]"
    scope = record.engagement.add_scope(
        "DMZ", ScopeGroup.EXTERNAL, "198.51.100.0/24"
    )
    target = workspace.create_target(
        record.root,
        record.engagement,
        "web[1]",
        addresses=[TargetAddress("198.51.100.25", scope.id)],
        primary_endpoint="198.51.100.25",
    )
    workspace.create_cleanup_item(
        record.root,
        record.engagement,
        target_id=target.id,
        kind=CleanupKind.FILE,
        location="/tmp/agent[1]",
    )
    workspace.set_last_engagement(record.engagement.id)
    app = TacmuxApp(replace(settings, startup="resume_last"))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        main = app.screen
        assert isinstance(main, MainScreen)
        banner = str(main.query_one("#engagement-banner", Label).render())
        assert "ACME [prod]" in banner and "Assessment [Q3]" in banner
        await pilot.press("a")
        await pilot.pause()
        assert isinstance(app.screen, ActionMenu)
        assert "web[1]" in str(app.screen.query_one(".title", Label).render())
        await pilot.press("escape")
        await pilot.pause()
        await pilot.press("3")
        await pilot.pause()
        assert main.query_one("#records-table").row_count == 1


@pytest.mark.asyncio
async def test_target_forms_reject_a_selected_scope_that_does_not_match(
    settings, workspace, record
):
    first = record.engagement.add_scope(
        "Segment A", ScopeGroup.INTERNAL, "10.0.0.0/24"
    )
    record.engagement.add_scope(
        "Segment B", ScopeGroup.INTERNAL, "10.0.0.0/25"
    )
    wrong = record.engagement.add_scope(
        "Other", ScopeGroup.INTERNAL, "192.0.2.0/24"
    )
    workspace.save(record.root, record.engagement)
    app = TacmuxApp(settings)
    async with app.run_test(size=(100, 32)) as pilot:
        await pilot.pause()
        app.push_screen(TargetForm(record.engagement))
        await pilot.pause()
        form = app.screen
        form.query_one("#name", Input).value = "host"
        form.query_one("#address", Input).value = "10.0.0.10"
        form.query_one("#scope", Select).value = wrong.id
        form.query_one("#add", Button).press()
        await pilot.pause()
        assert isinstance(app.screen, TargetForm)
        assert "does not contain" in str(
            app.screen.query_one(".error", Static).render()
        )
        await pilot.press("escape")
        app.push_screen(TargetAddressForm(record.engagement, "host"))
        await pilot.pause()
        form = app.screen
        form.query_one("#address", Input).value = "10.0.0.10"
        form.query_one("#scope", Select).value = wrong.id
        form.query_one("#add", Button).press()
        await pilot.pause()
        assert isinstance(app.screen, TargetAddressForm)
        assert "does not contain" in str(
            app.screen.query_one(".error", Static).render()
        )
    assert first.id != wrong.id


@pytest.mark.asyncio
async def test_outside_window_warns_before_every_session_start_path(
    settings, workspace, record, monkeypatch
):
    scope = record.engagement.add_scope(
        "DMZ", ScopeGroup.EXTERNAL, "198.51.100.0/24"
    )
    workspace.create_target(
        record.root,
        record.engagement,
        "web",
        addresses=[TargetAddress("198.51.100.25", scope.id)],
        primary_endpoint="198.51.100.25",
    )
    record.engagement.authorization = Authorization(
        authorized_by="ACME",
        window_start="2020-01-01T00:00:00Z",
        window_end="2020-01-02T00:00:00Z",
    )
    workspace.save(record.root, record.engagement)
    workspace.set_last_engagement(record.engagement.id)
    app = TacmuxApp(replace(settings, startup="resume_last"))
    monkeypatch.setattr(
        app.tmux,
        "start_target",
        lambda *_args, **_kwargs: pytest.fail("started without confirmation"),
    )
    monkeypatch.setattr(
        app.tmux,
        "start_ops",
        lambda *_args, **_kwargs: pytest.fail("started without confirmation"),
    )
    monkeypatch.setattr(
        app.jobs,
        "create",
        lambda *_args, **_kwargs: pytest.fail("scanned without confirmation"),
    )
    async with app.run_test(size=(110, 36)) as pilot:
        await pilot.pause()
        main = app.screen
        assert isinstance(main, MainScreen)
        actions = [
            main.action_attach,
            main.action_ops,
            lambda: main._start_scan([scope.id]),
            lambda: main._commit_import(([], True, {scope.id})),
        ]
        for action in actions:
            action()
            await pilot.pause()
            assert isinstance(app.screen, ConfirmModal)
            assert app.screen.modal_title == "Outside Authorized Window"
            await pilot.press("escape")
            await pilot.pause()
            assert app.screen is main


@pytest.mark.asyncio
async def test_closed_engagement_blocks_operational_entry_points(
    settings, workspace, record, monkeypatch
):
    workspace.set_status(
        record.root, record.engagement, EngagementStatus.CLOSED
    )
    workspace.set_last_engagement(record.engagement.id)
    app = TacmuxApp(replace(settings, startup="resume_last"))
    errors: list[str] = []
    monkeypatch.setattr(app, "show_error", errors.append)
    async with app.run_test(size=(110, 36)) as pilot:
        await pilot.pause()
        main = app.screen
        assert isinstance(main, MainScreen)
        main.action_new_target()
        main.action_attach()
        main.action_scan()
        main._commit_import(([], False, set()))
        await pilot.pause()
    assert errors == [
        "Engagement is closed — reopen it from the engagement picker"
    ] * 4


@pytest.mark.asyncio
async def test_failed_refresh_does_not_publish_partial_runtime_state(
    settings, workspace, record, monkeypatch
):
    workspace.set_last_engagement(record.engagement.id)
    app = TacmuxApp(replace(settings, startup="resume_last"))
    async with app.run_test(size=(110, 36)) as pilot:
        await pilot.pause()
        main = app.screen
        assert isinstance(main, MainScreen)
        original_record = main.record
        original_live = main.live_target_ids.copy()
        original_states = main._job_states.copy()
        external = workspace.load(record.root)
        workspace.add_scope(
            record.root,
            external,
            "External",
            ScopeGroup.EXTERNAL,
            "198.51.100.0/24",
        )
        monkeypatch.setattr(
            app.tmux, "live_target_ids", lambda _engagement: {"T9999"}
        )
        monkeypatch.setattr(
            app.jobs,
            "list",
            lambda _root: [{"id": "J9999", "state": "running"}],
        )
        monkeypatch.setattr(
            app.workspace,
            "refresh_sitrep",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk full")),
        )
        errors: list[str] = []
        monkeypatch.setattr(app, "show_error", errors.append)
        assert main.refresh_all() is False
        assert errors == ["disk full"]
        assert main.record is original_record
        assert main.live_target_ids == original_live
        assert main._job_states == original_states


@pytest.mark.asyncio
async def test_discovery_post_commit_failures_do_not_report_a_rollback(
    settings, workspace, record, monkeypatch
):
    scope = record.engagement.add_scope(
        "DMZ", ScopeGroup.EXTERNAL, "198.51.100.0/24"
    )
    target = workspace.create_target(
        record.root,
        record.engagement,
        "web",
        addresses=[TargetAddress("198.51.100.25", scope.id)],
        primary_endpoint="198.51.100.25",
    )
    workspace.set_last_engagement(record.engagement.id)
    app = TacmuxApp(replace(settings, startup="resume_last"))
    async with app.run_test(size=(110, 36)) as pilot:
        await pilot.pause()
        main = app.screen
        assert isinstance(main, MainScreen)
        messages: list[tuple[str, str]] = []
        monkeypatch.setattr(
            "tacmux.app.apply_reconciliation",
            lambda *_args, **_kwargs: [target],
        )
        monkeypatch.setattr(
            app.jobs,
            "mark_imported",
            lambda *_args: (_ for _ in ()).throw(OSError("read-only status")),
        )
        monkeypatch.setattr(
            app.tmux,
            "start_target",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                ConflictError("session collision")
            ),
        )
        monkeypatch.setattr(
            app,
            "notify",
            lambda message, *_args, **kwargs: messages.append(
                (str(message), str(kwargs.get("severity", "")))
            ),
        )
        main.pending_job_id = "J0001"
        main._commit_import(([], True, {scope.id}), window_checked=True)
        await pilot.pause()
        assert main.pending_job_id == ""
        assert messages and messages[-1][1] == "warning"
        assert "already committed" in messages[-1][0]
        assert "sessions not started" in messages[-1][0]
