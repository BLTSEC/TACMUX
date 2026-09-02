from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from tacmux.context import resolve
from tacmux.errors import ConflictError, ValidationError
from tacmux.tmux import Session, TmuxService


def test_context_resolves_target_from_working_directory(
    settings, workspace, engagement, monkeypatch
):
    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    monkeypatch.chdir(engagement / "targets/WEB01/working")
    context = resolve(settings, allow_picker=False)
    assert context.root == engagement
    assert context.target == "WEB01"


def test_tmux_pane_metadata_wins_and_disagreement_fails(
    settings, workspace, engagement, monkeypatch
):
    class FakeTmux:
        def current_context(self):
            return engagement, "WEB01"

    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    monkeypatch.setenv("TMUX", "1")
    monkeypatch.setenv("TACMUX_ROOT", str(engagement / "wrong"))
    with pytest.raises(ValidationError, match="disagrees"):
        resolve(settings, FakeTmux(), allow_picker=False)


def test_unowned_tmux_does_not_use_stale_environment(settings, workspace, monkeypatch):
    class FakeTmux:
        def current_context(self):
            return None, ""

    one = workspace.create_engagement("ONE")
    workspace.create_engagement("TWO")
    monkeypatch.setenv("TMUX", "1")
    monkeypatch.setenv("TACMUX_ROOT", str(one))
    monkeypatch.chdir(settings.workspace)
    with pytest.raises(ValidationError, match="no engagement context"):
        resolve(settings, FakeTmux(), allow_picker=False)


def test_session_name_is_readable_and_collision_resistant(settings):
    tmux = TmuxService(settings)
    root = settings.workspace / "ACME Corp"
    first = tmux.session_name(root, "WEB 01")
    second = tmux.session_name(root, "WEB-01")
    assert "ACME-Corp" in first
    assert first != second


def test_tmux_context_preserves_empty_operations_target(
    settings, engagement, monkeypatch
):
    tmux = TmuxService(settings)

    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(args, 0, f"{engagement}\t\n", "")

    monkeypatch.setattr(tmux, "available", lambda: True)
    monkeypatch.setattr(tmux, "run", fake_run)
    monkeypatch.setenv("TMUX", "1")

    assert tmux.current_context() == (engagement, "")
    assert tmux.session_context("tacmux-example-ops") == (engagement, "")


def test_start_exports_central_nocap_and_logs(
    settings, workspace, engagement, monkeypatch
):
    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    tmux = TmuxService(settings)
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[0] == "has-session":
            return subprocess.CompletedProcess(args, 1, "", "")
        if args[0] == "new-session":
            return subprocess.CompletedProcess(args, 0, "%1\n", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(tmux, "available", lambda: True)
    monkeypatch.setattr(tmux, "run", fake_run)
    monkeypatch.setattr(
        "tacmux.hooks.LogController.start", lambda *args, **kwargs: None
    )
    session = tmux.start(engagement, "WEB01")
    create = next(args for args in calls if args[0] == "new-session")
    assert "NOCAP_WORKSPACE=" + str(engagement) in create
    assert "TACMUX_TARGET=captures" in create
    assert "NOCAP_ROUTE_PREFIX=WEB01" in create
    assert "TARGET=192.0.2.10" in create
    hooks = [args for args in calls if args[0] == "set-hook"]
    assert {args[3] for args in hooks} == {
        "after-new-window[90]",
        "after-split-window[90]",
    }
    assert all("_internal log start" in args[4] for args in hooks)
    assert session.target == "WEB01"


def test_repair_autolog_hooks_touches_only_owned_sessions(settings, monkeypatch):
    tmux = TmuxService(settings)
    owned = [Session("tacmux-acme-ops", Path("/tmp/acme"), "")]
    installed = []
    removed = []
    monkeypatch.setattr(tmux, "sessions", lambda: owned)
    monkeypatch.setattr(tmux, "install_autolog_hooks", installed.append)
    monkeypatch.setattr(
        tmux, "remove_legacy_global_autolog_hooks", lambda: removed.append(True)
    )

    assert tmux.repair_autolog_hooks() == 1
    assert installed == ["tacmux-acme-ops"]
    assert removed == [True]


def test_legacy_global_hook_cleanup_is_specific(settings, monkeypatch):
    tmux = TmuxService(settings)
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[:2] == ["show-hooks", "-g"]:
            hook = args[2]
            output = (
                f'{hook}[90] run-shell -b "tacmux _internal log start pane"\n'
                f'{hook}[91] display-message "operator hook"\n'
            )
            return subprocess.CompletedProcess(args, 0, output, "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(tmux, "run", fake_run)
    tmux.remove_legacy_global_autolog_hooks()

    assert [args for args in calls if args[:2] == ["set-hook", "-gu"]] == [
        ["set-hook", "-gu", "after-new-window[90]"],
        ["set-hook", "-gu", "after-split-window[90]"],
    ]


def test_require_stopped(settings, monkeypatch):
    tmux = TmuxService(settings)
    monkeypatch.setattr(tmux, "target_running", lambda *_: True)
    with pytest.raises(ConflictError, match="stop WEB01"):
        tmux.require_stopped(Path("/tmp/acme"), "WEB01")


def test_start_refuses_unrelated_existing_session(
    settings, workspace, engagement, monkeypatch
):
    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    tmux = TmuxService(settings)
    monkeypatch.setattr(tmux, "available", lambda: True)
    monkeypatch.setattr(tmux, "has_session", lambda _name: True)
    monkeypatch.setattr(tmux, "session_context", lambda _name: (None, ""))
    with pytest.raises(ConflictError, match="unrelated tmux session"):
        tmux.start(engagement, "WEB01")
