"""Guided operator flow: safe help, prompts for gaps, vocabulary, palette, undo."""

from __future__ import annotations

import subprocess

import pytest

from tacmux import sitrep
from tacmux.cli import main
from tacmux.errors import NonInteractiveError
from tacmux.hooks import status_segment
from tacmux.interaction import ask, choose
from tacmux.vocab import ACCESS_ALIASES, AmbiguousWordError, match_word
from tacmux.workspace import ACCESS_LEVELS, OUTCOMES, UNDO_LIMIT


def _configure(monkeypatch, settings):
    monkeypatch.setenv("TACMUX_WORKSPACE", str(settings.workspace))
    monkeypatch.setenv("TACMUX_CONFIG", str(settings.config_file))
    monkeypatch.delenv("TMUX", raising=False)


@pytest.fixture
def web01(monkeypatch, settings, workspace, engagement):
    _configure(monkeypatch, settings)
    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    monkeypatch.chdir(engagement / "targets/WEB01")
    return engagement


def _sequence(monkeypatch, name, values):
    remaining = list(values)
    seen = []

    def fake(*args, **kwargs):
        seen.append((args, kwargs))
        if not remaining:
            raise AssertionError(f"unexpected {name} call: {args}")
        return remaining.pop(0)

    monkeypatch.setattr(f"tacmux.cli.{name}", fake)
    return seen


@pytest.mark.parametrize(
    "argv",
    [
        ["log", "--help"],
        ["done", "-h"],
        ["fail", "help"],
        ["target", "update", "--help"],
        ["stop", "--help"],
        ["creds", "confirm", "--help"],
        ["history", "WEB01", "--help"],
    ],
)
def test_help_never_mutates_sitrep(web01, workspace, capsys, argv):
    before = workspace.read(web01)
    assert main(argv) == 0
    output = capsys.readouterr().out
    assert f"tm {argv[0]}" in output
    assert workspace.read(web01) == before


def test_help_lists_accepted_vocabulary(web01, capsys):
    assert main(["help", "target"]) == 0
    output = capsys.readouterr().out
    for word in (*ACCESS_LEVELS, "complete", "hostnames"):
        assert word in output
    assert main(["log", "--help"]) == 0
    log_help = capsys.readouterr().out
    assert all(outcome in log_help for outcome in OUTCOMES)


def test_unknown_options_are_refused_and_sentinel_logs_text(web01, workspace, capsys):
    assert main(["log", "-x", "foo"]) == 1
    assert "unknown option -x" in capsys.readouterr().err
    assert main(["todo", "add", "--bogus"]) == 1
    assert sitrep.read_tasks(workspace.read(web01), "TODO") == []
    assert main(["log", "--", "-x", "foo"]) == 0
    assert sitrep.read_events(workspace.read(web01))[-1].summary == "-x foo"


def test_noninteractive_fails_fast_without_pickers(
    web01, workspace, monkeypatch, capsys
):
    monkeypatch.setenv("TACMUX_NONINTERACTIVE", "1")

    def no_fzf(*_args, **_kwargs):
        raise AssertionError("fzf must not run non-interactively")

    monkeypatch.setattr("tacmux.interaction.subprocess.run", no_fzf)
    assert main(["fail"]) == 1
    assert "missing" in capsys.readouterr().err
    assert main(["target", "update", "access"]) == 1
    assert sitrep.read_events(workspace.read(web01)) == []
    with pytest.raises(NonInteractiveError):
        choose([("a", "a")], "Pick> ")
    with pytest.raises(NonInteractiveError):
        ask("Summary")


def test_missing_terminal_is_detected_without_env(monkeypatch):
    monkeypatch.setattr("tacmux.interaction.picker_available", lambda: False)
    monkeypatch.setattr("tacmux.interaction.text_input_available", lambda: False)
    with pytest.raises(NonInteractiveError, match="missing target"):
        choose([("a", "a")], "Target> ")
    with pytest.raises(NonInteractiveError, match="missing summary"):
        ask("Summary")


@pytest.mark.parametrize("mode", ["forced", "no-terminal"])
def test_target_delete_requires_interactive_confirmation(
    web01, workspace, monkeypatch, capsys, mode
):
    before = workspace.read(web01)
    if mode == "forced":
        monkeypatch.setenv("TACMUX_NONINTERACTIVE", "1")
    else:
        monkeypatch.setattr("tacmux.interaction.text_input_available", lambda: False)
    monkeypatch.setattr("tacmux.tmux.TmuxService.require_stopped", lambda *_: None)

    def no_input(_prompt):
        raise AssertionError("delete must not read a noninteractive confirmation")

    monkeypatch.setattr("builtins.input", no_input)
    assert main(["target", "delete", "WEB01"]) == 1
    assert "missing" in capsys.readouterr().err
    assert (web01 / "targets/WEB01").is_dir()
    assert workspace.read(web01) == before


def test_target_delete_still_requires_the_exact_name(
    web01, workspace, monkeypatch, capsys
):
    monkeypatch.chdir(web01)
    monkeypatch.setattr("tacmux.tmux.TmuxService.require_stopped", lambda *_: None)
    before = workspace.read(web01)
    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")
    assert main(["target", "delete", "WEB01"]) == 1
    assert "deletion cancelled" in capsys.readouterr().err
    assert workspace.read(web01) == before
    monkeypatch.setattr("builtins.input", lambda _prompt: "WEB01")
    assert main(["target", "delete", "WEB01"]) == 0
    assert workspace.targets(web01) == []


def test_fail_shortcuts_and_history_filter(web01, workspace, capsys):
    assert main(["fail", "EDB", "50640", "broken"]) == 0
    assert main(["log", "f", "ferox", "only", "static"]) == 0
    assert main(["log", "in", "progress", "smb"]) == 0
    assert main(["log", "p", "hash", "did", "not", "crack"]) == 0
    events = sitrep.read_events(workspace.read(web01))
    assert [event.outcome for event in events] == [
        "failed",
        "failed",
        "info",
        "partial",
    ]
    assert events[2].summary == "in progress smb"
    capsys.readouterr()
    assert main(["history", "--outcome", "fail"]) == 0
    output = capsys.readouterr().out
    assert "EDB 50640 broken" in output
    assert "in progress smb" not in output


def test_match_word_exact_alias_prefix_and_ambiguity():
    assert match_word("root", ACCESS_LEVELS, ACCESS_ALIASES) == "admin"
    assert match_word("shell", ACCESS_LEVELS, ACCESS_ALIASES) == "user"
    assert match_word("auth", ACCESS_LEVELS, ACCESS_ALIASES) == "authenticated"
    assert match_word("dom", ACCESS_LEVELS, ACCESS_ALIASES) == "domain"
    assert match_word("USER", ACCESS_LEVELS, ACCESS_ALIASES) == "user"
    with pytest.raises(AmbiguousWordError) as caught:
        match_word("a", ACCESS_LEVELS, ACCESS_ALIASES)
    assert set(caught.value.candidates) == {"authenticated", "admin"}
    with pytest.raises(AmbiguousWordError, match="unknown"):
        match_word("bogus", ACCESS_LEVELS, ACCESS_ALIASES)


def test_target_update_prompts_only_for_missing_pieces(web01, workspace, monkeypatch):
    seen = _sequence(monkeypatch, "choose", ["user"])
    assert main(["target", "update", "access"]) == 0
    assert len(seen) == 1 and seen[0][0][1] == "Access> "
    assert main(["target", "update", "WEB01", "acc", "root"]) == 0
    assert main(["target", "update", "st", "done"]) == 0
    details = workspace.target_details(web01, "WEB01")
    assert details["Access"][0] == "admin"
    assert details["Status"][0] == "complete"


def test_ambiguous_value_opens_prefiltered_picker(web01, workspace, monkeypatch):
    seen = _sequence(monkeypatch, "choose", ["admin"])
    assert main(["target", "update", "access", "a"]) == 0
    assert seen[0][1]["query"] == "a"
    assert workspace.target_details(web01, "WEB01")["Access"][0] == "admin"


def test_credential_confirms_on_several_targets_with_port_service(
    web01, workspace, monkeypatch, tmp_path
):
    workspace.add_target(web01, "DC01", "192.0.2.20")
    report = tmp_path / "web.nmap"
    report.write_text("445/tcp open microsoft-ds Samba smbd\n22/tcp open ssh\n")
    assert main(["ports", "add", "WEB01", str(report)]) == 0
    credential = workspace.add_credential(web01, "alice", "Winter2024!", "password")
    assert main(["creds", "confirm", credential, "WEB01", "DC01", "auth", "445"]) == 0
    row = sitrep.read_global(workspace.read(web01), "CREDENTIALS")[0]
    assert sitrep.parse_confirmed_access(row[5]) == [
        ("WEB01", "microsoft-ds :445", "authenticated"),
        ("DC01", "microsoft-ds :445", "authenticated"),
    ]


def test_credential_confirm_service_picker_uses_ports(
    web01, workspace, monkeypatch, tmp_path
):
    report = tmp_path / "web.nmap"
    report.write_text("8000/tcp open http WSGIServer 0.2\n")
    assert main(["ports", "add", "WEB01", str(report)]) == 0
    credential = workspace.add_credential(web01, "admin", "admin", "password")
    seen = _sequence(monkeypatch, "choose", ["authenticated", "http :8000"])
    _sequence(monkeypatch, "ask", [""])
    assert main(["creds", "confirm", credential]) == 0
    services = [entry[0] for entry in seen[1][0][0]]
    assert any(display.startswith("http :8000") for display in services)
    row = sitrep.read_global(workspace.read(web01), "CREDENTIALS")[0]
    assert "WEB01 · http :8000 · authenticated" in row[5]
    assert workspace.target_details(web01, "WEB01")["Access"][0] == "authenticated"


def test_undo_restores_and_refuses_after_external_edit(
    web01, workspace, monkeypatch, capsys
):
    original = workspace.read(web01)
    assert main(["done", "root", "shell"]) == 0
    monkeypatch.setattr("builtins.input", lambda _prompt: "y")
    assert main(["undo"]) == 0
    assert workspace.read(web01) == original
    assert "Undid: tm done root shell" in capsys.readouterr().out

    assert main(["fail", "something"]) == 0
    path = workspace.sitrep_path(web01)
    path.write_text(path.read_text() + "\nmanual note\n")
    assert main(["undo"]) == 1
    assert "undo refused" in capsys.readouterr().err
    assert "manual note" in workspace.read(web01)


def test_undo_masks_credentials_and_prunes_journal(
    web01, workspace, monkeypatch, capsys
):
    assert main(["creds", "add", "password", "alice:SuperSecret1"]) == 0
    monkeypatch.setattr("builtins.input", lambda _prompt: "n")
    assert main(["undo"]) == 1
    output = capsys.readouterr()
    assert "SuperSecret1" not in output.out
    assert "credential C001 row" in output.out
    assert "tm creds add" in output.out
    for index in range(UNDO_LIMIT + 5):
        workspace.add_event(web01, "WEB01", "info", f"entry {index}")
    journal = list((web01 / ".tacmux/undo").glob("*.json"))
    assert len(journal) == UNDO_LIMIT


@pytest.mark.parametrize("concurrent_change", ["append", "undo"])
def test_undo_refuses_a_different_change_than_the_preview(
    web01, workspace, monkeypatch, capsys, concurrent_change
):
    assert main(["done", "First step"]) == 0

    def concurrent_write(_prompt):
        if concurrent_change == "append":
            workspace.add_event(web01, "WEB01", "info", "Concurrent step")
        else:
            workspace.undo_last_change(web01, expected=workspace.last_change(web01))
        return "y"

    monkeypatch.setattr("builtins.input", concurrent_write)
    assert main(["undo"]) == 1
    output = capsys.readouterr()
    assert "undo history changed" in output.err
    assert "Undid:" not in output.out
    assert [event.summary for event in sitrep.read_events(workspace.read(web01))] == (
        ["First step", "Concurrent step"] if concurrent_change == "append" else []
    )


@pytest.mark.parametrize("action", ["add", "rename", "delete"])
def test_target_lifecycle_starts_a_safe_undo_history(
    web01, workspace, monkeypatch, capsys, action
):
    monkeypatch.chdir(web01)
    monkeypatch.setattr("tacmux.tmux.TmuxService.require_stopped", lambda *_: None)
    monkeypatch.setattr("builtins.input", lambda _prompt: "WEB01")
    evidence = web01 / "targets/WEB01/working/evidence.txt"
    evidence.write_text("keep this evidence\n")
    assert main(["log", "Earlier engagement note"]) == 0
    if action == "add":
        assert main(["target", "add", "WEB02", "192.0.2.20"]) == 0
    elif action == "rename":
        assert main(["target", "rename", "WEB01", "WEB02"]) == 0
        evidence = web01 / "targets/WEB02/working/evidence.txt"
    else:
        assert main(["target", "delete", "WEB01"]) == 0
    baseline = workspace.read(web01)
    targets = workspace.targets(web01)

    assert main(["undo", "--yes"]) == 1
    assert (
        "undo history starts after target directory changes" in capsys.readouterr().err
    )
    assert workspace.read(web01) == baseline
    assert workspace.targets(web01) == targets
    assert workspace.validate(web01) == []
    assert len(list((web01 / ".tacmux/undo").glob("*.json"))) == 1
    if action != "delete":
        assert evidence.read_text() == "keep this evidence\n"

    assert main(["log", "Later engagement note"]) == 0
    assert main(["undo", "--yes"]) == 0
    assert workspace.read(web01) == baseline
    assert workspace.validate(web01) == []
    assert main(["undo", "--yes"]) == 1
    assert workspace.read(web01) == baseline


def test_palette_runs_actions_and_switches_sessions(web01, workspace, monkeypatch):
    _sequence(monkeypatch, "choose", ["fail"])
    _sequence(monkeypatch, "ask", ["EDB 50640 broken", ""])
    assert main(["menu"]) == 0
    event = sitrep.read_events(workspace.read(web01))[-1]
    assert (event.outcome, event.target, event.summary) == (
        "failed",
        "WEB01",
        "EDB 50640 broken",
    )

    started = []
    monkeypatch.setattr(
        "tacmux.tmux.TmuxService.start",
        lambda self, root, target="": started.append((root, target)) or "session",
    )
    monkeypatch.setattr("tacmux.tmux.TmuxService.attach", lambda self, session: 0)
    monkeypatch.setattr("tacmux.tmux.TmuxService.sessions", lambda self: [])
    _sequence(monkeypatch, "choose", [f"session\x1f{web01}\x1fWEB01"])
    assert main(["menu"]) == 0
    assert started == [(web01, "WEB01")]


def test_palette_choices_carry_direct_command_previews(web01, monkeypatch):
    captured = {}

    def fake_choose(choices, prompt, **kwargs):
        captured["choices"] = choices
        captured["header"] = kwargs.get("header", "")
        return "status"

    monkeypatch.setattr("tacmux.cli.choose", fake_choose)
    monkeypatch.setattr("tacmux.tmux.TmuxService.sessions", lambda self: [])
    assert main(["menu"]) == 0
    previews = {value: preview for _display, value, preview in captured["choices"]}
    assert "tm fail" in previews["fail"]
    assert "tm creds confirm" in previews["cred_confirm"]
    assert "WEB01" in captured["header"] and "Access: none" in captured["header"]
    assert any(value.startswith("session\x1f") for value in previews)


def test_status_segment_shows_cached_access(
    settings, workspace, engagement, monkeypatch
):
    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    options = {}
    reads = []

    class FakeTmux:
        def run(self, args, **_kwargs):
            if args[0] == "display-message":
                out = f"WEB01\t{engagement}\t1\tsess\n"
            elif args[0] == "show-option":
                out = options.get("cache", "")
            else:
                options["cache"] = args[-1]
                out = ""
            return subprocess.CompletedProcess(args, 0, out, "")

    original = workspace.target_details

    def counting(root, target):
        reads.append(target)
        return original(root, target)

    monkeypatch.setenv("TMUX", "1")
    monkeypatch.setattr(
        "tacmux.workspace.Workspace.target_details", lambda self, r, t: counting(r, t)
    )
    first = status_segment(settings, FakeTmux())
    assert "none" in first and "yellow,bold" in first
    status_segment(settings, FakeTmux())
    assert len(reads) == 1
    monkeypatch.undo()
    monkeypatch.setenv("TMUX", "1")
    workspace.set_target_detail(engagement, "WEB01", "Access", "user")
    assert "user" in status_segment(settings, FakeTmux())


def test_popup_binding_passes_invoking_pane_and_client(monkeypatch, settings):
    _configure(monkeypatch, settings)
    calls = []

    def fake_run(self, args, **_kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("tacmux.tmux.TmuxService.run", fake_run)
    assert main(["_internal", "popup", "%7", "/dev/pts/3", "/tmp"]) == 0
    argv = calls[0]
    assert argv[0] == "display-popup"
    assert argv[argv.index("-t") + 1] == "%7"
    assert argv[argv.index("-c") + 1] == "/dev/pts/3"
    assert "TMUX_PANE=%7" in argv and "TACMUX_POPUP=1" in argv
    assert argv[-1] == "menu"
