"""TACMUX 3.2 foundation: one-step access records and evidence attached later."""

from __future__ import annotations

from pathlib import Path

import pytest

from tacmux import sitrep
from tacmux.errors import ConflictError, ValidationError
from tacmux.workspace import CaptureRecord

PNG = b"\x89PNG\r\n\x1a\n" + b"\0" * 64


@pytest.fixture
def web01(workspace, engagement):
    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    return engagement


def _png(tmp_path: Path, name: str = "proof.png") -> Path:
    path = tmp_path / name
    path.write_bytes(PNG)
    return path


def _capture(engagement: Path, ident: str = "cap-1") -> CaptureRecord:
    evidence = engagement / "captures/WEB01/nmap.txt"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text("22/tcp open ssh\n")
    return CaptureRecord(ident, "done", "nmap", "WEB01/nmap.txt", "nmap -sV x")


def test_record_access_is_one_undoable_change(workspace, web01):
    credential = workspace.add_credential(web01, "admin", "admin", "password")
    before = workspace.read(web01)
    event = workspace.record_access(
        web01,
        "WEB01",
        "user",
        "Access: user as app via http :8000 (CVE-2021-43857 RCE)",
        principal="app",
        method="CVE-2021-43857 RCE via http :8000",
        credential=credential,
        credential_access="authenticated",
        service="http :8000",
    )
    text = workspace.read(web01)
    details = sitrep.details_map(text, "WEB01")
    assert (details["Access"][0], details["Principal"][0]) == ("user", "app")
    assert details["Method/Path"][0] == "CVE-2021-43857 RCE via http :8000"
    row = sitrep.read_global(text, "CREDENTIALS")[0]
    assert "WEB01 · http :8000 · authenticated" in row[5]
    assert sitrep.read_events(text)[-1].identifier == event
    workspace.undo_last_change(web01, expected=workspace.last_change(web01))
    assert workspace.read(web01) == before


def test_record_access_never_lowers(workspace, web01):
    workspace.record_access(web01, "WEB01", "admin", "root", principal="root")
    workspace.record_access(web01, "WEB01", "user", "user shell", principal="app")
    details = workspace.target_details(web01, "WEB01")
    assert (details["Access"][0], details["Principal"][0]) == ("admin", "root")
    assert [e.outcome for e in sitrep.read_events(workspace.read(web01))] == [
        "success",
        "success",
    ]


def test_attach_screenshot_replaces_the_placeholder(workspace, web01, tmp_path):
    capture = _capture(web01)
    event = workspace.add_event(web01, "WEB01", "success", "Shell", capture=capture)
    assert "_Not attached._" in workspace.read(web01)
    workspace.attach_to_event(web01, event, images=[_png(tmp_path)])
    body = sitrep.read_events(workspace.read(web01))[-1].body
    assert "_Not attached._" not in body
    assert "](<images/proof.png>)" in body
    assert body.count("#### Screenshots") == 1


def test_attach_screenshot_and_capture_to_a_plain_entry(workspace, web01, tmp_path):
    event = workspace.add_event(web01, "WEB01", "success", "root flag /root/proof.txt")
    workspace.attach_to_event(web01, event, images=[_png(tmp_path, "a.png")])
    workspace.attach_to_event(web01, event, images=[_png(tmp_path, "b.png")])
    workspace.attach_to_event(web01, event, capture=_capture(web01))
    entry = sitrep.read_events(workspace.read(web01))[-1]
    assert entry.capture_id == "cap-1"
    assert entry.body.startswith("#### Evidence")
    assert entry.body.count("#### Screenshots") == 1
    assert "images/a.png" in entry.body and "images/b.png" in entry.body
    assert workspace.validate(web01) == []


def test_attach_refuses_unknown_and_duplicate_captures(workspace, web01):
    first = workspace.add_event(web01, "WEB01", "info", "one", capture=_capture(web01))
    second = workspace.add_event(web01, "WEB01", "info", "two")
    with pytest.raises(ValidationError, match="unknown event"):
        workspace.attach_to_event(web01, "E999", capture=_capture(web01, "x"))
    with pytest.raises(ConflictError, match="already attached"):
        workspace.attach_to_event(web01, second, capture=_capture(web01))
    with pytest.raises(ConflictError, match="already has capture"):
        workspace.attach_to_event(web01, first, capture=_capture(web01, "cap-2"))
    with pytest.raises(ValidationError, match="nothing to attach"):
        workspace.attach_to_event(web01, second)


# --- 2.4 snapshots and shell-handler logs -----------------------------------


def _penelope(base: Path, name: str, files: dict[str, bytes]) -> Path:
    session = base / name
    for relative, data in files.items():
        path = session / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return session


def test_shell_logs_match_endpoint_with_or_without_hostname(tmp_path, engagement):
    from tacmux.integrations import collect_shell_logs

    base = tmp_path / ".penelope/sessions"
    _penelope(base, "ubuntu~192.0.2.10-Linux-x86_64", {"a.log": b"one\n"})
    _penelope(base, "192.0.2.10-Linux-x86_64", {"b.log": b"two\n"})
    _penelope(base, "ubuntu~192.0.2.100-Linux-x86_64", {"other.log": b"no\n"})
    _penelope(
        base,
        "dc01~192.0.2.10-Windows",
        {"c.log": b"three\n", "downloads/loot/db.sqlite3": b"db", "notes.txt": b"skip"},
    )
    copied = collect_shell_logs(engagement, "WEB01", "192.0.2.10", [base])
    shells = engagement / "captures/WEB01/shells/penelope"
    names = sorted(path.relative_to(shells).as_posix() for path in copied)
    assert names == [
        "192.0.2.10-Linux-x86_64/b.log",
        "dc01~192.0.2.10-Windows/c.log",
        "dc01~192.0.2.10-Windows/downloads/loot/db.sqlite3",
        "ubuntu~192.0.2.10-Linux-x86_64/a.log",
    ]
    assert not (shells / "ubuntu~192.0.2.100-Linux-x86_64").exists()
    readme = (shells / "ubuntu~192.0.2.10-Linux-x86_64/README.txt").read_text()
    assert "local time (UTC offset" in readme
    assert (
        shells / "ubuntu~192.0.2.10-Linux-x86_64/a.log"
    ).stat().st_mode & 0o777 == 0o600
    # Idempotent: an unchanged rerun copies nothing; a grown log is refreshed.
    assert collect_shell_logs(engagement, "WEB01", "192.0.2.10", [base]) == []
    (base / "ubuntu~192.0.2.10-Linux-x86_64/a.log").write_bytes(b"one\nmore\n")
    again = collect_shell_logs(engagement, "WEB01", "192.0.2.10", [base])
    assert [path.name for path in again] == ["a.log"]


def test_shell_logs_skip_symlinks_and_oversized_files(
    tmp_path, engagement, monkeypatch
):
    from tacmux import integrations

    base = tmp_path / "sessions"
    session = _penelope(base, "h~192.0.2.10-Linux", {"big.log": b"x" * 10})
    (session / "link.log").symlink_to(tmp_path / "secret")
    (tmp_path / "secret").write_text("not copied")
    (base / "h~192.0.2.10-Linked").symlink_to(session)
    monkeypatch.setattr(integrations, "SIZE_LIMIT", 5)
    assert (
        integrations.collect_shell_logs(engagement, "WEB01", "192.0.2.10", [base]) == []
    )


def test_snapshot_captures_rendered_text(settings, engagement, monkeypatch):
    from tacmux.hooks import LogController

    calls = []

    class FakeTmux:
        def run(self, args, **_kwargs):
            import subprocess

            calls.append(args)
            out = b"" if args[0] == "capture-pane" else "WEB01\twin\ttitle\t0"
            if args[0] == "show-option":
                out = (
                    str(engagement / "logs")
                    if "@tacmux_log_dir" in args
                    else str(engagement)
                )
            return subprocess.CompletedProcess(args, 0, out, "")

    controller = LogController(settings, FakeTmux())
    controller.capture("%1")
    capture = next(args for args in calls if args[0] == "capture-pane")
    assert "-J" in capture


def test_settings_parse_snapshot_and_shell_log_dirs(tmp_path):
    from tacmux.config import load_settings

    config = tmp_path / "config.toml"
    config.write_text(
        "[behavior]\nsnapshot_on_stop = false\n"
        '[integrations]\nshell_log_dirs = ["~/a", "/srv/b"]\n'
    )
    settings = load_settings({"TACMUX_CONFIG": str(config), "HOME": str(tmp_path)})
    assert settings.snapshot_on_stop is False
    assert settings.shell_log_dirs == (tmp_path / "a", Path("/srv/b"))
    default = load_settings(
        {"TACMUX_CONFIG": str(tmp_path / "none.toml"), "HOME": str(tmp_path)}
    )
    assert default.snapshot_on_stop is True
    assert default.shell_log_dirs == (tmp_path / ".penelope/sessions",)


def test_stop_snapshots_before_killing(
    settings, workspace, engagement, monkeypatch, capsys
):
    from tacmux.cli import main

    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    monkeypatch.setenv("TACMUX_WORKSPACE", str(settings.workspace))
    monkeypatch.setenv("TACMUX_CONFIG", str(settings.config_file))
    monkeypatch.delenv("TMUX", raising=False)
    monkeypatch.chdir(engagement / "targets/WEB01")
    order = []
    monkeypatch.setattr("tacmux.tmux.TmuxService.has_session", lambda self, name: True)
    monkeypatch.setattr(
        "tacmux.tmux.TmuxService.panes",
        lambda self, name: [("%1", "zsh"), ("%2", "penelope")],
    )
    monkeypatch.setattr(
        "tacmux.tmux.TmuxService.logging_panes", lambda self, name: {"%1", "%2"}
    )
    monkeypatch.setattr(
        "tacmux.hooks.LogController.capture",
        lambda self, pane: order.append(("capture", pane)) or engagement / "logs/x.log",
    )
    monkeypatch.setattr(
        "tacmux.tmux.TmuxService.stop",
        lambda self, root, target="": order.append(("stop", target)),
    )
    assert main(["stop"]) == 0
    assert order == [("capture", "%1"), ("capture", "%2"), ("stop", "WEB01")]
    assert "Snapshot  2 pane(s)" in capsys.readouterr().out


# --- 2.5 evidence helpers ----------------------------------------------------


def _fake_flameshot(tmp_path: Path, monkeypatch, payload: bytes) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    data = tmp_path / "shot.bin"
    data.write_bytes(payload)
    script = bin_dir / "flameshot"
    script.write_text(f'#!/bin/sh\ncat "{data}"\n')
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{__import__('os').environ['PATH']}")
    monkeypatch.delenv("TMUX", raising=False)


def test_take_screenshot_saves_and_attaches(workspace, web01, tmp_path, monkeypatch):
    from tacmux.evidence import take_screenshot

    event = workspace.add_event(web01, "WEB01", "success", "root flag /root/proof.txt")
    _fake_flameshot(tmp_path, monkeypatch, PNG)
    path = take_screenshot(workspace, web01, "WEB01", event)
    assert path is not None and path.parent == web01 / "targets/WEB01/screenshots"
    assert path.read_bytes() == PNG and path.stat().st_mode & 0o777 == 0o600
    body = sitrep.read_events(workspace.read(web01))[-1].body
    assert f"](<images/{path.name}>)" in body


def test_cancelled_screenshot_changes_nothing(
    workspace, web01, tmp_path, monkeypatch, capsys
):
    from tacmux.evidence import take_screenshot

    event = workspace.add_event(web01, "WEB01", "success", "proof")
    before = workspace.read(web01)
    _fake_flameshot(tmp_path, monkeypatch, b"")
    assert take_screenshot(workspace, web01, "WEB01", event) is None
    assert workspace.read(web01) == before
    assert "Screenshot cancelled" in capsys.readouterr().out


def test_screenshot_is_deferred_until_the_popup_closes(workspace, web01, monkeypatch):
    from tacmux import evidence

    calls = []
    monkeypatch.setenv("TMUX", "/tmp/sock,1,0")
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(evidence.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        evidence.subprocess, "run", lambda argv, **_kw: calls.append(argv)
    )
    assert evidence.schedule_screenshot(workspace, web01, "WEB01", "E001") is True
    argv = calls[0]
    assert argv[:3] == ["tmux", "run-shell", "-b"]
    assert argv[3].startswith("sleep 0.4; env DISPLAY=:0 ")
    assert argv[3].endswith(f"_internal shot {web01} WEB01 E001")


def test_offer_capture_skips_attached_and_noninteractive(workspace, web01, monkeypatch):
    from tacmux import evidence

    record = _capture(web01)
    monkeypatch.setattr(evidence.shutil, "which", lambda _name: "/usr/bin/cap")
    monkeypatch.setattr(
        "tacmux.workspace.Workspace.inspect_capture", lambda *_a, **_k: record
    )
    monkeypatch.setattr("builtins.input", lambda _prompt: "")
    assert evidence.offer_capture(workspace, web01, "WEB01") == record  # default yes
    monkeypatch.setenv("TACMUX_NONINTERACTIVE", "1")
    assert evidence.offer_capture(workspace, web01, "WEB01") is None
    monkeypatch.delenv("TACMUX_NONINTERACTIVE")
    workspace.add_event(web01, "WEB01", "info", "has it", capture=record)
    assert evidence.offer_capture(workspace, web01, "WEB01") is None


def _cli(monkeypatch, settings, engagement):
    monkeypatch.setenv("TACMUX_WORKSPACE", str(settings.workspace))
    monkeypatch.setenv("TACMUX_CONFIG", str(settings.config_file))
    monkeypatch.delenv("TMUX", raising=False)
    monkeypatch.chdir(engagement / "targets/WEB01")
    from tacmux.cli import main

    return main


def test_done_screenshot_flag_schedules_for_the_new_entry(
    settings, workspace, web01, monkeypatch
):
    main = _cli(monkeypatch, settings, web01)
    scheduled = []
    monkeypatch.setattr(
        "tacmux.evidence.schedule_screenshot",
        lambda _ws, root, target, ident: scheduled.append((root, target, ident)),
    )
    assert main(["done", "-s", "root", "flag"]) == 0
    assert scheduled == [(web01, "WEB01", "E001")]
    assert sitrep.read_events(workspace.read(web01))[-1].summary == "root flag"


def test_palette_attaches_latest_capture_to_a_chosen_entry(
    settings, workspace, web01, monkeypatch
):
    main = _cli(monkeypatch, settings, web01)
    workspace.add_event(web01, "WEB01", "success", "linpeas run")
    record = _capture(web01)
    monkeypatch.setattr("tacmux.evidence.latest_unattached_capture", lambda *_a: record)
    picks = iter(["attach_capture", "E001"])
    monkeypatch.setattr("tacmux.cli.choose", lambda *_a, **_k: next(picks))
    monkeypatch.setattr("tacmux.tmux.TmuxService.sessions", lambda self: [])
    assert main(["menu"]) == 0
    assert sitrep.read_events(workspace.read(web01))[-1].capture_id == "cap-1"


def test_internal_shot_validates_context(
    settings, workspace, web01, monkeypatch, tmp_path
):
    main = _cli(monkeypatch, settings, web01)
    event = workspace.add_event(web01, "WEB01", "success", "proof")
    _fake_flameshot(tmp_path, monkeypatch, PNG)
    assert main(["_internal", "shot", str(web01), "web01", event]) == 0
    assert "images/" in sitrep.read_events(workspace.read(web01))[-1].body
    assert main(["_internal", "shot", str(tmp_path), "WEB01", event]) == 1


# --- 2.2 tm access / 2.3 tm proof -------------------------------------------


def test_access_direct_form_records_everything_in_one_step(
    settings, workspace, web01, monkeypatch, capsys
):
    main = _cli(monkeypatch, settings, web01)
    credential = workspace.add_credential(web01, "admin", "admin", "password")
    args = ["access", "user", "app", "CVE-2021-43857", "RCE", "--via", "http :8000"]
    assert main([*args, "--cred", credential]) == 0
    text = workspace.read(web01)
    details = sitrep.details_map(text, "WEB01")
    assert (details["Access"][0], details["Principal"][0]) == ("user", "app")
    assert details["Method/Path"][0] == "CVE-2021-43857 RCE via http :8000"
    event = sitrep.read_events(text)[-1]
    assert event.summary == "Access: user as app via http :8000 (CVE-2021-43857 RCE)"
    assert (
        "WEB01 · http :8000 · authenticated"
        in sitrep.read_global(text, "CREDENTIALS")[0][5]
    )
    assert "Access none → user" in capsys.readouterr().out
    assert main(["access", "root", "root", "python3.10", "cap_setuid"]) == 0
    assert workspace.target_details(web01, "WEB01")["Access"][0] == "admin"
    assert main(["access", "shell", "app", "again"]) == 0
    assert "Access stays admin" in capsys.readouterr().out


def test_access_fails_fast_without_a_terminal(
    settings, workspace, web01, monkeypatch, capsys
):
    main = _cli(monkeypatch, settings, web01)
    monkeypatch.setenv("TACMUX_NONINTERACTIVE", "1")
    before = workspace.read(web01)
    assert main(["access"]) == 1
    assert "missing access gained" in capsys.readouterr().err
    assert workspace.read(web01) == before


def test_access_interactive_flow_uses_ports_and_credentials(
    settings, workspace, web01, monkeypatch, tmp_path
):
    main = _cli(monkeypatch, settings, web01)
    report = tmp_path / "web.nmap"
    report.write_text("8000/tcp open http WSGIServer 0.2\n")
    assert main(["ports", "add", "WEB01", str(report)]) == 0
    workspace.add_credential(web01, "admin", "admin", "password")
    seen = []

    def fake_choose(choices, prompt, **_kwargs):
        seen.append(prompt)
        answers = {
            "Access gained> ": "user",
            "Via> ": "http :8000",
            "Credential used> ": "C001",
            "C001 itself gives> ": "authenticated",
        }
        return answers[prompt]

    asks = iter(["app", "CVE-2021-43857 RCE"])
    monkeypatch.setattr("tacmux.cli.choose", fake_choose)
    monkeypatch.setattr("tacmux.cli.ask", lambda *_a, **_k: next(asks))
    monkeypatch.setattr("tacmux.cli.confirm", lambda *_a, **_k: False)
    monkeypatch.setattr("tacmux.evidence.offer_capture", lambda *_a: None)
    assert main(["access"]) == 0
    text = workspace.read(web01)
    assert seen == [
        "Access gained> ",
        "Via> ",
        "Credential used> ",
        "C001 itself gives> ",
    ]
    assert sitrep.details_map(text, "WEB01")["Access"][0] == "user"
    assert (
        "WEB01 · http :8000 · authenticated"
        in sitrep.read_global(text, "CREDENTIALS")[0][5]
    )


def test_proof_direct_form_infers_path_and_never_raises_access(
    settings, workspace, web01, monkeypatch, capsys
):
    main = _cli(monkeypatch, settings, web01)
    principal = "app"
    workspace.set_target_detail(web01, "WEB01", "Principal", principal)
    assert main(["proof", "u", "9a1d4ff100f424aa5d2f66366b365495"]) == 0
    event = sitrep.read_events(workspace.read(web01))[-1]
    expected = f"user flag /home/{principal}/local.txt 9a1d4ff100f424aa5d2f66366b365495"
    assert event.summary == expected
    assert workspace.target_details(web01, "WEB01")["Access"][0] == "none"
    assert "hint: Access is none" in capsys.readouterr().out
    assert main(["flag", "root", "49d8", "/root/proof.txt"]) == 0
    assert (
        sitrep.read_events(workspace.read(web01))[-1].summary
        == "root flag /root/proof.txt 49d8"
    )


def test_proof_interactive_asks_before_raising_and_can_show_in_pane(
    settings, workspace, web01, monkeypatch
):
    main = _cli(monkeypatch, settings, web01)
    sent, scheduled = [], []
    monkeypatch.setenv("TMUX_PANE", "%3")
    monkeypatch.setattr(
        "tacmux.tmux.TmuxService.run",
        lambda self, args, **_k: sent.append(args)
        or __import__("subprocess").CompletedProcess(args, 0, "", ""),
    )
    picks = iter(["root", "/root/proof.txt"])
    monkeypatch.setattr("tacmux.cli.choose", lambda *_a, **_k: next(picks))
    monkeypatch.setattr("tacmux.cli.ask", lambda *_a, **_k: "49d89584")
    monkeypatch.setattr("tacmux.cli.confirm", lambda *_a, **_k: True)
    monkeypatch.setattr("tacmux.evidence.offer_capture", lambda *_a: None)
    monkeypatch.setattr(
        "tacmux.evidence.schedule_screenshot",
        lambda _ws, _root, _target, ident, delay="0.4": scheduled.append(
            (ident, delay)
        ),
    )
    assert main(["proof"]) == 0
    assert workspace.target_details(web01, "WEB01")["Access"][0] == "admin"
    assert sent[0] == [
        "send-keys",
        "-t",
        "%3",
        "-l",
        "hostname; whoami; ip a; cat /root/proof.txt",
    ]
    assert scheduled == [("E001", "1.5")]


# --- 2.6 tm close --------------------------------------------------------------


@pytest.fixture
def fake_sessions(monkeypatch):
    """Live sessions and pane programs keyed by target ('' = OPS)."""
    state = {
        "live": {"", "WEB01"},
        "panes": {},
        "stopped": [],
        "snapped": [],
        "inside": None,
    }
    monkeypatch.setattr(
        "tacmux.tmux.TmuxService.target_running",
        lambda self, root, target: target in state["live"],
    )
    monkeypatch.setattr(
        "tacmux.tmux.TmuxService.session_name",
        lambda self, root, target="": f"s-{target or 'ops'}",
    )
    monkeypatch.setattr(
        "tacmux.tmux.TmuxService.panes",
        lambda self, name: state["panes"].get(name, [("%1", "zsh")]),
    )

    def stop(self, root, target=""):
        state["stopped"].append(target)
        state["live"].discard(target)

    monkeypatch.setattr("tacmux.tmux.TmuxService.stop", stop)
    monkeypatch.setattr(
        "tacmux.tmux.TmuxService.current_context",
        lambda self: (state["inside"][0], state["inside"][1])
        if state["inside"]
        else (None, ""),
    )
    monkeypatch.setattr(
        "tacmux.cli._snapshot",
        lambda _s, _w, _t, _root, target, shells=True: state["snapped"].append(target)
        or ([], []),
    )
    return state


def test_close_yes_completes_snapshots_and_stops(
    settings, workspace, web01, monkeypatch, fake_sessions, capsys
):
    main = _cli(monkeypatch, settings, web01)
    assert main(["close", "--yes", "--no-stop"]) == 0
    assert workspace.target_details(web01, "WEB01")["Status"][0] == "complete"
    assert fake_sessions["snapped"] == ["WEB01"] and fake_sessions["stopped"] == []
    fake_sessions["panes"]["s-WEB01"] = [("%1", "zsh"), ("%2", "penelope")]
    assert main(["close", "--yes"]) == 0
    assert fake_sessions["stopped"] == ["WEB01"]
    assert "running programs: %2 penelope" in capsys.readouterr().out


def test_close_interactive_checklist_fixes_cleanup_and_keeps_busy_sessions(
    settings, workspace, web01, monkeypatch, fake_sessions
):
    main = _cli(monkeypatch, settings, web01)
    workspace.add_cleanup(web01, "WEB01", "Gerapy project evil_project")
    fake_sessions["panes"]["s-WEB01"] = [("%2", "penelope")]
    shown = []

    def fake_choose(choices, prompt, **_kwargs):
        shown.append([display for display, *_ in choices])
        if prompt.startswith("Close WEB01"):
            return "cleanup" if len(shown) == 1 else "continue"
        if prompt.startswith("Complete"):
            return "X001"
        return "complete"  # Status>

    monkeypatch.setattr("tacmux.cli.choose", fake_choose)
    monkeypatch.setattr("tacmux.cli.ask", lambda *_a, **_k: "Rooted via cap_setuid")
    monkeypatch.setattr("tacmux.cli.confirm", lambda *_a, **_k: False)
    assert main(["close"]) == 0
    assert any("Cleanup X001" in line and "release gate" in line for line in shown[0])
    assert any("Access none" in line for line in shown[0])
    text = workspace.read(web01)
    assert sitrep.read_tasks(text, "CLEANUP")[0].complete
    assert sitrep.read_events(text)[-1].summary == "Rooted via cap_setuid"
    assert fake_sessions["stopped"] == []  # penelope still running → kept


def test_engagement_close_stops_the_invoking_session_last(
    settings, workspace, web01, monkeypatch, fake_sessions
):
    main = _cli(monkeypatch, settings, web01)
    workspace.add_target(web01, "DC01", "192.0.2.20")
    fake_sessions["live"] = {"", "WEB01", "DC01"}
    fake_sessions["inside"] = (web01, "WEB01")
    assert main(["close", "--engagement", "--yes"]) == 0
    assert fake_sessions["stopped"] == ["DC01", "", "WEB01"]
    assert fake_sessions["snapped"] == ["DC01", "WEB01", ""]


def test_access_credential_level_can_be_stated(settings, workspace, web01, monkeypatch):
    main = _cli(monkeypatch, settings, web01)
    credential = workspace.add_credential(web01, "app", "pw", "password")
    assert (
        main(
            [
                "access",
                "user",
                "app",
                "ssh",
                "login",
                "--via",
                "ssh :22",
                "--cred",
                f"{credential}:shell",
            ]
        )
        == 0
    )
    assert (
        "WEB01 · ssh :22 · user"
        in sitrep.read_global(workspace.read(web01), "CREDENTIALS")[0][5]
    )
    assert main(["access", "user", "app", "x", "--cred", "WEB01"]) == 1


def test_close_yes_reminds_about_open_cleanup(
    settings, workspace, web01, monkeypatch, fake_sessions, capsys
):
    main = _cli(monkeypatch, settings, web01)
    workspace.add_cleanup(web01, "WEB01", "Remove larkspur-assessment-check.txt")
    assert main(["close", "--yes"]) == 0
    out = capsys.readouterr().out
    reminder = out.index("Reminder: 1 cleanup item(s) still open on WEB01")
    assert "X001  Remove larkspur-assessment-check.txt" in out[reminder:]
    assert reminder < out.index("Stopping WEB01")


def test_rename_inside_its_own_session_says_where_to_stop_it(
    settings, workspace, web01, monkeypatch, capsys
):
    main = _cli(monkeypatch, settings, web01)
    monkeypatch.setattr("tacmux.tmux.TmuxService.target_running", lambda *_a: True)
    monkeypatch.setattr(
        "tacmux.tmux.TmuxService.current_context", lambda self: (web01, "WEB01")
    )
    assert main(["target", "rename", "WEB01", "WEB02"]) == 1
    err = capsys.readouterr().err
    assert "stop WEB01 first from OPS or another shell" in err
    monkeypatch.setattr(
        "tacmux.tmux.TmuxService.current_context", lambda self: (web01, "")
    )
    assert main(["target", "rename", "WEB01", "WEB02"]) == 1
    assert "stop WEB01 first with: tacmux stop WEB01" in capsys.readouterr().err


def test_snapshots_skip_panes_with_logging_turned_off(
    settings, workspace, web01, monkeypatch, capsys
):
    from tacmux.cli import _snapshot
    from tacmux.tmux import TmuxService

    captured = []
    monkeypatch.setattr("tacmux.tmux.TmuxService.has_session", lambda self, name: True)
    monkeypatch.setattr(
        "tacmux.tmux.TmuxService.panes",
        lambda self, name: [("%1", "zsh"), ("%2", "zsh"), ("%3", "penelope")],
    )
    monkeypatch.setattr(
        "tacmux.tmux.TmuxService.logging_panes", lambda self, name: {"%1", "%3"}
    )
    monkeypatch.setattr(
        "tacmux.hooks.LogController.capture",
        lambda self, pane: captured.append(pane) or web01 / "logs/x.log",
    )
    saved, _ = _snapshot(settings, workspace, TmuxService(settings), web01, "WEB01")
    assert captured == ["%1", "%3"] and len(saved) == 2
    assert "Skipped 1 pane(s) with logging off" in capsys.readouterr().out


def test_logging_panes_reads_pane_pipe(settings, monkeypatch):
    import subprocess

    from tacmux.tmux import TmuxService

    tmux = TmuxService(settings)
    monkeypatch.setattr(
        tmux,
        "run",
        lambda args, **_k: subprocess.CompletedProcess(
            args, 0, "%1\t1\n%2\t0\n%3\t1\n", ""
        ),
    )
    assert tmux.logging_panes("s") == {"%1", "%3"}


# --- 3.2.3: terminal messages and undo labels -------------------------------


def test_editor_without_terminal_names_the_real_requirement(
    settings, monkeypatch, tmp_path
):
    from tacmux.errors import NonInteractiveError
    from tacmux.interaction import open_editor

    monkeypatch.setattr("tacmux.interaction.text_input_available", lambda: False)
    with pytest.raises(
        NonInteractiveError,
        match=r"opens \$EDITOR, which needs an interactive terminal",
    ):
        open_editor(settings, tmp_path / "SITREP.md")


def test_discover_without_terminal_fails_before_reading_or_scanning(
    settings, workspace, web01, monkeypatch, capsys
):
    main = _cli(monkeypatch, settings, web01)
    monkeypatch.setattr("tacmux.interaction.text_input_available", lambda: False)

    def must_not_run(*_args, **_kwargs):
        raise AssertionError("discovery read input or scanned without a terminal")

    monkeypatch.setattr("tacmux.cli._input_text", must_not_run)
    monkeypatch.setattr("tacmux.cli.run_host_discovery", must_not_run)
    for argv in (["discover", "hosts"], ["discover", "nmap", "192.0.2.0/24"]):
        assert main(argv) == 1
        assert (
            "paste the hosts into the editor, or pass a FILE" in capsys.readouterr().err
        )
    assert workspace.targets(web01) == ["WEB01"]


def test_discover_from_a_terminal_with_a_file_still_creates_targets(
    settings, workspace, web01, monkeypatch, tmp_path, capsys
):
    main = _cli(monkeypatch, settings, web01)
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("DC01 192.0.2.20\n")
    monkeypatch.setattr(
        "tacmux.cli.review_candidates", lambda _s, candidates: candidates
    )
    monkeypatch.setattr("tacmux.discovery.confirm", lambda *_a, **_k: True)
    assert main(["discover", "hosts", str(hosts)]) == 0
    assert "DC01" in workspace.targets(web01)


def test_undo_labels_name_screenshots_captures_and_hostnames(
    settings, workspace, web01, monkeypatch, tmp_path
):
    from tacmux.evidence import take_screenshot

    main = _cli(monkeypatch, settings, web01)
    event = workspace.add_event(web01, "WEB01", "success", "proof")
    _fake_flameshot(tmp_path, monkeypatch, PNG)
    take_screenshot(workspace, web01, "WEB01", event)
    assert workspace.last_change(web01)[1]["label"] == f"screenshot → {event}"

    record = _capture(web01)
    monkeypatch.setattr("tacmux.evidence.latest_unattached_capture", lambda *_a: record)
    picks = iter(["attach_capture", event])
    monkeypatch.setattr("tacmux.cli.choose", lambda *_a, **_k: next(picks))
    monkeypatch.setattr("tacmux.tmux.TmuxService.sessions", lambda self: [])
    assert main(["menu"]) == 0
    assert workspace.last_change(web01)[1]["label"] == f"capture cap-1 → {event}"

    picks = iter(["hostname"])
    monkeypatch.setattr("tacmux.cli.choose", lambda *_a, **_k: next(picks))
    monkeypatch.setattr("tacmux.cli.ask", lambda *_a, **_k: "web01.example")
    monkeypatch.setattr("tacmux.cli.clipboard_copy", lambda *_a: 0)
    assert main(["menu"]) == 0
    assert workspace.last_change(web01)[1]["label"] == "hostname web01.example → WEB01"
