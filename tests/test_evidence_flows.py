"""TACMUX 3.2 foundation: one-step access records and evidence attached later."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import subprocess

import pytest

from tacmux import sitrep
from tacmux.errors import ConflictError, ValidationError
from tacmux.tmux import PaneInfo
from tacmux.workspace import CaptureRecord, Workspace

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


def test_attach_screenshot_adds_one_section(workspace, web01, tmp_path):
    capture = _capture(web01)
    event = workspace.add_event(web01, "WEB01", "success", "Shell", capture=capture)
    assert "_Not attached._" not in workspace.read(web01)
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


def test_stop_renders_readable_logs_before_killing(
    settings, workspace, engagement, monkeypatch, capsys
):
    from tacmux.cli import main

    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    day = engagement / "logs/20260101"
    day.mkdir(parents=True)
    raw = day / "WEB01_WEB01_host_p1_000000_000000.log"
    raw.write_bytes(
        b"=== TACMUX pane log ===\nSession: s\nTarget: WEB01\nPane: %1\n\n"
        b"scan 10%\rscan 100%\r\n"
    )
    other = day / "ENGAGEMENT_OPS_host_p1_000000_000001.log"
    other.write_bytes(b"=== TACMUX pane log ===\nTarget: ENGAGEMENT\n\nops\r\n")
    monkeypatch.setenv("TACMUX_WORKSPACE", str(settings.workspace))
    monkeypatch.setenv("TACMUX_CONFIG", str(settings.config_file))
    monkeypatch.chdir(engagement / "targets/WEB01")
    order = []
    monkeypatch.setattr("tacmux.tmux.TmuxService.has_session", lambda self, name: True)
    monkeypatch.setattr(
        "tacmux.tmux.TmuxService.stop",
        lambda self, root, target="": order.append(
            ("stop", target, raw.with_suffix(".txt").exists())
        ),
    )
    assert main(["stop"]) == 0
    assert order == [("stop", "WEB01", True)]
    assert "scan 100%" in raw.with_suffix(".txt").read_text()
    assert "scan 10%" not in raw.with_suffix(".txt").read_text()
    assert not other.with_suffix(".txt").exists()
    assert "Readable logs  1" in capsys.readouterr().out


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
    monkeypatch.setattr(evidence, "_SCHEDULED", False)
    monkeypatch.setenv("TMUX", "/tmp/sock,1,0")
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(evidence.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        evidence.subprocess,
        "run",
        lambda argv, **_kw: calls.append(argv)
        or subprocess.CompletedProcess(argv, 0, "", ""),
    )
    assert evidence.schedule_screenshot(workspace, web01, "WEB01", "E001") is True
    argv = calls[0]
    assert argv[:3] == ["tmux", "run-shell", "-b"]
    assert argv[3].startswith("sleep 0.4; env DISPLAY=:0 ")
    assert argv[3].endswith(f"_internal shot {web01} WEB01 E001")
    assert evidence.screenshot_scheduled()


@pytest.mark.parametrize("captured", [False, True])
def test_synchronous_screenshot_runs_followup_only_after_capture(
    workspace, web01, monkeypatch, captured
):
    from tacmux import evidence

    monkeypatch.setattr(evidence.shutil, "which", lambda name: f"/mock/{name}")
    monkeypatch.setattr(evidence, "_SCHEDULED", False)
    order = []

    def shot(*_args):
        order.append("capture completed")
        return Path("proof.png") if captured else None

    def follow(argv, **_kwargs):
        order.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(evidence, "take_screenshot", shot)
    monkeypatch.setattr(evidence.subprocess, "run", follow)
    assert (
        evidence.schedule_screenshot(
            workspace, web01, "WEB01", "E001", then=["follow-up", "WEB01"]
        )
        is captured
    )
    assert order == ["capture completed", ["follow-up", "WEB01"]]
    assert not evidence.screenshot_scheduled()


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
    assert event.summary == "Access: user as app"
    assert event.body == "via http :8000 — CVE-2021-43857 RCE"
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
    monkeypatch.setattr("tacmux.cli.confirm", lambda *_a, **_k: False)  # no shot
    workspace.set_target_detail(web01, "WEB01", "Principal", principal)
    workspace.set_target_detail(web01, "WEB01", "OS", "Linux")
    assert main(["proof", "u", "9a1d4ff100f424aa5d2f66366b365495"]) == 0
    event = sitrep.read_events(workspace.read(web01))[-1]
    assert event.summary == "User flag (local.txt)"
    assert "9a1d4ff100f424aa5d2f66366b365495\n```" in event.body
    assert f"/home/{principal}/local.txt" in event.body
    assert workspace.target_details(web01, "WEB01")["Access"][0] == "none"
    assert "hint: Access is none" in capsys.readouterr().out
    assert main(["flag", "root", "49d8", "/root/proof.txt"]) == 0
    assert (
        sitrep.read_events(workspace.read(web01))[-1].summary == "Root flag (proof.txt)"
    )


def test_proof_interactive_asks_before_raising_and_can_show_in_pane(
    settings, workspace, web01, monkeypatch
):
    main = _cli(monkeypatch, settings, web01)
    workspace.set_target_detail(web01, "WEB01", "OS", "Linux")
    sent, scheduled = [], []
    monkeypatch.setattr(
        "tacmux.tmux.TmuxService.run",
        lambda self, args, **_k: sent.append(args)
        or __import__("subprocess").CompletedProcess(args, 0, "", ""),
    )
    monkeypatch.setattr(
        "tacmux.tmux.TmuxService.pane_info",
        lambda self, name: [
            PaneInfo("%1", "zsh", "1.1", "", False, 5),
            PaneInfo("%3", "penelope", "1.2", "", False, 5),
            PaneInfo("%4", "nvim", "1.3", "", False, 5),
        ],
    )
    monkeypatch.setattr("tacmux.tmux.TmuxService.pane_tail", lambda self, pane: [])
    offered = []

    def fake_choose(choices, prompt, **_kwargs):
        if prompt == "Show proof in pane> ":
            offered.extend(value for _display, value, *_ in choices)
            return "%3"
        return {"Proof> ": "root", "Path> ": "/root/proof.txt"}[prompt]

    monkeypatch.setattr("tacmux.cli.choose", fake_choose)
    monkeypatch.setattr(
        "tacmux.cli.ask",
        lambda label, *_a, **_k: "" if label.startswith("How") else "49d89584",
    )
    monkeypatch.setattr(
        "tacmux.cli.confirm", lambda prompt, **_k: not prompt.startswith("Close out")
    )
    monkeypatch.setattr("tacmux.evidence.offer_capture", lambda *_a: None)
    monkeypatch.setattr(
        "tacmux.evidence.schedule_screenshot",
        lambda _ws, _root, _target, ident, delay="0.4", **_k: scheduled.append(
            (ident, delay)
        ),
    )
    assert main(["proof"]) == 0
    assert workspace.target_details(web01, "WEB01")["Access"][0] == "admin"
    assert offered[:2] == ["%3", "%4"] and "%1" not in offered  # never a local shell
    assert sent[0] == [
        "send-keys",
        "-t",
        "%3",
        "-l",
        "hostname; whoami; ip a; cat /root/proof.txt",
    ]
    assert scheduled == [("E001", "1.5")]


def _picker(monkeypatch, panes, tails):
    from tacmux.cli import _choose_shell_pane
    from tacmux.tmux import TmuxService

    monkeypatch.setattr(TmuxService, "session_name", lambda self, root, target="": "s")
    monkeypatch.setattr(TmuxService, "pane_info", lambda self, name: panes)
    monkeypatch.setattr(
        TmuxService, "pane_tail", lambda self, pane: tails.get(pane, [])
    )
    seen = {}

    def fake_choose(choices, prompt, **kwargs):
        seen["choices"], seen["default"] = choices, kwargs.get("default")
        return kwargs.get("default", "")

    monkeypatch.setattr("tacmux.cli.choose", fake_choose)
    tmux = TmuxService.__new__(TmuxService)
    return _choose_shell_pane(tmux, Path("."), "T"), seen


def test_proof_picker_labels_panes_and_hides_the_invoking_pane(monkeypatch):
    panes = [
        PaneInfo("%2", "python", "1.1", "", False, 10),
        PaneInfo("%5", "python", "1.2", "", False, 10),  # tm proof runs here
        PaneInfo("%6", "python", "1.3", "root-shell", True, 10),
    ]
    tails = {
        "%2": ["kali@kali:~/exploits$ python exploit.py"],
        "%6": ["uid=0(root)", "root@exfiltrated:~# "],
    }
    monkeypatch.setenv("TMUX_PANE", "%5")
    monkeypatch.delenv("TACMUX_POPUP", raising=False)
    chosen, seen = _picker(monkeypatch, panes, tails)
    values = [value for _label, value, *_ in seen["choices"]]
    assert "%5" not in values  # never the pane running tm proof
    assert chosen == "%6" and seen["default"] == "%6"  # the pane you came from
    assert seen["choices"][0][0] == "1.3  python  root-shell  root@exfiltrated:~#"
    assert seen["choices"][0][2] == "uid=0(root)\\nroot@exfiltrated:~# "


def test_proof_picker_from_popup_prefers_the_pane_it_opened_from(monkeypatch):
    panes = [
        PaneInfo("%3", "python", "1.1", "", False, 10),
        PaneInfo("%4", "python", "1.2", "", True, 10),
    ]
    monkeypatch.setenv("TMUX_PANE", "%3")
    monkeypatch.setenv("TACMUX_POPUP", "1")
    chosen, seen = _picker(monkeypatch, panes, {})
    assert chosen == "%3"
    assert [value for _l, value, *_ in seen["choices"]] == ["%3", "%4", ""]


def test_proof_picker_preview_escapes_backslashes():
    from tacmux.cli import _preview_text

    assert _preview_text(["C:\\Users\\a>", "x"]) == "C:\\\\Users\\\\a>\\nx"


def test_pane_info_parses_list_panes(monkeypatch, settings):
    from subprocess import CompletedProcess

    from tacmux.tmux import TmuxService

    out = "%1\tzsh\t1.1\t\t0\t100\n%6\tpython\t1.3\troot-shell\t1\t200\nbad\n"
    monkeypatch.setattr(
        TmuxService, "run", lambda self, args, **_k: CompletedProcess(args, 0, out, "")
    )
    assert TmuxService(settings).pane_info("s") == [
        PaneInfo("%1", "zsh", "1.1", "", False, 100),
        PaneInfo("%6", "python", "1.3", "root-shell", True, 200),
    ]


def _root_proof(monkeypatch, *, how="", close=False, popup=False, shot=True):
    calls = {"closed": [], "scheduled": [], "waited": []}
    monkeypatch.setattr(
        "tacmux.cli.ask",
        lambda label, *_a, **_k: how if label.startswith("How") else "49d89584",
    )

    def fake_confirm(prompt, **_k):
        if prompt.startswith("Close out"):
            return close
        if prompt.startswith("Take the proof screenshot"):
            return shot
        return not prompt.startswith("Show the proof")

    monkeypatch.setattr("tacmux.cli.confirm", fake_confirm)
    monkeypatch.setattr(
        "tacmux.cli.choose",
        lambda _c, prompt, **_k: {"Proof> ": "root", "Path> ": "/root/proof.txt"}[
            prompt
        ],
    )
    monkeypatch.setattr("tacmux.evidence.offer_capture", lambda *_a: None)

    def fake_schedule(_ws, _root, _target, ident, delay="0.4", then=None, wait=False):
        calls["scheduled"].append(then)
        calls["waited"].append(wait)
        return True

    monkeypatch.setattr("tacmux.evidence.schedule_screenshot", fake_schedule)
    monkeypatch.setattr(
        "tacmux.cli._close_command",
        lambda _s, _w, _t, args: calls["closed"].append(list(args)) or 0,
    )
    if popup:
        monkeypatch.setenv("TACMUX_POPUP", "1")
        monkeypatch.setenv("TACMUX_CLIENT", "/dev/pts/3")
        monkeypatch.setenv("TMUX_PANE", "%2")
    return calls


def test_proof_raise_records_how_when_given(settings, workspace, web01, monkeypatch):
    main = _cli(monkeypatch, settings, web01)
    workspace.set_target_detail(web01, "WEB01", "OS", "Linux")
    _root_proof(monkeypatch, how="exiftool root cron (CVE-2021-22204)")
    assert main(["proof"]) == 0
    details = workspace.target_details(web01, "WEB01")
    assert (details["Access"][0], details["Principal"][0]) == ("admin", "root")
    assert details["Method/Path"][0] == "exiftool root cron (CVE-2021-22204)"


def test_root_proof_offers_close_out_in_a_terminal(
    settings, workspace, web01, monkeypatch
):
    main = _cli(monkeypatch, settings, web01)
    workspace.set_target_detail(web01, "WEB01", "OS", "Linux")
    calls = _root_proof(monkeypatch, close=True)
    assert main(["proof"]) == 0
    assert calls["scheduled"] == [None]  # nothing chained outside a popup
    assert calls["waited"] == [True]
    assert calls["closed"] == [["WEB01"]]


def test_root_proof_close_out_follows_the_shot_from_the_popup(
    settings, workspace, web01, monkeypatch, capsys
):
    main = _cli(monkeypatch, settings, web01)
    workspace.set_target_detail(web01, "WEB01", "OS", "Linux")
    calls = _root_proof(monkeypatch, close=True, popup=True)
    assert main(["proof"]) == 0
    assert calls["closed"] == []  # the popup must close before the shot
    assert calls["waited"] == [False]
    (follow,) = calls["scheduled"]
    assert follow[:3] == ["tmux", "display-popup", "-E"]
    assert ["-c", "/dev/pts/3"] == follow[3:5] and follow[-2:][1] == "WEB01"
    assert '"$0" close "$1"' in follow[-3]
    assert "opens after the screenshot" in capsys.readouterr().out


def test_root_proof_close_out_runs_now_without_a_screenshot(
    settings, workspace, web01, monkeypatch
):
    main = _cli(monkeypatch, settings, web01)
    workspace.set_target_detail(web01, "WEB01", "OS", "Linux")
    calls = _root_proof(monkeypatch, close=True, popup=True, shot=False)
    assert main(["proof"]) == 0
    assert calls["scheduled"] == [] and calls["closed"] == [["WEB01"]]


@pytest.mark.parametrize("in_tmux", [False, True])
@pytest.mark.parametrize("captured", [False, True])
def test_terminal_proof_finishes_screenshot_before_close(
    settings, workspace, web01, monkeypatch, in_tmux, captured
):
    from tacmux import evidence
    from tacmux.context import Context

    main = _cli(monkeypatch, settings, web01)
    workspace.set_target_detail(web01, "WEB01", "OS", "Linux")
    real_schedule = evidence.schedule_screenshot
    _root_proof(monkeypatch, close=True)
    monkeypatch.setattr(evidence, "schedule_screenshot", real_schedule)
    monkeypatch.setattr(evidence, "_SCHEDULED", False)
    monkeypatch.setattr(evidence.shutil, "which", lambda name: f"/mock/{name}")
    monkeypatch.setattr("tacmux.cli.resolve", lambda *_a, **_k: Context(web01, "WEB01"))
    monkeypatch.setattr("tacmux.cli._collect_shells", lambda *_a: [])
    if in_tmux:
        monkeypatch.setenv("TMUX", "/tmp/test.sock,1,0")
    order, delays = [], []
    monkeypatch.setattr("time.sleep", delays.append)

    def take_shot(*_args):
        order.append("screenshot finished")
        return web01 / "targets/WEB01/screenshots/proof.png" if captured else None

    def queued(argv, **_kwargs):
        order.append("screenshot queued")
        return subprocess.CompletedProcess(argv, 0, "", "")

    def close(*_args):
        order.append("close entered")
        return 0

    monkeypatch.setattr(evidence, "take_screenshot", take_shot)
    monkeypatch.setattr(evidence.subprocess, "run", queued)
    monkeypatch.setattr("tacmux.cli._close_command", close)
    assert main(["proof"]) == 0
    assert order == ["screenshot finished", "close entered"]
    assert delays == [0.4]
    assert not evidence.screenshot_scheduled()


@pytest.mark.parametrize("failure", ["exit", "missing-executable"])
def test_failed_screenshot_queue_keeps_popup_close_fallback(
    settings, workspace, web01, monkeypatch, capsys, failure
):
    from tacmux import evidence
    from tacmux.context import Context

    main = _cli(monkeypatch, settings, web01)
    workspace.set_target_detail(web01, "WEB01", "OS", "Linux")
    real_schedule = evidence.schedule_screenshot
    calls = _root_proof(monkeypatch, close=True, popup=True)
    monkeypatch.setenv("TMUX", "/tmp/test.sock,1,0")
    monkeypatch.setattr("tacmux.cli.resolve", lambda *_a, **_k: Context(web01, "WEB01"))
    monkeypatch.setattr("tacmux.cli._collect_shells", lambda *_a: [])
    monkeypatch.setattr(evidence, "schedule_screenshot", real_schedule)
    monkeypatch.setattr(evidence, "_SCHEDULED", False)
    monkeypatch.setattr(evidence.shutil, "which", lambda name: f"/mock/{name}")

    def fail_queue(argv, **_kwargs):
        if failure == "missing-executable":
            raise FileNotFoundError("tmux disappeared")
        return subprocess.CompletedProcess(argv, 1, "", "tmux rejected screenshot job")

    monkeypatch.setattr(evidence.subprocess, "run", fail_queue)
    assert main(["proof"]) == 0
    assert calls["closed"] == [["WEB01"]]
    assert not evidence.screenshot_scheduled()
    captured = capsys.readouterr()
    assert "could not schedule screenshot" in captured.err
    assert "opens after the screenshot" not in captured.out
    assert "select a region" not in captured.out


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
    rendered = []
    monkeypatch.setattr(
        "tacmux.render.refresh_readable",
        lambda root, target=None: rendered.append(
            (target, list(fake_sessions["stopped"]))
        )
        or [],
    )
    assert main(["close", "--engagement", "--yes"]) == 0
    assert fake_sessions["stopped"] == ["DC01", "", "WEB01"]
    # Every pane log of the engagement is rendered once, before any stop.
    assert rendered == [(None, [])]


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


def test_automatic_snapshot_never_captures_scrollback(
    settings, workspace, web01, monkeypatch
):
    """Readable copies come from raw logs only; an off→on toggle cannot leak."""
    from tacmux.cli import _snapshot
    from tacmux.tmux import TmuxService

    monkeypatch.setattr(
        "tacmux.hooks.LogController.capture",
        lambda self, pane: pytest.fail("automatic snapshot must not capture-pane"),
    )
    saved, _ = _snapshot(settings, workspace, TmuxService(settings), web01, "WEB01")
    assert saved == []


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


# --- 3.3.0 -----------------------------------------------------------------------


def test_popup_closes_immediately_when_a_screenshot_is_pending(monkeypatch):
    from tacmux import cli, evidence

    monkeypatch.setenv("TACMUX_POPUP", "1")
    monkeypatch.setattr(evidence, "_SCHEDULED", True)
    monkeypatch.setattr(
        "builtins.input", lambda *_a: (_ for _ in ()).throw(AssertionError("waited"))
    )
    cli._wait_in_popup()  # must return without waiting for Enter


def test_windows_proof_line_works_in_cmd_and_powershell(
    settings, workspace, web01, monkeypatch
):
    main = _cli(monkeypatch, settings, web01)
    workspace.set_target_detail(web01, "WEB01", "OS", "Windows")
    sent = []
    monkeypatch.setattr(
        "tacmux.tmux.TmuxService.run",
        lambda self, args, **_k: sent.append(args)
        or __import__("subprocess").CompletedProcess(args, 0, "", ""),
    )
    monkeypatch.setattr(
        "tacmux.tmux.TmuxService.pane_info",
        lambda self, name: [PaneInfo("%2", "evil-winrm", "1.2", "", False, 5)],
    )
    monkeypatch.setattr("tacmux.tmux.TmuxService.pane_tail", lambda self, pane: [])
    monkeypatch.setattr("tacmux.cli.choose", lambda *_a, **_k: "%2")
    monkeypatch.setattr("tacmux.cli.confirm", lambda *_a, **_k: False)
    assert main(["proof", "root", "abc123", "--show"]) == 0
    assert sent[0][-1] == (
        'cmd /c "hostname & whoami & ipconfig & type '
        'C:\\Users\\Administrator\\Desktop\\proof.txt"'
    )


def test_show_without_a_remote_shell_pane_sends_nothing(
    settings, workspace, web01, monkeypatch, capsys
):
    main = _cli(monkeypatch, settings, web01)
    workspace.set_target_detail(web01, "WEB01", "OS", "Linux")
    sent = []
    monkeypatch.setattr(
        "tacmux.tmux.TmuxService.run", lambda self, args, **_k: sent.append(args)
    )
    monkeypatch.setattr(
        "tacmux.tmux.TmuxService.pane_info",
        lambda self, name: [PaneInfo("%1", "zsh", "1.1", "", False, 5)],
    )
    monkeypatch.setattr("tacmux.cli.confirm", lambda *_a, **_k: False)
    assert main(["proof", "user", "abc", "--show"]) == 0
    assert sent == [] and "runs a remote shell" in capsys.readouterr().out


def test_direct_proof_offers_the_screenshot_at_a_terminal(
    settings, workspace, web01, monkeypatch
):
    main = _cli(monkeypatch, settings, web01)
    scheduled = []
    monkeypatch.setattr("tacmux.cli.confirm", lambda *_a, **_k: True)
    monkeypatch.setattr(
        "tacmux.evidence.schedule_screenshot",
        lambda _ws, _root, _target, ident, delay="0.4", **_k: scheduled.append(ident),
    )
    assert main(["proof", "user", "9a1d"]) == 0
    assert scheduled == ["E001"]
    monkeypatch.setenv("TACMUX_NONINTERACTIVE", "1")  # agents never get a shot
    assert main(["proof", "root", "49d8"]) == 0
    assert scheduled == ["E001"]


def test_proof_paths_are_full_paths_for_htb_style_flags():
    from tacmux.cli import _proof_paths

    principal = "app"
    home = f"/home/{principal}"
    linux = {"OS": ("Linux", ""), "Principal": (principal, "")}
    assert _proof_paths("user", linux) == [
        f"{home}/local.txt",
        "/root/proof.txt",
        f"{home}/user.txt",
        "/root/root.txt",
    ]


def test_quoted_text_starting_with_a_dash_is_logged(
    settings, workspace, web01, monkeypatch, capsys
):
    main = _cli(monkeypatch, settings, web01)
    assert main(["fail", "-sC scan timed out"]) == 0
    assert sitrep.read_events(workspace.read(web01))[-1].summary == "-sC scan timed out"
    assert main(["fail", "-sC"]) == 1
    assert "unknown option -sC" in capsys.readouterr().err


def test_service_names_match_ports_in_any_case(
    settings, workspace, web01, monkeypatch, tmp_path
):
    main = _cli(monkeypatch, settings, web01)
    report = tmp_path / "web.nmap"
    report.write_text("8000/tcp open http WSGIServer\n")
    assert main(["ports", "add", "WEB01", str(report)]) == 0
    credential = workspace.add_credential(web01, "a", "b", "password")
    assert main(["creds", "confirm", credential, "auth", "HTTP"]) == 0
    assert (
        "WEB01 · http :8000 · authenticated"
        in sitrep.read_global(workspace.read(web01), "CREDENTIALS")[0][5]
    )


def test_new_endpoint_restarts_a_running_session_from_ops(
    settings, workspace, web01, monkeypatch, capsys
):
    main = _cli(monkeypatch, settings, web01)
    monkeypatch.chdir(web01)  # OPS-style context, not inside WEB01
    workspace.set_target_detail(web01, "WEB01", "Hostnames", "web01.example")
    order = []
    monkeypatch.setattr("tacmux.tmux.TmuxService.target_running", lambda *_a: True)
    monkeypatch.setattr(
        "tacmux.tmux.TmuxService.current_context", lambda self: (None, "")
    )
    monkeypatch.setattr("tacmux.cli.confirm", lambda *_a, **_k: True)
    monkeypatch.setattr(
        "tacmux.cli._snapshot", lambda *_a, **_k: order.append("snap") or ([], [])
    )
    monkeypatch.setattr(
        "tacmux.tmux.TmuxService.stop",
        lambda self, root, target="": order.append("stop"),
    )
    monkeypatch.setattr(
        "tacmux.tmux.TmuxService.start",
        lambda self, root, target="": order.append(
            ("start", workspace.target_details(root, target)["Endpoint"][0])
        ),
    )
    monkeypatch.setattr("tacmux.cli.clipboard_copy", lambda *_a: 0)
    assert main(["target", "update", "WEB01", "endpoint", "192.0.2.99"]) == 0
    assert order == ["snap", "stop", ("start", "192.0.2.99")]
    out = capsys.readouterr().out
    copied = []
    monkeypatch.setattr(
        "tacmux.cli.clipboard_copy", lambda _t, data: copied.append(data)
    )
    assert main(["target", "update", "WEB01", "endpoint", "192.0.2.11"]) == 0
    out += capsys.readouterr().out
    from tacmux.cli import _hosts_command

    # The clipboard holds the long command; the terminal shows one line.
    assert copied == [_hosts_command("192.0.2.11", ["web01.example"]).encode()]
    assert "Copied: /etc/hosts → 192.0.2.11 web01.example (paste to run;" in out
    assert "python3" not in out


def test_hosts_line_prints_the_full_command_without_a_clipboard(monkeypatch, capsys):
    from tacmux.cli import _copy_hosts_line, _hosts_command
    from tacmux.errors import ExternalToolError

    def no_clipboard(*_a):
        raise ExternalToolError("no clipboard")

    monkeypatch.setattr("tacmux.cli.clipboard_copy", no_clipboard)
    _copy_hosts_line(None, "192.0.2.9", ["box.offsec"])
    assert _hosts_command("192.0.2.9", ["box.offsec"]) in capsys.readouterr().out


def test_hosts_command_replaces_stale_lines_in_one_paste(tmp_path):
    import subprocess

    from tacmux.cli import _hosts_command

    hosts = tmp_path / "hosts"
    hosts.write_text(
        "127.0.0.1\tlocalhost\n192.0.2.10 BOX.offsec\n10.0.0.5 dc01\n"
        "192.0.2.10\tbox\n# boxXoffsec stays\n"
    )
    command = _hosts_command("192.0.2.99", ["box.offsec", "BOX"])
    local = command.replace("sudo ", "").replace("/etc/hosts", str(hosts))
    subprocess.run(["sh", "-c", local], check=True, capture_output=True)
    assert hosts.read_text().splitlines() == [
        "127.0.0.1\tlocalhost",
        "10.0.0.5 dc01",
        "# boxXoffsec stays",
        "192.0.2.99 box.offsec BOX",
    ]


def test_hosts_command_falls_back_to_append_for_unusual_names():
    from tacmux.cli import _hosts_command

    # Unusual names retain the append-only fallback, with shell-safe quoting.
    assert _hosts_command("192.0.2.9", ["we'ird"]) == (
        "echo '192.0.2.9 we'\"'\"'ird' | sudo tee -a /etc/hosts"
    )


@pytest.mark.parametrize(
    ("before", "preserved"),
    [
        (
            "192.0.2.10 WEB01.example admin.web01.example # primary\n",
            "192.0.2.10\tadmin.web01.example # primary\n",
        ),
        (
            "192.0.2.10 admin.web01.example\tweb01.example\tapi.example\n",
            "192.0.2.10\tadmin.web01.example api.example\n",
        ),
        (
            "10.0.0.5 dc01 # web01.example\n  # web01.example stays\n",
            "10.0.0.5 dc01 # web01.example\n  # web01.example stays\n",
        ),
        (
            "192.0.2.10 web01.example# keep this comment\n",
            "# keep this comment\n",
        ),
        (
            "::1 localhost ip6-localhost\n192.0.2.10 web01Xexample\n",
            "::1 localhost ip6-localhost\n192.0.2.10 web01Xexample\n",
        ),
        ("127.0.0.1 localhost", "127.0.0.1 localhost\n"),
        ("", ""),
    ],
)
def test_hosts_command_preserves_other_aliases_comments_and_file(
    tmp_path, before, preserved
):
    import shlex
    import subprocess

    from tacmux.cli import _hosts_command

    hosts = tmp_path / "hosts"
    hosts.write_text(before)
    hosts.chmod(0o640)
    original = hosts.stat()
    command = _hosts_command("192.0.2.99", ["web01.example"])
    local = command.replace("sudo ", "").replace("/etc/hosts", shlex.quote(str(hosts)))
    for _ in range(2):  # Repeated pastes must not accumulate duplicate entries.
        subprocess.run(["sh", "-c", local], check=True, capture_output=True)
        assert hosts.read_text() == preserved + "192.0.2.99 web01.example\n"
    assert hosts.stat().st_ino == original.st_ino
    assert hosts.stat().st_mode == original.st_mode


@pytest.mark.parametrize(
    ("action", "flag"), [("attach_capture", "-c"), ("screenshot", "-s")]
)
def test_palette_attach_without_entries_starts_a_new_entry(
    settings, workspace, web01, monkeypatch, action, flag
):
    main = _cli(monkeypatch, settings, web01)
    monkeypatch.setattr("tacmux.cli.choose", lambda *_a, **_k: action)
    monkeypatch.setattr("tacmux.tmux.TmuxService.sessions", lambda self: [])
    calls = []
    real = __import__("tacmux.cli", fromlist=["_dispatch"])._dispatch

    def spy(settings_, workspace_, tmux_, command, rest):
        if command == "log":
            calls.append(list(rest))
            return 0
        return real(settings_, workspace_, tmux_, command, rest)

    monkeypatch.setattr("tacmux.cli._dispatch", spy)
    assert main(["menu"]) == 0
    assert calls == [[flag]]


def test_target_add_and_init_offer_the_session_inside_tmux(
    settings, workspace, engagement, monkeypatch, tmp_path
):
    from tacmux.cli import main

    monkeypatch.setenv("TACMUX_WORKSPACE", str(settings.workspace))
    monkeypatch.setenv("TACMUX_CONFIG", str(settings.config_file))
    monkeypatch.setenv("TMUX", "/tmp/sock,1,0")
    monkeypatch.chdir(engagement)
    opened = []
    monkeypatch.setattr(
        "tacmux.tmux.TmuxService.start", lambda self, root, target="": (root, target)
    )
    monkeypatch.setattr(
        "tacmux.tmux.TmuxService.attach",
        lambda self, session: opened.append(session) or 0,
    )
    monkeypatch.setattr(
        "tacmux.tmux.TmuxService.current_context", lambda self: (None, "")
    )
    monkeypatch.setattr("tacmux.cli.confirm", lambda *_a, **_k: True)
    assert main(["target", "add", "WEB01", "192.0.2.10"]) == 0
    assert opened == [(engagement, "WEB01")]
    answers = iter(["BOX", "192.0.2.50"])
    monkeypatch.setattr("tacmux.cli.ask", lambda *_a, **_k: next(answers))
    assert main(["init", "LAB"]) == 0
    assert opened[-1] == (settings.workspace / "LAB", "BOX")


def test_access_and_proof_collect_penelope_logs(
    settings, workspace, web01, tmp_path, monkeypatch, capsys
):
    monkeypatch.setenv("HOME", str(tmp_path))
    base = tmp_path / ".penelope/sessions"
    session = _penelope(base, "ubuntu~192.0.2.10-Linux-x86_64", {"a.log": b"id\n"})
    main = _cli(monkeypatch, settings, web01)
    monkeypatch.setattr("tacmux.cli.can_prompt", lambda: False)
    assert main(["access", "user", "app", "rce"]) == 0
    shells = web01 / "captures/WEB01/shells/penelope/ubuntu~192.0.2.10-Linux-x86_64"
    assert (shells / "a.log").read_bytes() == b"id\n"
    assert "Shell logs  1 new file(s)" in capsys.readouterr().out
    (session / "b.log").write_bytes(b"cat local.txt\n")
    assert main(["proof", "user", "9a1d", "/root/local.txt", "--no-screenshot"]) == 0
    assert (shells / "b.log").is_file()


def test_done_title_code_details_and_last_command(
    settings, workspace, web01, monkeypatch
):
    from tacmux.journal import append_command

    main = _cli(monkeypatch, settings, web01)
    monkeypatch.setenv("TMUX_PANE", "%3")
    append_command(
        web01, "1", "1.0", "0", "WEB01", "%3", "/x", "getcap -r / 2>/dev/null"
    )
    append_command(web01, "2", "1.0", "0", "WEB01", "%9", "/x", "other pane")
    append_command(web01, "3", "0.1", "0", "WEB01", "%3", "/x", "tm status")
    assert main(["done", "Root via cap_setuid :: proof.txt captured", "-l"]) == 0
    event = sitrep.read_events(workspace.read(web01))[-1]
    assert event.summary == "Root via cap_setuid"
    assert event.body == "```bash\ngetcap -r / 2>/dev/null\n```\n\nproof.txt captured"
    assert main(["fail", "50640 :: ```python3 50640.py``` broken"]) == 0
    event = sitrep.read_events(workspace.read(web01))[-1]
    assert (event.outcome, event.summary) == ("failed", "50640")
    assert event.body.startswith("```bash\npython3 50640.py\n```")
    text = workspace.read(web01)
    assert "> [!failure] 50640" in text and "> [!success] Root via cap_setuid" in text


def test_evidence_map_refreshes_and_counts(
    settings, workspace, web01, tmp_path, monkeypatch, capsys
):
    from tacmux.journal import append_command

    monkeypatch.setenv("HOME", str(tmp_path))
    _penelope(tmp_path / ".penelope/sessions", "h~192.0.2.10-Linux", {"a.log": b"x\n"})
    day = web01 / "logs/20260101"
    day.mkdir(parents=True)
    (day / "WEB01_p1.log").write_bytes(b"=== TACMUX ===\nTarget: WEB01\n\nok\r\n")
    append_command(web01, "1", "1.0", "1", "WEB01", "%1", "/x", "python3 x.py")
    main = _cli(monkeypatch, settings, web01)
    main(["fail", "x.py broken"])
    monkeypatch.setattr("tacmux.cli.can_prompt", lambda: False)
    capsys.readouterr()
    assert main(["evidence"]) == 0
    out = capsys.readouterr().out
    assert "SITREP events   1 (1 failed)" in out
    assert "Commands        1 in logs/commands.tsv (1 non-zero)" in out
    assert "Pane logs       1 readable .txt under logs/ (1 refreshed)" in out
    assert "Shell logs      1 under captures/*/shells/ (1 new)" in out
    assert (day / "WEB01_p1.txt").read_text().endswith("ok\n")


def test_last_command_skips_tacmux_and_cap_grab(web01, monkeypatch):
    from tacmux.cli import _last_command
    from tacmux.journal import append_command

    monkeypatch.delenv("TMUX_PANE", raising=False)
    append_command(web01, "1", "1", "0", "WEB01", "%1", "/x", "hashcat -m 0 hash.txt")
    append_command(web01, "2", "1", "0", "WEB01", "%1", "/x", "cap grab")
    append_command(web01, "3", "1", "0", "WEB01", "%1", "/x", "X=1 tacmux status")
    assert _last_command(web01) == "hashcat -m 0 hash.txt"


def test_code_blocks_refuse_control_characters(workspace, web01):
    from tacmux.errors import ValidationError

    with pytest.raises(ValidationError, match="control characters"):
        workspace.add_event(web01, "WEB01", "info", "x", code="echo \x1b[31m")
    identifier = workspace.add_event(web01, "WEB01", "info", "x", code="a\nb\tc")
    assert identifier


def test_evidence_picker_lists_entries_and_screenshots(
    settings, workspace, web01, monkeypatch
):
    main = _cli(monkeypatch, settings, web01)
    main(["done", "Shell as app"])
    shots = web01 / "targets/WEB01/screenshots"
    shots.mkdir(parents=True, exist_ok=True)
    (shots / "E001-x.png").write_bytes(b"\x89PNG")
    offered = []

    def capture(choices, *_args, **_kwargs):
        offered.extend(choice[0] for choice in choices)
        raise ValidationError("selection cancelled")

    monkeypatch.setattr("tacmux.cli.choose", capture)
    assert main(["evidence"]) == 0
    assert any(label.startswith("📋 SITREP entries (1)") for label in offered)
    assert any("E001-x.png" in label for label in offered)


# --- 3.4.2 review fixes -------------------------------------------------------


def _cancel(*_args, **_kwargs):
    from tacmux.errors import Cancelled

    raise Cancelled("selection cancelled")


def test_close_checklist_recognizes_a_3_4_proof(
    settings, workspace, web01, monkeypatch
):
    main = _cli(monkeypatch, settings, web01)
    monkeypatch.setenv("TACMUX_NONINTERACTIVE", "1")
    assert main(["proof", "user", "abc123", "/root/local.txt"]) == 0
    from tacmux.cli import _close_items

    labels = [label for label, _key in _close_items(workspace, web01, "WEB01")]
    assert any(label.startswith("✓  Proof: E") for label in labels)
    assert not any("No proof recorded" in label for label in labels)


def test_ops_names_the_operations_session(
    settings, workspace, web01, monkeypatch, fake_sessions, capsys
):
    main = _cli(monkeypatch, settings, web01)  # inside WEB01's folder
    monkeypatch.setattr("tacmux.tmux.TmuxService.has_session", lambda *_: False)
    assert main(["stop", "ops"]) == 0
    assert fake_sessions["stopped"] == [""]
    assert "Stopped OPS" in capsys.readouterr().out
    assert main(["snap", "OPS"]) == 0
    assert fake_sessions["snapped"] == [""]
    assert main(["status", "ops"]) == 0
    output = capsys.readouterr().out
    assert "Endpoint" in output and "Session:" not in output  # engagement view


def test_escape_in_a_picker_exits_quietly(
    settings, workspace, web01, monkeypatch, capsys
):
    main = _cli(monkeypatch, settings, web01)
    monkeypatch.setattr("tacmux.cli.choose", _cancel)
    assert main(["target"]) == 0  # target table, then Esc at the action picker
    captured = capsys.readouterr()
    assert "WEB01" in captured.out and captured.err == ""


def test_escape_inside_a_palette_action_closes_the_popup(
    settings, workspace, web01, monkeypatch
):
    from tacmux.errors import Cancelled

    main = _cli(monkeypatch, settings, web01)
    monkeypatch.setenv("TACMUX_POPUP", "1")
    monkeypatch.setattr("tacmux.cli._session_choices", lambda *_: [])

    def palette_choose(_choices, prompt, **_kwargs):
        if prompt == "TACMUX> ":
            return "note"
        raise Cancelled("selection cancelled")  # Esc at Outcome>

    monkeypatch.setattr("tacmux.cli.choose", palette_choose)
    monkeypatch.setattr("builtins.input", lambda *_: pytest.fail("popup waited"))
    assert main(["menu"]) == 0
    assert sitrep.read_events(workspace.read(web01)) == []


def test_evidence_lists_prefix_s_captures(
    settings, workspace, web01, monkeypatch, capsys
):
    main = _cli(monkeypatch, settings, web01)
    day = web01 / "logs/20260101"
    day.mkdir(parents=True, exist_ok=True)
    for target in ("WEB01", "ENGAGEMENT"):
        (day / f"scrollback_{target}_main_x_p1_000000_1.log").write_text(
            f"=== TACMUX scrollback log ===\nSession: s\nTarget: {target}\n"
            "Pane: %1\n\nhello\n"
        )
    offered: list[str] = []

    def fake_choose(choices, _prompt, **_kwargs):
        offered.extend(choice[0] for choice in choices)
        _cancel()

    monkeypatch.setattr("tacmux.cli.choose", fake_choose)
    assert main(["evidence"]) == 0
    assert "Exact captures  1 scrollback_*.log (Prefix+S)" in capsys.readouterr().out
    assert any(
        label.startswith("📌") and "scrollback_WEB01" in label for label in offered
    )
    assert not any("scrollback_ENGAGEMENT" in label for label in offered)


def test_target_list_aliases_and_prefixes(
    settings, workspace, web01, monkeypatch, capsys
):
    main = _cli(monkeypatch, settings, web01)
    monkeypatch.setenv("TACMUX_NONINTERACTIVE", "1")
    for words in (["target"], ["target", "list"], ["target", "status"]):
        assert main(words) == 0
        assert "192.0.2.10" in capsys.readouterr().out
    assert main(["target", "up", "os", "Linux"]) == 0
    assert workspace.target_details(web01, "WEB01")["OS"][0] == "Linux"
    assert main(["target", "bogus"]) == 1
    assert "target requires add" in capsys.readouterr().err


def test_init_with_an_endpoint_creates_the_box_target(
    settings, workspace, monkeypatch, tmp_path, capsys
):
    from tacmux.cli import main

    monkeypatch.setenv("TACMUX_WORKSPACE", str(settings.workspace))
    monkeypatch.setenv("TACMUX_CONFIG", str(settings.config_file))
    monkeypatch.setenv("TACMUX_NONINTERACTIVE", "1")
    monkeypatch.chdir(tmp_path)
    assert main(["init", "Fractal", "192.0.2.50"]) == 0
    root = settings.workspace / "Fractal"
    assert workspace.targets(root) == ["FRACTAL"]
    assert workspace.target_details(root, "FRACTAL")["Endpoint"][0] == "192.0.2.50"
    assert "Open it with: tm switch (FRACTAL)" in capsys.readouterr().out
    assert main(["init", "Fractal", "192.0.2.51"]) == 1
    assert "already has targets" in capsys.readouterr().err


def test_init_prefills_the_target_name(settings, workspace, monkeypatch, tmp_path):
    from tacmux.cli import main

    monkeypatch.setenv("TACMUX_WORKSPACE", str(settings.workspace))
    monkeypatch.setenv("TACMUX_CONFIG", str(settings.config_file))
    monkeypatch.chdir(tmp_path)
    asked = {}

    def fake_ask(label, default="", **kwargs):
        asked[label] = (default, kwargs.get("prefill", False))
        return default if label == "Target name" else "192.0.2.60"

    monkeypatch.setattr("tacmux.cli.ask", fake_ask)
    monkeypatch.setattr(
        "tacmux.cli.confirm", lambda prompt, default=False: "first target" in prompt
    )
    assert main(["init", "Box"]) == 0
    assert asked["Target name"] == ("BOX", True)
    assert workspace.targets(settings.workspace / "Box") == ["BOX"]


def test_guided_proof_asks_for_an_unrecorded_os(
    settings, workspace, web01, monkeypatch
):
    main = _cli(monkeypatch, settings, web01)
    asked = []

    def fake_choose(choices, prompt, **_kwargs):
        asked.append(prompt)
        if "OS is not recorded" in prompt:
            return "Windows"
        if prompt == "Proof> ":
            return "root"
        return choices[0][1]  # first suggested path

    monkeypatch.setattr("tacmux.cli.choose", fake_choose)
    monkeypatch.setattr("tacmux.cli.ask", lambda *_a, **_k: "abc123")
    monkeypatch.setattr("tacmux.cli.confirm", lambda *_a, **_k: False)
    assert main(["proof"]) == 0
    assert asked[0] == "WEB01 OS is not recorded> "
    assert workspace.target_details(web01, "WEB01")["OS"][0] == "Windows"
    event = sitrep.read_events(workspace.read(web01))[-1]
    assert event.body.splitlines()[-1].startswith("C:\\")  # Windows path suggested


def test_web_login_cannot_silently_raise_os_access(
    settings, workspace, web01, monkeypatch, capsys
):
    main = _cli(monkeypatch, settings, web01)
    credential = workspace.add_credential(web01, "admin", "admin", "password")
    monkeypatch.setattr("tacmux.cli.confirm", lambda *_a, **_k: False)  # not OS admin
    assert main(["creds", "confirm", credential, "admin", "http :80"]) == 0
    assert "Recorded as authenticated." in capsys.readouterr().out
    assert workspace.target_details(web01, "WEB01")["Access"][0] == "authenticated"
    monkeypatch.setenv("TACMUX_NONINTERACTIVE", "1")  # scripts keep explicit words
    assert main(["creds", "confirm", credential, "user", "ssh :22"]) == 0
    assert workspace.target_details(web01, "WEB01")["Access"][0] == "user"


# --- 3.4.3: PG-Kevin review fixes ---------------------------------------------


def test_capture_is_not_offered_again_after_a_later_entry(
    workspace, web01, monkeypatch
):
    from tacmux.evidence import latest_unattached_capture

    monkeypatch.setattr("tacmux.evidence.shutil.which", lambda _name: "/usr/bin/cap")
    old = CaptureRecord(
        "cap-1", "done", "nmapq", "WEB01/nmap.txt", "nmapq x", "2026-01-01T10:00:00Z"
    )
    monkeypatch.setattr(Workspace, "inspect_capture", lambda *_a, **_k: old)
    assert latest_unattached_capture(workspace, web01, "WEB01") == old
    workspace.add_event(web01, "WEB01", "success", "Web login works")  # passed over
    assert latest_unattached_capture(workspace, web01, "WEB01") is None
    newer = CaptureRecord(
        "cap-2", "done", "ffuf", "WEB01/ffuf.txt", "ffuf", "2999-01-01T00:00:00Z"
    )
    monkeypatch.setattr(Workspace, "inspect_capture", lambda *_a, **_k: newer)
    assert latest_unattached_capture(workspace, web01, "WEB01") == newer


@pytest.mark.parametrize(
    ("finished", "should_offer"),
    [
        ("2026-11-04T12:00:00.100000Z", False),
        ("2026-11-04T12:00:00.900000Z", False),
        ("2026-11-04T12:00:00.950000Z", False),  # same second: passed over
        ("2026-11-04T12:00:01.000000Z", True),  # the next second is new output
    ],
)
def test_capture_offer_treats_the_entry_second_as_passed_over(
    workspace, web01, monkeypatch, finished, should_offer
):
    from tacmux.evidence import latest_unattached_capture

    class FrozenClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 11, 4, 12, 0, 0, 900000, tzinfo=timezone.utc)

    monkeypatch.setattr("tacmux.workspace.datetime", FrozenClock)
    monkeypatch.setattr("tacmux.evidence.shutil.which", lambda _name: "/mock/cap")
    record = CaptureRecord(
        "cap-1", "done", "nmap", "WEB01/nmap.txt", "nmap x", finished
    )
    monkeypatch.setattr(Workspace, "inspect_capture", lambda *_a, **_k: record)
    workspace.add_event(web01, "WEB01", "info", "Observation")
    document = workspace.read(web01)
    # Stored to the second so SITREP stays readable.
    assert sitrep.read_events(document)[-1].timestamp == "2026-11-04T12:00:00Z"
    assert sitrep.read_events(sitrep.normalize_document(document))[-1].timestamp == (
        "2026-11-04T12:00:00Z"
    )
    assert (
        latest_unattached_capture(workspace, web01, "WEB01") is not None
    ) == should_offer


def test_creds_add_then_confirm_asks_notes_once(
    settings, workspace, web01, monkeypatch
):
    main = _cli(monkeypatch, settings, web01)
    asked = []

    def fake_ask(label, *_a, **_k):
        asked.append(label)
        return {"Principal": "admin", "Source": "web", "Notes": "default"}.get(
            label, ""
        )

    monkeypatch.setattr("tacmux.cli.ask", fake_ask)
    monkeypatch.setattr("tacmux.cli.getpass.getpass", lambda *_a: "admin")
    monkeypatch.setattr("tacmux.cli.confirm", lambda *_a, **_k: True)  # works somewhere
    picks = iter(["http :80", "authenticated"])
    monkeypatch.setattr("tacmux.cli.choose", lambda *_a, **_k: next(picks))
    assert main(["creds", "add", "password"]) == 0
    assert asked.count("Notes") == 1


def test_default_target_drops_the_notes_folder_prefix(tmp_path):
    from tacmux.cli import _default_target_name
    from tacmux.config import Settings

    pg = Settings(
        workspace=tmp_path / "ws",
        config_file=tmp_path / "c.toml",
        sitrep_root=tmp_path / "PG",
    )
    assert _default_target_name(pg, "PG-Kevin") == "KEVIN"
    assert _default_target_name(pg, "Fractal") == "FRACTAL"
    assert _default_target_name(pg, "PG-") == "PG-"
    plain = Settings(workspace=tmp_path / "ws", config_file=tmp_path / "c.toml")
    assert _default_target_name(plain, "PG-Kevin") == "PG-KEVIN"


def test_root_proof_suggests_close_and_unknown_os_records_only_the_file(
    settings, workspace, web01, monkeypatch, capsys
):
    main = _cli(monkeypatch, settings, web01)
    monkeypatch.setattr("tacmux.cli.confirm", lambda *_a, **_k: False)
    assert main(["proof", "root", "49d8"]) == 0  # OS not recorded, no path given
    event = sitrep.read_events(workspace.read(web01))[-1]
    assert event.body.splitlines()[-1] == "proof.txt"
    assert "Done with WEB01? tm close" in capsys.readouterr().out


def test_database_login_is_guarded_like_a_web_login(
    settings, workspace, web01, monkeypatch, capsys
):
    main = _cli(monkeypatch, settings, web01)
    credential = workspace.add_credential(web01, "sa", "sa", "password")
    monkeypatch.setattr("tacmux.cli.confirm", lambda *_a, **_k: False)
    assert main(["creds", "confirm", credential, "admin", "ms-sql-s :1433"]) == 0
    assert workspace.target_details(web01, "WEB01")["Access"][0] == "authenticated"


def test_access_after_proof_records_the_real_method(
    settings, workspace, web01, monkeypatch, capsys
):
    """PG-Algernon: proof first (with the implied shell), then tm access."""
    main = _cli(monkeypatch, settings, web01)
    workspace.set_target_detail(web01, "WEB01", "OS", "Windows")
    workspace.set_target_detail(web01, "WEB01", "Method/Path", "ftp anonymous access")
    monkeypatch.setattr("tacmux.cli.confirm", lambda prompt, **_k: "shell" in prompt)
    monkeypatch.setattr("tacmux.cli.choose", lambda *_a, **_k: "root")
    monkeypatch.setattr(
        "tacmux.cli.ask",
        lambda label, *_a, **_k: "" if label.startswith("How") else "7f53",
    )
    monkeypatch.setattr("tacmux.cli._choose_shell_pane", lambda *_a: "")
    assert (
        main(["proof"]) == 0
    )  # guided; "also record a system shell?" → yes, HOW skipped
    details = workspace.target_details(web01, "WEB01")
    assert details["Access"][0] == "system"
    # Neither the flag title nor the stale authenticated-level method.
    assert details["Method/Path"][0] == ""
    monkeypatch.setenv("TACMUX_NONINTERACTIVE", "1")
    assert (
        main(
            [
                "access",
                "system",
                "SYSTEM",
                "SmarterMail CVE-2019-7214",
                "--via",
                "remoting :17001",
            ]
        )
        == 0
    )
    details = workspace.target_details(web01, "WEB01")
    assert details["Access"][0] == "system"
    assert details["Method/Path"][0] == "SmarterMail CVE-2019-7214 via remoting :17001"
    assert "Principal and Method/Path updated" in capsys.readouterr().out
    # A lower access record never lowers Access nor rewrites how it was reached.
    assert main(["access", "user", "app", "other path"]) == 0
    details = workspace.target_details(web01, "WEB01")
    assert details["Access"][0] == "system"
    assert details["Method/Path"][0] == "SmarterMail CVE-2019-7214 via remoting :17001"


@pytest.mark.parametrize("extra", [[], ["--via", "local"]])
def test_same_level_access_without_a_method_preserves_provenance(
    settings, workspace, web01, monkeypatch, capsys, extra
):
    main = _cli(monkeypatch, settings, web01)
    monkeypatch.setenv("TACMUX_NONINTERACTIVE", "1")
    workspace.record_access(
        web01,
        "WEB01",
        "system",
        "Initial shell",
        principal="SYSTEM",
        method="Verified exploit via remoting :17001",
    )
    before = workspace.read(web01)
    assert main(["access", "system", "SYSTEM", *extra]) == 0
    details = workspace.target_details(web01, "WEB01")
    assert details["Access"][0] == "system"
    assert details["Principal"][0] == "SYSTEM"
    assert details["Method/Path"][0] == "Verified exploit via remoting :17001"
    assert (
        sitrep.read_events(workspace.read(web01))[-1].summary
        == "Access: system as SYSTEM"
    )
    assert "Method/Path unchanged" in capsys.readouterr().out
    workspace.undo_last_change(web01, expected=workspace.last_change(web01))
    assert workspace.read(web01) == before


def test_access_without_a_method_leaves_an_empty_method_empty(
    settings, workspace, web01, monkeypatch
):
    main = _cli(monkeypatch, settings, web01)
    monkeypatch.setenv("TACMUX_NONINTERACTIVE", "1")
    assert main(["access", "user", "app"]) == 0
    details = workspace.target_details(web01, "WEB01")
    assert details["Access"][0] == "user"
    assert details["Principal"][0] == "app"
    assert details["Method/Path"][0] == ""


def test_raising_access_without_how_clears_the_lower_level_method(
    settings, workspace, web01, monkeypatch, capsys
):
    main = _cli(monkeypatch, settings, web01)
    monkeypatch.setenv("TACMUX_NONINTERACTIVE", "1")
    assert (
        main(["access", "auth", "anonymous", "ftp anonymous", "--via", "ftp :21"]) == 0
    )
    assert workspace.target_details(web01, "WEB01")["Method/Path"][0] == (
        "ftp anonymous via ftp :21"
    )
    capsys.readouterr()
    assert main(["access", "system", "SYSTEM"]) == 0  # no HOW
    details = workspace.target_details(web01, "WEB01")
    assert details["Access"][0] == "system"
    assert details["Principal"][0] == "SYSTEM"
    assert details["Method/Path"][0] == ""  # not "SYSTEM via anonymous FTP"
    assert "Method/Path is empty" in capsys.readouterr().out


def test_exact_comparison_for_entries_with_fractional_seconds():
    from datetime import datetime, timezone

    from tacmux.evidence import _passed_over

    logged = datetime(2026, 11, 4, 12, 0, 0, 500000, tzinfo=timezone.utc)
    assert _passed_over(logged.replace(microsecond=400000), logged)
    assert not _passed_over(logged.replace(microsecond=600000), logged)
