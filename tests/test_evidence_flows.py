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
