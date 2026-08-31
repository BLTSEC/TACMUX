from __future__ import annotations

from io import BytesIO, TextIOWrapper
import os
import subprocess
import sys
from pathlib import Path

from tacmux.archive import create_archive
from tacmux.cli import main
from tacmux.hooks import clipboard_copy
from tacmux.model import EngagementStatus, ScopeGroup, TargetAddress


ROOT = Path(__file__).resolve().parents[1]


def test_version_help_unknown_and_non_tty(capsys, monkeypatch):
    assert main(["version"]) == 0
    assert capsys.readouterr().out.strip() == "tacmux 2.1.0"
    assert main(["help"]) == 0
    assert "interactive operator cockpit" in capsys.readouterr().out
    assert main(["not-a-command"]) == 2
    assert "Usage:" in capsys.readouterr().err


def test_public_clip_and_ssh_tty_fallback(settings, monkeypatch):
    copied: list[bytes] = []
    monkeypatch.setattr("tacmux.cli.load_settings", lambda: settings)
    monkeypatch.setattr(
        "tacmux.cli.clipboard_copy",
        lambda _tmux, data: copied.append(data) or 0,
    )
    stdin = TextIOWrapper(BytesIO(b"public clipboard"), encoding="utf-8")
    monkeypatch.setattr("sys.stdin", stdin)
    assert main(["clip"]) == 0
    assert copied == [b"public clipboard"]

    class NoTmux:
        def available(self):
            return False

    writes: list[tuple[int, bytes]] = []
    closed: list[int] = []
    for name in ("TMUX", "WAYLAND_DISPLAY", "DISPLAY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SSH_CONNECTION", "client server")
    monkeypatch.setattr("tacmux.hooks.shutil.which", lambda _name: None)
    monkeypatch.setattr("tacmux.hooks.os.isatty", lambda _fd: False)
    monkeypatch.setattr("tacmux.hooks.os.open", lambda *_args: 42)
    monkeypatch.setattr(
        "tacmux.hooks.os.write", lambda fd, data: writes.append((fd, data)) or len(data)
    )
    monkeypatch.setattr("tacmux.hooks.os.close", lambda fd: closed.append(fd))
    assert clipboard_copy(NoTmux(), b"remote") == 0
    assert writes == [(42, b"\x1b]52;c;cmVtb3Rl\x07")]
    assert closed == [42]


def test_archive_verify_cli(tmp_path, capsys):
    source = tmp_path / "evidence"
    source.mkdir()
    (source / "proof.txt").write_text("proof")
    archive, _ = create_archive(
        source,
        tmp_path / "archives",
        kind="targets",
        engagement_id="E-0123456789ab",
        object_id="T0001",
        object_metadata={"id": "T0001", "directory": source.name},
    )
    assert main(["archive", "verify", str(archive)]) == 0
    output = capsys.readouterr().out
    assert "Verified:" in output and "Files: 1" in output


def test_repository_wrapper_reports_v2():
    result = subprocess.run(
        [str(ROOT / "bin/tacmux"), "version"],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "tacmux 2.1.0"


def test_cli_import_does_not_load_textual():
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys, tacmux.cli; "
            "print(any(name == 'textual' or name.startswith('textual.') "
            "for name in sys.modules))",
        ],
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )
    assert result.stdout.strip() == "False"


def test_health_reports_invalid_engagement_manifests(tmp_path, capsys, monkeypatch):
    workspace = tmp_path / "workspace"
    archive = tmp_path / "archives"
    logs = tmp_path / "logs"
    manifest = workspace / "E-bad/.tacmux/engagement.json"
    manifest.parent.mkdir(parents=True)
    archive.mkdir()
    logs.mkdir()
    manifest.write_text("[]")
    config = tmp_path / "config.toml"
    config.write_text(
        "[paths]\n"
        f'workspace = "{workspace}"\n'
        f'archive_dir = "{archive}"\n'
        f'log_dir = "{logs}"\n'
    )
    monkeypatch.setenv("TACMUX_CONFIG", str(config))
    monkeypatch.setattr("tacmux.cli.TmuxService.available", lambda *_: True)
    monkeypatch.setattr("tacmux.cli.TmuxService.version", lambda *_: "tmux test")
    monkeypatch.setattr("tacmux.cli.shutil.which", lambda name: f"/usr/bin/{name}")
    assert main(["health"]) == 1
    output = capsys.readouterr().out
    assert "1 invalid" in output
    assert str(manifest) in output


def test_health_reports_workspace_level_delete_staging(
    tmp_path, capsys, monkeypatch
):
    workspace = tmp_path / "workspace"
    archive = tmp_path / "archives"
    logs = tmp_path / "logs"
    staged = workspace / ".tacmux/deleting/E-deleted-recovery"
    staged.mkdir(parents=True)
    archive.mkdir()
    logs.mkdir()
    config = tmp_path / "config.toml"
    config.write_text(
        "[paths]\n"
        f'workspace = "{workspace}"\n'
        f'archive_dir = "{archive}"\n'
        f'log_dir = "{logs}"\n'
    )
    monkeypatch.setenv("TACMUX_CONFIG", str(config))
    monkeypatch.setattr("tacmux.cli.TmuxService.available", lambda *_: True)
    monkeypatch.setattr("tacmux.cli.TmuxService.version", lambda *_: "tmux test")
    monkeypatch.setattr("tacmux.cli.shutil.which", lambda name: f"/usr/bin/{name}")
    assert main(["health"]) == 0
    output = capsys.readouterr().out
    assert "1 item(s) require manual review" in output
    assert f"staged deletion: {staged}" in output


def test_in_pane_note_activity_and_sitrep(
    settings, workspace, record, monkeypatch, capsys
):
    scope = workspace.add_scope(
        record.root,
        record.engagement,
        "LAN",
        ScopeGroup.INTERNAL,
        "10.90.0.0/24",
    )
    target = workspace.create_target(
        record.root,
        record.engagement,
        "host",
        addresses=[TargetAddress("10.90.0.10", scope.id)],
        primary_endpoint="10.90.0.10",
    )
    settings.config_file.parent.mkdir(parents=True, exist_ok=True)
    settings.config_file.write_text(
        "[paths]\n"
        f'workspace = "{settings.workspace}"\n'
        f'archive_dir = "{settings.archive_dir}"\n'
        f'log_dir = "{settings.log_dir}"\n'
    )
    monkeypatch.setenv("TACMUX_CONFIG", str(settings.config_file))
    monkeypatch.setenv("TACMUX_ENGAGEMENT_ID", record.engagement.id)
    monkeypatch.setenv("TACMUX_TARGET_ID", target.id)
    monkeypatch.setattr("tacmux.cli.TmuxService.available", lambda *_: False)

    assert main(["note", "shell", "as", "svc_deploy"]) == 0
    notes = record.root / "targets" / target.directory / "NOTES.md"
    assert "shell as svc_deploy" in notes.read_text()

    assert main(["activity", "confirmed", "Established", "route"]) == 0
    loaded = workspace.load(record.root)
    assert loaded.activities[-1].summary == "Established route"
    assert loaded.activities[-1].target_id == target.id

    assert main(["sitrep"]) == 0
    output = capsys.readouterr().out
    assert "# SITREP" in output and "Established route" in output

    assert main(["export"]) == 0
    export_path = Path(capsys.readouterr().out.strip())
    assert export_path.is_file()
    assert "Established route" in export_path.read_text()

    assert main(["export", "not-a-profile"]) == 1
    assert "compact or evidence" in capsys.readouterr().err

    workspace.set_status(record.root, loaded, EngagementStatus.CLOSED)
    assert main(["note", "late", "note"]) == 1
    assert main(["activity", "confirmed", "Late", "activity"]) == 1
    assert capsys.readouterr().err.count("engagement is closed") == 2
