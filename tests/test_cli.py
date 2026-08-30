from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from tacmux.archive import create_archive
from tacmux.cli import main


ROOT = Path(__file__).resolve().parents[1]


def test_version_help_unknown_and_non_tty(capsys, monkeypatch):
    assert main(["version"]) == 0
    assert capsys.readouterr().out.strip() == "tacmux 2.0.0"
    assert main(["help"]) == 0
    assert "interactive operator cockpit" in capsys.readouterr().out
    assert main(["not-a-command"]) == 2
    assert "Usage:" in capsys.readouterr().err


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
    assert result.stdout.strip() == "tacmux 2.0.0"


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
