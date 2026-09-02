from __future__ import annotations

import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_shell_scripts_parse_and_v3_has_no_full_tmux_preset():
    for script in (ROOT / "install.sh", ROOT / "uninstall.sh", ROOT / "bin/tacmux"):
        subprocess.run(["bash", "-n", str(script)], check=True)
    installer = (ROOT / "install.sh").read_text()
    assert "--full-tmux" not in installer
    assert "tacmux-v3" in installer
    assert not (ROOT / "tmux/tacmux.conf").exists()


def test_uninstaller_refuses_unmarked_install(tmp_path):
    home = tmp_path / "home"
    install = home / ".local/share/tacmux"
    install.mkdir(parents=True)
    sentinel = install / "operator-data"
    sentinel.write_text("keep")
    env = os.environ | {"HOME": str(home)}
    result = subprocess.run(
        [str(ROOT / "uninstall.sh")], env=env, text=True, capture_output=True
    )
    assert result.returncode == 0
    assert sentinel.read_text() == "keep"
    assert "Skipped unmarked" in result.stderr


def test_installer_refuses_unrelated_command(tmp_path):
    home = tmp_path / "home"
    binary = home / ".local/bin/tacmux"
    binary.parent.mkdir(parents=True)
    binary.write_text("operator command")
    env = os.environ | {"HOME": str(home)}
    result = subprocess.run(
        [str(ROOT / "install.sh"), "--skip-tmux"],
        env=env,
        text=True,
        capture_output=True,
    )
    assert result.returncode != 0
    assert binary.read_text() == "operator command"
    assert "unrelated command" in result.stderr


def test_tmux_fragment_contains_only_tacmux_integration():
    text = (ROOT / "tmux/tacmux-integration.conf").read_text()
    assert "tacmux switch" in text
    for general_setting in (
        "prefix C-space",
        "mouse on",
        "status-format",
        "split-window -v",
    ):
        assert general_setting not in text


def test_installer_refuses_linked_tmux_config_without_skip(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    managed = tmp_path / "managed-tmux.conf"
    managed.write_text("set -g mouse on\n")
    os.symlink(managed, home / ".tmux.conf")
    env = os.environ | {
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
    }
    result = subprocess.run(
        [str(ROOT / "install.sh")], env=env, text=True, capture_output=True
    )
    assert result.returncode != 0
    assert "Refusing to edit linked tmux config" in result.stderr
    assert managed.read_text() == "set -g mouse on\n"
    assert not (home / ".local/share/tacmux").exists()


def test_uninstaller_preserves_linked_tmux_config(tmp_path):
    home = tmp_path / "home"
    install = home / ".local/share/tacmux"
    install.mkdir(parents=True)
    (install / ".tacmux-install").write_text("tacmux-v3\n")
    managed = tmp_path / "managed-tmux.conf"
    managed.write_text("set -g mouse on\n")
    os.symlink(managed, home / ".tmux.conf")
    env = os.environ | {
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
    }
    result = subprocess.run(
        [str(ROOT / "uninstall.sh")], env=env, text=True, capture_output=True
    )
    assert result.returncode == 0
    assert managed.read_text() == "set -g mouse on\n"
    assert (home / ".tmux.conf").is_symlink()
    assert not install.exists()


def test_install_reinstall_and_uninstall_preserve_operator_data(tmp_path):
    home = tmp_path / "home"
    workspace = tmp_path / "engagements with spaces"
    home.mkdir()
    env = os.environ | {
        "HOME": str(home),
        "UV_OFFLINE": "1",
        "XDG_CACHE_HOME": str(tmp_path / "cache"),
    }
    first = subprocess.run(
        [
            str(ROOT / "install.sh"),
            "--workspace",
            str(workspace),
            "--skip-tmux",
        ],
        env=env,
        text=True,
        capture_output=True,
    )
    assert first.returncode == 0, first.stderr
    command = home / ".local/bin/tacmux"
    version = subprocess.run(
        [str(command), "version"], env=env, text=True, capture_output=True, check=True
    )
    assert version.stdout.strip() == "tacmux 3.0.0"

    subprocess.run([str(command), "init", "ACME"], env=env, text=True, check=True)
    evidence = workspace / "ACME/targets/operator-evidence.txt"
    evidence.write_text("keep\n")

    second = subprocess.run(
        [str(ROOT / "install.sh"), "--skip-tmux"],
        env=env,
        text=True,
        capture_output=True,
    )
    assert second.returncode == 0, second.stderr
    assert evidence.read_text() == "keep\n"

    removed = subprocess.run(
        [str(ROOT / "uninstall.sh")],
        env=env,
        text=True,
        capture_output=True,
    )
    assert removed.returncode == 0, removed.stderr
    assert evidence.read_text() == "keep\n"
    assert not command.exists()
