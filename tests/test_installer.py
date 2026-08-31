from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_install_reinstall_and_uninstall_preserve_operator_data(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / ".zshrc").write_text("# operator zsh config\n")
    (home / ".bashrc").write_text("# operator bash config\n")
    workspace = tmp_path / "workspace with spaces"
    original_uv_cache = subprocess.run(
        ["uv", "cache", "dir"], text=True, capture_output=True, check=True
    ).stdout.strip()
    env = os.environ.copy()
    env.update(
        HOME=str(home),
        XDG_CONFIG_HOME=str(home / ".config"),
        PATH=f"{home}/.local/bin:{env['PATH']}",
        UV_CACHE_DIR=original_uv_cache,
        UV_OFFLINE="1",
    )
    command = [
        str(ROOT / "install.sh"),
        "--unattended",
        "--workspace",
        str(workspace),
    ]
    for _ in range(2):
        result = subprocess.run(
            command, env=env, text=True, capture_output=True, check=False
        )
        assert result.returncode == 0, result.stdout + result.stderr

    binary = home / ".local/bin/tacmux"
    config = home / ".config/tacmux/config.toml"
    assert binary.is_symlink()
    assert (
        subprocess.run(
            [str(binary), "version"],
            env=env,
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        == "tacmux 2.2.0"
    )
    installed_css = list(
        (home / ".local/share/tacmux/app/.venv/lib").glob(
            "python*/site-packages/tacmux/tacmux.tcss"
        )
    )
    assert len(installed_css) == 1
    assert "workspace with spaces" in config.read_text()
    assert stat.S_IMODE(config.stat().st_mode) == 0o600
    assert stat.S_IMODE(workspace.stat().st_mode) == 0o700
    assert (home / ".zshrc").read_text() == "# operator zsh config\n"
    assert "tmux/tacmux.conf" in (home / ".tmux.conf").read_text()
    assert (
        home / ".config/tacmux/install-state"
    ).read_text() == "TMUX_MODE=full\n"

    evidence = workspace / "preserve.txt"
    evidence.write_text("operator evidence")
    result = subprocess.run(
        [str(ROOT / "uninstall.sh")],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert not binary.exists()
    assert not (home / ".local/share/tacmux").exists()
    assert config.is_file()
    assert evidence.read_text() == "operator evidence"
    assert (home / ".zshrc").read_text() == "# operator zsh config\n"


def test_installer_preserves_tmux_mode_and_explicit_full_override(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    tmux_config = home / ".tmux.conf"
    tmux_config.write_text("set -g mouse off\n")
    original_uv_cache = subprocess.run(
        ["uv", "cache", "dir"], text=True, capture_output=True, check=True
    ).stdout.strip()
    env = os.environ.copy()
    env.update(
        HOME=str(home),
        XDG_CONFIG_HOME=str(home / ".config"),
        PATH=f"{home}/.local/bin:{env['PATH']}",
        UV_CACHE_DIR=original_uv_cache,
        UV_OFFLINE="1",
    )
    command = [str(ROOT / "install.sh"), "--unattended"]

    result = subprocess.run(
        command, env=env, text=True, capture_output=True, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "set -g mouse off" in tmux_config.read_text()
    assert "tmux/tacmux-integration.conf" in tmux_config.read_text()

    result = subprocess.run(
        command, env=env, text=True, capture_output=True, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "tmux/tacmux-integration.conf" in tmux_config.read_text()

    result = subprocess.run(
        [*command, "--full-tmux"],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "tmux/tacmux.conf" in tmux_config.read_text()
    assert "tmux/tacmux-integration.conf" not in tmux_config.read_text()

    result = subprocess.run(
        command, env=env, text=True, capture_output=True, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "tmux/tacmux.conf" in tmux_config.read_text()
    assert "TMUX_MODE=full\n" == (
        home / ".config/tacmux/install-state"
    ).read_text()


def test_uninstaller_refuses_unmarked_install_directory(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    install = home / ".local/share/tacmux"
    install.mkdir(parents=True)
    sentinel = install / "keep"
    sentinel.write_text("safe")
    env = os.environ.copy()
    env.update(HOME=str(home))
    result = subprocess.run(
        [str(ROOT / "uninstall.sh")],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    assert sentinel.read_text() == "safe"
    assert "Skipped unmarked" in result.stderr


def test_uninstall_preserves_unrelated_command_and_unmatched_config(tmp_path):
    home = tmp_path / "home"
    install = home / ".local/share/tacmux"
    binary = home / ".local/bin/tacmux"
    install.mkdir(parents=True)
    binary.parent.mkdir(parents=True)
    (install / ".tacmux-install").write_text("tacmux-v2\n")
    binary.write_text("operator command\n")
    shell_config = home / ".zshrc"
    original = "before\n# >>> TACMUX >>>\nafter must survive\n"
    shell_config.write_text(original)
    env = os.environ.copy()
    env.update(HOME=str(home))

    result = subprocess.run(
        [str(ROOT / "uninstall.sh")],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert shell_config.read_text() == original
    assert binary.read_text() == "operator command\n"
    assert install.is_dir()

    shell_config.write_text("# operator config\n")
    result = subprocess.run(
        [str(ROOT / "uninstall.sh")],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    assert binary.read_text() == "operator command\n"
    assert "Preserved unrelated command" in result.stderr


def test_installer_refuses_unmarked_or_custom_install_directory(tmp_path):
    home = tmp_path / "home"
    install = home / ".local/share/tacmux"
    install.mkdir(parents=True)
    sentinel = install / "src/keep"
    sentinel.parent.mkdir()
    sentinel.write_text("operator data")
    env = os.environ.copy()
    env.update(HOME=str(home))
    result = subprocess.run(
        [str(ROOT / "install.sh"), "--unattended", "--skip-tmux"],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert sentinel.read_text() == "operator data"
    assert "unmarked install directory" in result.stderr

    env["TACMUX_HOME"] = str(tmp_path / "custom")
    result = subprocess.run(
        [str(ROOT / "install.sh"), "--unattended", "--skip-tmux"],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert "TACMUX_HOME is not supported" in result.stderr


def test_failed_upgrade_restores_previous_application(tmp_path):
    home = tmp_path / "home"
    install = home / ".local/share/tacmux"
    old_app = install / "app"
    old_app.mkdir(parents=True)
    (install / ".tacmux-install").write_text("tacmux-v2\n")
    sentinel = old_app / "previous-version"
    sentinel.write_text("still usable")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_uv = fake_bin / "uv"
    fake_uv.write_text("#!/bin/sh\nexit 42\n")
    fake_uv.chmod(0o700)
    env = os.environ.copy()
    env.update(HOME=str(home), PATH=f"{fake_bin}:{env['PATH']}")
    result = subprocess.run(
        [str(ROOT / "install.sh"), "--unattended", "--skip-tmux"],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 42
    assert sentinel.read_text() == "still usable"
    assert not list(install.glob(".app-*"))


def test_installer_refuses_unmatched_configuration_block_before_upgrade(tmp_path):
    home = tmp_path / "home"
    install = home / ".local/share/tacmux"
    app = install / "app"
    app.mkdir(parents=True)
    (install / ".tacmux-install").write_text("tacmux-v2\n")
    sentinel = app / "previous-version"
    sentinel.write_text("unchanged")
    shell_config = home / ".zshrc"
    original = "before\n# <<< TACMUX <<<\nmiddle\n# >>> TACMUX >>>\nafter\n"
    shell_config.write_text(original)
    env = os.environ.copy()
    env.update(HOME=str(home))
    result = subprocess.run(
        [str(ROOT / "install.sh"), "--unattended", "--skip-tmux"],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert "malformed TACMUX markers" in result.stderr
    assert shell_config.read_text() == original
    assert sentinel.read_text() == "unchanged"
