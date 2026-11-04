"""The test runner must not resolve an operator's live engagement or config."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

from tacmux.config import Settings, load_settings
from tacmux.workspace import Workspace


ROOT = Path(__file__).resolve().parents[1]


def test_default_cli_environment_uses_only_fixture_paths(settings):
    loaded = load_settings()
    assert loaded.workspace == settings.workspace
    assert loaded.config_file == settings.config_file
    assert loaded.sitrep_root is None
    assert not any(name.startswith("NOCAP_") for name in os.environ)
    assert (
        not {"TACMUX_ROOT", "TACMUX_TARGET_NAME", "TMUX", "TMUX_PANE"}
        & os.environ.keys()
    )


def test_pytest_does_not_modify_an_inherited_engagement(tmp_path):
    workspace = Workspace(
        Settings(
            workspace=tmp_path / "active-workspace", config_file=tmp_path / "host.toml"
        )
    )
    active = workspace.create_engagement("ACTIVE")
    workspace.add_target(active, "LIVE", "192.0.2.254")
    config = tmp_path / "host.toml"
    config.write_text(f'[paths]\nworkspace = "{workspace.settings.workspace}"\n')
    before = {
        path.relative_to(active): path.read_bytes()
        for path in active.rglob("*")
        if path.is_file()
    }
    environment = os.environ | {
        "TACMUX_ROOT": str(active),
        "TACMUX_TARGET_NAME": "LIVE",
        "TACMUX_WORKSPACE": str(workspace.settings.workspace),
        "TACMUX_CONFIG": str(config),
        "TACMUX_SITREP_ROOT": str(tmp_path / "host-notes"),
        "TACMUX_NONINTERACTIVE": "1",
        "TMUX": f"{tmp_path}/host.sock,1,0",
        "TMUX_PANE": "%99999",
        "NOCAP_WORKSPACE": str(active),
        "NOCAP_ROUTE_PREFIX": "LIVE",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    }
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "tests/test_cli.py::test_cli_operational_flow",
        ],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert workspace.targets(active) == ["LIVE"]
    assert {
        path.relative_to(active): path.read_bytes()
        for path in active.rglob("*")
        if path.is_file()
    } == before
    assert (
        config.read_text() == f'[paths]\nworkspace = "{workspace.settings.workspace}"\n'
    )
