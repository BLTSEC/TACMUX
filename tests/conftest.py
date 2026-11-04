from __future__ import annotations

import os
from pathlib import Path

import pytest

from tacmux.config import Settings
from tacmux.workspace import Workspace


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch, settings):
    """Never let tests resolve an inherited engagement or read host config."""
    for name in tuple(os.environ):
        if name.startswith(("TACMUX_", "NOCAP_")) or name in {
            "TMUX",
            "TMUX_PANE",
            "TMUX_TMPDIR",
            "TARGET",
        }:
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TACMUX_WORKSPACE", str(settings.workspace))
    monkeypatch.setenv("TACMUX_CONFIG", str(settings.config_file))


@pytest.fixture(autouse=True)
def interactive_terminal(monkeypatch):
    """Tests drive prompts through patched input/fzf; pretend a terminal exists."""
    monkeypatch.setattr("tacmux.interaction.text_input_available", lambda: True)
    monkeypatch.setattr("tacmux.interaction.picker_available", lambda: True)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        workspace=tmp_path / "workspace",
        config_file=tmp_path / "config" / "config.toml",
        auto_log=True,
    )


@pytest.fixture
def workspace(settings: Settings) -> Workspace:
    value = Workspace(settings)
    value.initialize()
    return value


@pytest.fixture
def engagement(workspace: Workspace) -> Path:
    return workspace.create_engagement("ACME")
