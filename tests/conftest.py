from __future__ import annotations

from pathlib import Path

import pytest

from tacmux.config import Settings
from tacmux.workspace import Workspace


@pytest.fixture(autouse=True)
def interactive_terminal(monkeypatch):
    """Tests drive prompts through patched input/fzf; pretend a terminal exists."""
    monkeypatch.delenv("TACMUX_NONINTERACTIVE", raising=False)
    # Tests run hermetically even when started from inside tmux.
    monkeypatch.delenv("TMUX", raising=False)
    monkeypatch.delenv("TMUX_PANE", raising=False)
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
