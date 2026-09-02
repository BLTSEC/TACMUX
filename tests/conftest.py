from __future__ import annotations

from pathlib import Path

import pytest

from tacmux.config import Settings
from tacmux.workspace import Workspace


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
