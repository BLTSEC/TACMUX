from __future__ import annotations

from pathlib import Path

import pytest

from tacmux.config import Settings
from tacmux.model import AssessmentType
from tacmux.store import Workspace


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    config_file = tmp_path / "config" / "config.toml"
    return Settings(
        workspace=tmp_path / "workspace",
        archive_dir=tmp_path / "archives",
        log_dir=tmp_path / "logs",
        config_file=config_file,
        state_file=config_file.parent / "state.json",
        auto_log=True,
        startup="picker",
        include_mermaid=True,
        nocap_enabled=False,
    )


@pytest.fixture
def workspace(settings: Settings) -> Workspace:
    value = Workspace(settings)
    value.initialize()
    return value


@pytest.fixture
def record(workspace: Workspace):
    return workspace.create_engagement(
        "ACME", "2026 Security Assessment", AssessmentType.BOTH
    )
