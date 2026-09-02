from __future__ import annotations

import subprocess

import pytest

from tacmux.errors import ValidationError
from tacmux.hooks import LogController, status_segment


def test_log_root_must_match_owning_engagement(settings, engagement):
    controller = LogController(settings)
    assert (
        controller._validated_session_log_root(
            str(engagement / "logs"), str(engagement)
        )
        == engagement / "logs"
    )

    other = settings.workspace / "OTHER"
    other.mkdir()
    with pytest.raises(ValidationError, match="does not match"):
        controller._validated_session_log_root(str(other / "logs"), str(engagement))


def test_status_segment_uses_engagement_name_for_operations_session(
    settings, engagement, monkeypatch
):
    class FakeTmux:
        def run(self, args, **kwargs):
            return subprocess.CompletedProcess(
                args, 0, f"\t{engagement}\t1\n", ""
            )

    monkeypatch.setenv("TMUX", "1")
    assert f"[{engagement.name} LOG]" in status_segment(settings, FakeTmux())
