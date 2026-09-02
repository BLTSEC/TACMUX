from __future__ import annotations

import pytest

from tacmux.errors import ValidationError
from tacmux.hooks import LogController


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
