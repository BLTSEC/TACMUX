"""Resolve the engagement context exported into TACMUX tmux sessions."""

from __future__ import annotations

import os

from .config import Settings
from .errors import ValidationError
from .model import Target
from .store import EngagementRecord, Workspace
from .tmux import TmuxService


def resolve(
    settings: Settings, tmux: TmuxService | None = None
) -> tuple[EngagementRecord, Target | None]:
    tmux = tmux or TmuxService(settings)
    engagement_id = os.environ.get("TACMUX_ENGAGEMENT_ID", "")
    target_id = os.environ.get("TACMUX_TARGET_ID", "")
    if not engagement_id:
        engagement_id, target_id = tmux.current_context()
    if not engagement_id:
        raise ValidationError(
            "Run this inside a TACMUX target or operations session"
        )
    record = Workspace(settings).find(engagement_id)
    target = record.engagement.target_by_id(target_id) if target_id else None
    return record, target
