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
    environment_engagement = os.environ.get("TACMUX_ENGAGEMENT_ID", "")
    environment_target = os.environ.get("TACMUX_TARGET_ID", "")
    if os.environ.get("TMUX"):
        engagement_id, target_id = tmux.current_context()
        if not engagement_id:
            raise ValidationError(
                "Current tmux pane is not owned by TACMUX; open the cockpit from "
                "a TACMUX target or operations session"
            )
        disagreements = []
        if environment_engagement and environment_engagement != engagement_id:
            disagreements.append("engagement")
        if environment_target and environment_target != target_id:
            disagreements.append("target")
        if disagreements:
            raise ValidationError(
                "TACMUX pane metadata disagrees with inherited "
                + " and ".join(disagreements)
                + " environment; open a fresh shell in this session"
            )
    else:
        engagement_id, target_id = environment_engagement, environment_target
    if not engagement_id:
        raise ValidationError(
            "Run this inside a TACMUX target or operations session"
        )
    record = Workspace(settings).find(engagement_id)
    target = record.engagement.target_by_id(target_id) if target_id else None
    return record, target
