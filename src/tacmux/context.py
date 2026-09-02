"""Resolve engagement and target context without a persistent manifest."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path

from .config import Settings
from .errors import ValidationError
from .interaction import choose
from .tmux import TmuxService
from .workspace import Workspace


@dataclass(slots=True, frozen=True)
class Context:
    root: Path
    target: str = ""


def _directory_target(root: Path, path: Path, workspace: Workspace) -> str:
    try:
        relative = path.resolve(strict=False).relative_to((root / "targets").resolve())
    except ValueError:
        return ""
    return workspace.canonical_target(root, relative.parts[0]) if relative.parts else ""


def resolve(
    settings: Settings,
    tmux: TmuxService | None = None,
    *,
    require_target: bool = False,
    allow_picker: bool = True,
) -> Context:
    workspace = Workspace(settings)
    tmux = tmux or TmuxService(settings)
    root: Path | None = None
    target = ""

    in_tmux = bool(os.environ.get("TMUX"))
    if in_tmux:
        root, target = tmux.current_context()
        environment_root = os.environ.get("TACMUX_ROOT", "")
        environment_target = os.environ.get("TACMUX_TARGET_NAME", "")
        if root:
            if environment_root and Path(environment_root) != root:
                raise ValidationError("tmux pane metadata disagrees with TACMUX_ROOT")
            if environment_target and environment_target != target:
                raise ValidationError(
                    "tmux pane metadata disagrees with TACMUX_TARGET_NAME"
                )
    if root is None and not in_tmux:
        environment_root = os.environ.get("TACMUX_ROOT", "")
        if environment_root:
            root = Path(environment_root)
            target = os.environ.get("TACMUX_TARGET_NAME", "")
    if root is None:
        root = workspace.find_root(Path.cwd())
        if root:
            target = _directory_target(root, Path.cwd(), workspace)
    if root is None:
        engagements = workspace.engagements()
        if len(engagements) == 1:
            root = engagements[0]
        elif allow_picker and engagements:
            selected = choose(
                [(path.name, str(path)) for path in engagements], "Engagement> "
            )
            root = Path(selected)
        else:
            raise ValidationError("no engagement context; run tacmux init NAME")
    workspace.require_engagement(root)
    if target:
        target = workspace.canonical_target(root, target)
    if require_target and not target:
        targets = workspace.targets(root)
        if not targets:
            raise ValidationError("engagement has no targets")
        if allow_picker:
            target = choose([(name, name) for name in targets], "Target> ")
        else:
            raise ValidationError("this command requires a target")
    return Context(root, target)
