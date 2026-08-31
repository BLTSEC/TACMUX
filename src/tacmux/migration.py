"""Copy-only importer for v1 engagement workspaces."""

from __future__ import annotations

from pathlib import Path
import shutil

from .errors import ConflictError, ValidationError
from .model import AssessmentType
from .store import (
    EngagementRecord,
    Workspace,
    _private_directory,
    harden_private_tree,
)


def import_v1_workspace(
    workspace: Workspace,
    source: Path,
    *,
    client: str,
    name: str,
    assessment_type: AssessmentType,
) -> EngagementRecord:
    source = source.expanduser().resolve(strict=True)
    if not source.is_dir():
        raise ValidationError(f"legacy source is not a directory: {source}")
    try:
        source.relative_to(workspace.settings.workspace.resolve(strict=False))
    except ValueError:
        pass
    else:
        raise ConflictError("copy-only import source must be outside the v2 workspace")

    target_source = source / "targets" if (source / "targets").is_dir() else source
    candidates = [
        path
        for path in sorted(target_source.iterdir())
        if path.is_dir() and path.name not in {"notes", "findings", ".nocap", ".tacmux"}
    ]
    if not candidates:
        raise ValidationError("legacy source contains no target directories")

    record = workspace.create_engagement(client, name, assessment_type)
    for legacy_target in candidates:
        target = workspace.create_target(
            record.root, record.engagement, legacy_target.name
        )
        destination = record.root / "targets" / target.directory
        shutil.copytree(legacy_target, destination, dirs_exist_ok=True, symlinks=True)
        harden_private_tree(destination)

    legacy_root = record.root / "legacy-import"
    _private_directory(legacy_root)
    for relative in ("ENGAGEMENT.md", "notes", "findings"):
        item = source / relative
        if not item.exists():
            continue
        destination = legacy_root / relative
        if item.is_dir():
            shutil.copytree(item, destination, dirs_exist_ok=True, symlinks=True)
        else:
            shutil.copy2(item, destination, follow_symlinks=False)
    harden_private_tree(legacy_root)
    workspace.render_documents(record.root, record.engagement)
    return record
