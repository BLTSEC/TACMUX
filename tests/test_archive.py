from __future__ import annotations

from dataclasses import asdict
import json
import stat

import pytest

from tacmux.archive import (
    create_archive,
    restore_archive,
    restore_target_archive,
    verify_archive,
)
from tacmux.errors import ConflictError, SafetyError, ValidationError
from tacmux.model import EngagementStatus, ScopeGroup, TargetAddress


def test_archive_hashes_members_verifies_and_restores(tmp_path):
    source = tmp_path / "T0001-mail"
    (source / "logs").mkdir(parents=True)
    (source / "logs/session.log").write_text("operator output\n")
    (source / "NOTES.md").write_text("# Notes\n")
    source.chmod(0o755)
    (source / "logs/session.log").chmod(0o644)
    archive, manifest = create_archive(
        source,
        tmp_path / "archives",
        kind="targets",
        engagement_id="E-0123456789ab",
        object_id="T0001",
        object_metadata={"id": "T0001", "directory": source.name},
    )
    document = verify_archive(archive)
    assert document["schema"] == "tacmux.archive/v2"
    assert document["contents"]["file_count"] == 2
    assert stat.S_IMODE(archive.stat().st_mode) == 0o600
    assert stat.S_IMODE(manifest.stat().st_mode) == 0o600
    source.rename(tmp_path / "original-away")
    restored = restore_archive(archive, tmp_path)
    assert (restored / "logs/session.log").read_text() == "operator output\n"
    assert stat.S_IMODE(restored.stat().st_mode) == 0o700
    assert stat.S_IMODE((restored / "logs/session.log").stat().st_mode) == 0o600
    with pytest.raises(ConflictError, match="already exists"):
        restore_archive(archive, tmp_path)


def test_archive_tampering_and_forged_source_name_are_rejected(tmp_path):
    source = tmp_path / "evidence"
    source.mkdir()
    (source / "proof.txt").write_text("confirmed")
    archive, manifest = create_archive(
        source,
        tmp_path / "archives",
        kind="engagements",
        engagement_id="E-0123456789ab",
        object_id="E-0123456789ab",
    )
    document = json.loads(manifest.read_text())
    document["context"]["source_name"] = "../escape"
    manifest.write_text(json.dumps(document))
    with pytest.raises(SafetyError, match="source name"):
        verify_archive(archive)

    document["context"]["source_name"] = source.name
    manifest.write_text(json.dumps(document))
    with archive.open("ab") as stream:
        stream.write(b"tamper")
    with pytest.raises(ValidationError, match="size"):
        verify_archive(archive)


def test_absolute_archive_symlink_is_not_restorable(tmp_path):
    source = tmp_path / "evidence"
    source.mkdir()
    (source / "unsafe").symlink_to("/etc/passwd")
    with pytest.raises(SafetyError, match="unsafe archive link"):
        create_archive(
            source,
            tmp_path / "archives",
            kind="targets",
            engagement_id="E-0123456789ab",
            object_id="T0001",
            object_metadata={"id": "T0001", "directory": source.name},
        )


def test_failed_restore_leaves_no_partial_destination(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "proof.txt").write_text("evidence")
    archive, _ = create_archive(
        source,
        tmp_path / "archives",
        kind="engagements",
        engagement_id="E-0123456789ab",
        object_id="E-0123456789ab",
    )
    source.rename(tmp_path / "source-away")

    def fail_hardening(*_):
        raise OSError("permission failure")

    monkeypatch.setattr("tacmux.archive.harden_private_tree", fail_hardening)
    with pytest.raises(OSError, match="permission failure"):
        restore_archive(archive, tmp_path)
    assert not (tmp_path / "source").exists()
    assert not list(tmp_path.glob(".tacmux-restore-*"))


def test_archive_manifest_requires_structured_sections(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "proof.txt").write_text("evidence")
    archive, manifest = create_archive(
        source,
        tmp_path / "archives",
        kind="engagements",
        engagement_id="E-0123456789ab",
        object_id="E-0123456789ab",
    )
    manifest.write_text("[]")
    with pytest.raises(ValidationError, match="JSON object"):
        verify_archive(archive)


def test_target_archive_restore_commits_manifest_and_files(workspace, record):
    scope = record.engagement.add_scope(
        "LAN", ScopeGroup.INTERNAL, "10.44.0.0/24"
    )
    target = workspace.create_target(
        record.root,
        record.engagement,
        "host",
        addresses=[TargetAddress("10.44.0.10", scope.id)],
        primary_endpoint="10.44.0.10",
    )
    target_root = record.root / "targets" / target.directory
    (target_root / "recon/scan.txt").write_text("evidence")
    archive, _ = create_archive(
        target_root,
        workspace.settings.archive_dir,
        kind="targets",
        engagement_id=record.engagement.id,
        object_id=target.id,
        object_metadata=asdict(target),
    )
    workspace.delete_target(record.root, record.engagement, target.id)
    context = verify_archive(archive)["context"]

    restored = restore_target_archive(
        archive, workspace, record.root, record.engagement, context
    )
    assert (restored / "recon/scan.txt").read_text() == "evidence"
    assert workspace.load(record.root).target_by_id(target.id) == target


def test_closed_engagement_refuses_target_restore(workspace, record):
    target = workspace.create_target(record.root, record.engagement, "host")
    target_root = record.root / "targets" / target.directory
    archive, _ = create_archive(
        target_root,
        workspace.settings.archive_dir,
        kind="targets",
        engagement_id=record.engagement.id,
        object_id=target.id,
        object_metadata=asdict(target),
    )
    workspace.delete_target(record.root, record.engagement, target.id)
    workspace.set_status(record.root, record.engagement, EngagementStatus.CLOSED)

    with pytest.raises(ConflictError, match="closed"):
        restore_target_archive(
            archive,
            workspace,
            record.root,
            record.engagement,
            verify_archive(archive)["context"],
        )


def test_target_archive_restore_rolls_back_files_when_save_fails(
    workspace, record, monkeypatch
):
    target = workspace.create_target(record.root, record.engagement, "unresolved")
    target_root = record.root / "targets" / target.directory
    archive, _ = create_archive(
        target_root,
        workspace.settings.archive_dir,
        kind="targets",
        engagement_id=record.engagement.id,
        object_id=target.id,
        object_metadata=asdict(target),
    )
    workspace.delete_target(record.root, record.engagement, target.id)
    context = verify_archive(archive)["context"]
    before = record.engagement.to_dict()

    def fail_save(*_):
        raise OSError("disk full")

    monkeypatch.setattr(workspace, "save", fail_save)
    with pytest.raises(OSError, match="disk full"):
        restore_target_archive(
            archive, workspace, record.root, record.engagement, context
        )
    assert record.engagement.to_dict() == before
    assert not target_root.exists()
