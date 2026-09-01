from __future__ import annotations

import os

from tacmux.export import ExportProfile, create_handoff, render_handoff
from tacmux.model import (
    AccessLevel,
    ActivityResult,
    CleanupKind,
    FindingState,
    ScopeGroup,
    Severity,
    TargetAddress,
)


def _populated_record(workspace, record):
    scope = workspace.add_scope(
        record.root,
        record.engagement,
        "External DMZ",
        ScopeGroup.EXTERNAL,
        "198.51.100.0/24",
    )
    target = workspace.create_target(
        record.root,
        record.engagement,
        "WEB01",
        addresses=[TargetAddress("198.51.100.25", scope.id)],
        hostnames=["web01.acme.test"],
        primary_endpoint="198.51.100.25",
    )
    evidence = record.root / "targets" / target.directory / "recon/scan.log"
    evidence.write_bytes(b"\x1b[32m22/tcp open ssh\x1b[0m\nprogress 10%\rprogress 100%\n")
    binary = record.root / "targets" / target.directory / "screenshots/proof.png"
    binary.write_bytes(b"\x89PNG\r\n\x1a\n\0binary")
    notes = record.root / "targets" / target.directory / "NOTES.md"
    notes.write_text(notes.read_text() + "\nObserved public login portal.\n````\n")
    workspace.create_access(
        record.root,
        record.engagement,
        target.id,
        principal="operator",
        authority="ACME",
        method="SSH key",
        level=AccessLevel.USER_EXECUTION,
        evidence=evidence.relative_to(record.root).as_posix(),
    )
    activity = workspace.create_activity(
        record.root,
        record.engagement,
        summary="Established initial access",
        result=ActivityResult.CONFIRMED,
        target_id=target.id,
        evidence=evidence.relative_to(record.root).as_posix(),
    )
    finding = workspace.create_finding(
        record.root,
        record.engagement,
        title="Exposed administrative service",
        severity=Severity.HIGH,
        state=FindingState.CONFIRMED,
        target_ids=[target.id],
        evidence=[evidence.relative_to(record.root).as_posix()],
    )
    finding_path = record.root / finding.document
    finding_path.write_text(finding_path.read_text() + "The service permitted access.\n")
    workspace.create_attack_path(
        record.root,
        record.engagement,
        "Initial access",
        [
            ("activity", activity.id, "Reached WEB01"),
            ("finding", finding.id, "Validated exposure"),
        ],
    )
    workspace.create_cleanup_item(
        record.root,
        record.engagement,
        target_id=target.id,
        kind=CleanupKind.FILE,
        location="/tmp/tacmux-marker",
        note="Remove after validation",
    )
    return target, evidence, binary


def test_compact_handoff_contains_all_records_and_authored_markdown(
    workspace, record
):
    target, evidence, binary = _populated_record(workspace, record)
    document = render_handoff(
        record,
        profile=ExportProfile.COMPACT,
        live_target_ids={target.id},
        jobs=[
            {
                "id": "J0001",
                "profile": "tcp-services",
                "pace": "careful",
                "state": "succeeded",
                "scope_ids": [record.engagement.scope[0].id],
            }
        ],
        generated_at="2026-08-31T12:00:00Z",
    )
    assert "# TACMUX Handoff" in document
    assert "Established initial access" in document
    assert "Exposed administrative service" in document
    assert "The service permitted access" in document
    assert "Observed public login portal" in document
    assert "Initial access" in document
    assert "Remove after validation" in document
    assert evidence.relative_to(record.root).as_posix() in document
    assert binary.relative_to(record.root).as_posix() in document
    assert "22/tcp open ssh" not in document
    assert '"revision":' in document
    assert "`````markdown" in document


def test_evidence_handoff_embeds_clean_text_but_not_binary(workspace, record):
    _, evidence, binary = _populated_record(workspace, record)
    document = render_handoff(record, profile=ExportProfile.EVIDENCE)
    assert "22/tcp open ssh" in document
    assert "progress 100%" in document
    assert "\x1b" not in document
    assert f"`{binary.relative_to(record.root).as_posix()}` is binary" in document
    assert evidence.relative_to(record.root).as_posix() in document


def test_create_handoff_is_private_unique_and_excludes_prior_exports(
    workspace, record
):
    _populated_record(workspace, record)
    first = create_handoff(record, profile=ExportProfile.COMPACT)
    second = create_handoff(record, profile=ExportProfile.COMPACT)
    assert first != second
    assert first.parent == record.root / "exports"
    assert first.stat().st_mode & 0o777 == 0o600
    assert second.stat().st_mode & 0o777 == 0o600
    assert first.name not in second.read_text()


def test_handoff_does_not_follow_evidence_symlinks(workspace, record, tmp_path):
    target, _, _ = _populated_record(workspace, record)
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("must not be exported")
    link = record.root / "targets" / target.directory / "loot/outside.txt"
    os.symlink(outside, link)
    document = render_handoff(record, profile=ExportProfile.EVIDENCE)
    assert "must not be exported" not in document
    assert "loot/outside.txt" not in document


def test_handoff_rejects_evidence_below_a_linked_directory(
    workspace, record, tmp_path
):
    target, _, _ = _populated_record(workspace, record)
    outside = tmp_path / "outside-evidence"
    outside.mkdir()
    (outside / "proof.txt").write_text("must not be exported")
    link = record.root / "targets" / target.directory / "loot/linked"
    link.symlink_to(outside, target_is_directory=True)
    reference = link.relative_to(record.root) / "proof.txt"
    workspace.create_activity(
        record.root,
        record.engagement,
        summary="Referenced linked proof",
        result=ActivityResult.CONFIRMED,
        target_id=target.id,
        evidence=reference.as_posix(),
    )

    document = render_handoff(record, profile=ExportProfile.EVIDENCE)

    assert "must not be exported" not in document
    assert f"Referenced evidence is missing: {reference.as_posix()}" in document
