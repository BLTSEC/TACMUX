from __future__ import annotations

import hashlib
import os

import pytest

import tacmux.export as export_module
from tacmux.export import (
    ExportProfile,
    create_handoff,
    parse_export_profile,
    render_handoff,
)
from tacmux.errors import ValidationError
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


def test_handoff_contains_all_records_and_readable_authored_markdown(
    workspace, record
):
    target, evidence, binary = _populated_record(workspace, record)
    document = render_handoff(
        record,
        profile=ExportProfile.HANDOFF,
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
    assert "# TACMUX Engagement Handoff" in document
    assert "**Export format:** `tacmux.handoff/v1`" in document
    assert "**Profile:** handoff" in document
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
    assert "#### Engagement —" in document
    assert "`````markdown" not in document
    assert "TACMUX closed an unterminated source fence" in document
    notes_start = document.index("### `targets/T0001-WEB01/NOTES.md`")
    discovery_start = document.index("## Discovery History")
    assert document[notes_start:discovery_start].count("````") == 2
    assert "](findings/F0001.md)" not in document
    assert "External DMZ (S0001)" in document
    assert document.count("## Engagement Snapshot") == 1
    assert document.count("## Targets and Services") == 1
    assert "## Complete Structured Records" not in document
    assert "## SITREP" not in document
    assert document.index("## Machine-readable Manifest") > document.index(
        "## Evidence Coverage and Inventory"
    )


def test_full_context_embeds_clean_text_but_not_binary(workspace, record):
    _, evidence, binary = _populated_record(workspace, record)
    document = render_handoff(record, profile=ExportProfile.FULL)
    assert "22/tcp open ssh" in document
    assert "progress 100%" in document
    assert "\x1b" not in document
    binary_row = binary.relative_to(record.root).as_posix()
    assert f"`{binary_row}`" in document
    assert "| binary |" in document
    assert evidence.relative_to(record.root).as_posix() in document
    assert document.index("## Machine-readable Manifest") < document.index(
        "## Embedded Evidence Excerpts"
    )


def test_export_profile_names_and_compatibility_aliases():
    assert parse_export_profile("handoff") == ExportProfile.HANDOFF
    assert parse_export_profile("full") == ExportProfile.FULL
    assert parse_export_profile("compact") == ExportProfile.HANDOFF
    assert parse_export_profile("evidence") == ExportProfile.FULL
    with pytest.raises(ValidationError, match="handoff or full"):
        parse_export_profile("everything")


def test_full_context_prioritizes_references_and_indexes_job_internals(
    workspace, record, monkeypatch
):
    _, evidence, _ = _populated_record(workspace, record)
    job_root = record.root / ".tacmux/jobs/J0001"
    job_root.mkdir(parents=True)
    (job_root / "job.json").write_text('{"administrative":"do not embed this"}')
    (job_root / "raw.xml").write_text("<administrative>raw scanner XML</administrative>")
    fake_home = record.root.parent.parent
    monkeypatch.setattr(export_module.Path, "home", lambda: fake_home)
    home_relative = record.root.relative_to(fake_home).as_posix()
    scan_text = (
        f"Useful scan at {record.root}/targets and ~/{home_relative}/loot; "
        "retain /opt/client/evidence\n"
    )
    scan_log = job_root / "nmap.log"
    scan_log.write_text(scan_text)

    document = render_handoff(record, profile=ExportProfile.FULL)

    assert "Useful scan at <ENGAGEMENT_ROOT>/targets" in document
    assert "and <ENGAGEMENT_ROOT>/loot" in document
    assert "/opt/client/evidence" in document
    assert str(record.root) not in document
    assert "do not embed this" not in document
    assert "raw scanner XML" not in document
    assert "`.tacmux/jobs/J0001/job.json`" in document
    assert "`.tacmux/jobs/J0001/raw.xml`" in document
    assert hashlib.sha256(scan_text.encode()).hexdigest() in document
    referenced_heading = f"### `{evidence.relative_to(record.root).as_posix()}`"
    assert document.index(referenced_heading) < document.index(
        "### `.tacmux/jobs/J0001/nmap.log`"
    )


def test_full_context_reports_truncation_and_total_limit(
    workspace, record, monkeypatch
):
    target, evidence, _ = _populated_record(workspace, record)
    extra = record.root / "targets" / target.directory / "loot/unreferenced.txt"
    extra.write_text("UNREFERENCED-NOISE")
    monkeypatch.setattr(export_module, "PER_FILE_TEXT_LIMIT", 16)
    monkeypatch.setattr(export_module, "TOTAL_TEXT_LIMIT", 16)

    document = render_handoff(record, profile=ExportProfile.FULL)

    evidence_path = evidence.relative_to(record.root).as_posix()
    extra_path = extra.relative_to(record.root).as_posix()
    assert f"| `{evidence_path}`" in document
    assert "| embedded, truncated |" in document
    assert f"| `{extra_path}`" in document
    assert "| omitted: total limit |" in document
    assert "UNREFERENCED-NOISE" not in document
    assert "- **Truncated excerpts:** 1" in document


def test_handoff_flags_report_and_cleanup_attention_items(workspace, record):
    _populated_record(workspace, record)

    document = render_handoff(record, profile=ExportProfile.HANDOFF)

    assert (
        "Finding F0001 has empty or missing sections: Summary, Evidence, Impact"
        in document
    )
    assert "Outstanding cleanup remains: C0001" in document


def test_create_handoff_is_private_unique_and_excludes_prior_exports(
    workspace, record
):
    _populated_record(workspace, record)
    first = create_handoff(record, profile=ExportProfile.HANDOFF)
    second = create_handoff(record, profile=ExportProfile.HANDOFF)
    full = create_handoff(record, profile=ExportProfile.FULL)
    assert first != second
    assert first.parent == record.root / "exports"
    assert first.stat().st_mode & 0o777 == 0o600
    assert second.stat().st_mode & 0o777 == 0o600
    assert first.name not in second.read_text()
    assert first.name.endswith(f"-{record.engagement.id}-handoff.md")
    assert full.name.endswith(f"-{record.engagement.id}-full.md")


def test_handoff_does_not_follow_evidence_symlinks(workspace, record, tmp_path):
    target, _, _ = _populated_record(workspace, record)
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("must not be exported")
    link = record.root / "targets" / target.directory / "loot/outside.txt"
    os.symlink(outside, link)
    document = render_handoff(record, profile=ExportProfile.FULL)
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

    document = render_handoff(record, profile=ExportProfile.FULL)

    assert "must not be exported" not in document
    assert f"Referenced evidence is missing: {reference.as_posix()}" in document
