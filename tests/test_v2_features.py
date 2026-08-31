from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from threading import Event
import ipaddress
import json
import subprocess

import pytest

from tacmux.discovery import (
    DiscoveryCandidate,
    DiscoveryJobs,
    Reconciliation,
    apply_reconciliation,
    parse_host_lines,
    parse_nmap_xml,
    reconcile_candidates,
)
from tacmux.errors import ConflictError, ValidationError
from tacmux.hooks import LogController
from tacmux.model import (
    ActivityResult,
    Authorization,
    CleanupKind,
    Engagement,
    FindingState,
    ScopeGroup,
    ScopeKind,
    Service,
    Severity,
    TargetAddress,
    hostname_matches,
    pattern_inside,
)
from tacmux.render import render_sitrep
from tacmux.panes import DocumentsPane


def test_scope_exclusions_are_enforced_in_model_and_discovery(workspace, record):
    scope = workspace.add_scope(
        record.root,
        record.engagement,
        "Corporate LAN",
        ScopeGroup.INTERNAL,
        "10.77.10.0/24",
        exclusions=["10.77.10.250/32"],
    )
    assert scope.contains(ipaddress.ip_address("10.77.10.20"))
    assert not scope.contains(ipaddress.ip_address("10.77.10.250"))
    decision = reconcile_candidates(
        record.engagement,
        [DiscoveryCandidate(["10.77.10.250"])],
        allowed_scope_ids={scope.id},
    )[0]
    assert decision.allowed_actions == ("ignore",)
    assert "excluded" in decision.note
    with pytest.raises(ValidationError, match="excluded"):
        workspace.create_target(
            record.root,
            record.engagement,
            "production-db",
            addresses=[TargetAddress("10.77.10.250", scope.id)],
            primary_endpoint="10.77.10.250",
        )


def test_domain_scope_is_strict_and_hostname_import_is_contained(
    workspace, record, settings, monkeypatch
):
    domain = workspace.add_scope(
        record.root,
        record.engagement,
        "Web apps",
        ScopeGroup.EXTERNAL,
        "*.acme.test",
        exclusions=["admin.acme.test"],
    )
    assert domain.kind == ScopeKind.DOMAIN
    assert hostname_matches("*.acme.test", "shop.acme.test")
    assert not hostname_matches("*.acme.test", "acme.test")
    assert pattern_inside("admin.acme.test", "*.acme.test")
    candidates = parse_host_lines("shop.acme.test\nadmin.acme.test\nacme.test\n")
    decisions = reconcile_candidates(
        record.engagement, candidates, allowed_scope_ids={domain.id}
    )
    assert [item.action for item in decisions] == ["add", "ignore", "ignore"]
    assert "excluded" in decisions[1].note
    assert "outside" in decisions[2].note
    created = apply_reconciliation(
        workspace,
        record.root,
        record.engagement,
        decisions,
        allowed_scope_ids={domain.id},
    )
    assert [item.primary_endpoint for item in created] == ["shop.acme.test"]
    with pytest.raises(ValidationError, match="not inside declared domain scope"):
        workspace.create_target(
            record.root,
            record.engagement,
            "rogue",
            hostnames=["rogue.example.test"],
            primary_endpoint="rogue.example.test",
        )
    forged = Reconciliation(
        DiscoveryCandidate([], ["rogue.example.test"]),
        [],
        "add",
        hostname_scope_id=domain.id,
    )
    with pytest.raises(ValidationError, match="not allowed"):
        apply_reconciliation(
            workspace,
            record.root,
            record.engagement,
            [forged],
            allowed_scope_ids={domain.id},
        )
    monkeypatch.setattr("tacmux.discovery.shutil.which", lambda _name: "/usr/bin/nmap")
    with pytest.raises(ValidationError, match="domain scope entries cannot be scanned"):
        DiscoveryJobs(settings).create(record.root, record.engagement, [domain.id])


def test_hostname_primary_is_contained_even_when_target_has_an_address(
    workspace, record
):
    network = workspace.add_scope(
        record.root,
        record.engagement,
        "DMZ",
        ScopeGroup.EXTERNAL,
        "198.51.100.0/24",
    )
    workspace.add_scope(
        record.root,
        record.engagement,
        "Web apps",
        ScopeGroup.EXTERNAL,
        "*.acme.test",
    )
    with pytest.raises(ValidationError, match="not inside declared domain scope"):
        workspace.create_target(
            record.root,
            record.engagement,
            "unsafe-primary",
            addresses=[TargetAddress("198.51.100.25", network.id)],
            hostnames=["rogue.example.test"],
            primary_endpoint="rogue.example.test",
        )

    target = workspace.create_target(
        record.root,
        record.engagement,
        "web",
        addresses=[TargetAddress("198.51.100.25", network.id)],
        hostnames=["rogue.example.test", "shop.acme.test"],
        primary_endpoint="198.51.100.25",
    )
    workspace.remove_target_address(
        record.root, record.engagement, target.id, 0
    )
    assert target.primary_endpoint == "shop.acme.test"


def test_finding_paths_targets_and_concurrent_creation_are_safe(workspace, record):
    scope = workspace.add_scope(
        record.root,
        record.engagement,
        "DMZ",
        ScopeGroup.EXTERNAL,
        "198.51.100.0/24",
    )
    target = workspace.create_target(
        record.root,
        record.engagement,
        "web",
        addresses=[TargetAddress("198.51.100.25", scope.id)],
        primary_endpoint="198.51.100.25",
    )
    stale = [workspace.load(record.root), workspace.load(record.root)]

    def create(engagement):
        try:
            return workspace.create_finding(
                record.root,
                engagement,
                title="Concurrent finding",
                severity=Severity.MEDIUM,
                state=FindingState.CONFIRMED,
                target_ids=[target.id],
            ).id
        except ConflictError as exc:
            return type(exc).__name__

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(create, stale))
    assert sorted(results) == ["ConflictError", "F0001"]
    loaded = workspace.load(record.root)
    assert [item.id for item in loaded.findings] == ["F0001"]
    assert [path.name for path in (record.root / "findings").glob("F*.md")] == [
        "F0001.md"
    ]

    value = loaded.to_dict()
    value["findings"][0]["document"] = "ENGAGEMENT.md"
    with pytest.raises(ValidationError, match="unsafe finding path"):
        Engagement.from_dict(value)
    value = loaded.to_dict()
    value["findings"][0]["target_ids"] = []
    with pytest.raises(ValidationError, match="invalid finding"):
        Engagement.from_dict(value)
    value = loaded.to_dict()
    value["findings"][0]["target_ids"] = [target.id, target.id]
    with pytest.raises(ValidationError, match="invalid finding"):
        Engagement.from_dict(value)


def test_finding_creation_preserves_a_preexisting_document(workspace, record):
    scope = workspace.add_scope(
        record.root,
        record.engagement,
        "DMZ",
        ScopeGroup.EXTERNAL,
        "198.51.100.0/24",
    )
    target = workspace.create_target(
        record.root,
        record.engagement,
        "web",
        addresses=[TargetAddress("198.51.100.25", scope.id)],
        primary_endpoint="198.51.100.25",
    )
    orphan = record.root / "findings/F0001.md"
    orphan.write_text("operator recovery copy", encoding="utf-8")
    with pytest.raises(ConflictError, match="already exists"):
        workspace.create_finding(
            record.root,
            record.engagement,
            title="Must not replace evidence",
            severity=Severity.MEDIUM,
            state=FindingState.CONFIRMED,
            target_ids=[target.id],
        )
    assert orphan.read_text(encoding="utf-8") == "operator recovery copy"
    assert not record.engagement.findings


def test_target_rename_and_in_pane_note_do_not_overwrite_each_other(
    workspace, record, monkeypatch
):
    scope = workspace.add_scope(
        record.root,
        record.engagement,
        "DMZ",
        ScopeGroup.EXTERNAL,
        "198.51.100.0/24",
    )
    target = workspace.create_target(
        record.root,
        record.engagement,
        "old-name",
        addresses=[TargetAddress("198.51.100.25", scope.id)],
        primary_endpoint="198.51.100.25",
    )
    saved = Event()
    release = Event()
    original_save = workspace.save

    def blocked_save(*args):
        original_save(*args)
        if len(args) >= 3 and args[2] is True:
            saved.set()
            assert release.wait(timeout=5)

    monkeypatch.setattr(workspace, "save", blocked_save)
    with ThreadPoolExecutor(max_workers=2) as executor:
        rename = executor.submit(
            workspace.rename_target,
            record.root,
            record.engagement,
            target.id,
            "new-name",
        )
        assert saved.wait(timeout=5)
        note = executor.submit(
            workspace.append_note,
            record,
            target,
            "concurrent operator note",
        )
        release.set()
        assert rename.result(timeout=5) == ""
        note.result(timeout=5)
    content = (
        record.root / "targets" / target.directory / "NOTES.md"
    ).read_text()
    assert content.startswith("# new-name\n")
    assert "concurrent operator note" in content


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("port", 0, "invalid service port"),
        ("protocol", "icmp", "invalid service protocol"),
        ("state", "closed", "invalid service state"),
        ("source", "../../outside.xml", "unsafe service source"),
    ],
)
def test_service_fields_are_validated(
    workspace, record, field, value, message
):
    scope = workspace.add_scope(
        record.root,
        record.engagement,
        "DMZ",
        ScopeGroup.EXTERNAL,
        "198.51.100.0/24",
    )
    target = workspace.create_target(
        record.root,
        record.engagement,
        "web",
        addresses=[TargetAddress("198.51.100.25", scope.id)],
        primary_endpoint="198.51.100.25",
        services=[Service(443, "tcp", source="evidence/services.xml")],
    )
    document = record.engagement.to_dict()
    service = next(
        item for item in document["targets"] if item["id"] == target.id
    )["services"][0]
    service[field] = value
    with pytest.raises(ValidationError, match=message):
        Engagement.from_dict(document)

    duplicate = record.engagement.to_dict()
    services = next(
        item for item in duplicate["targets"] if item["id"] == target.id
    )["services"]
    services.append(services[0].copy())
    with pytest.raises(ValidationError, match="duplicate services"):
        Engagement.from_dict(duplicate)


def test_existing_v2_manifest_loads_with_new_fields_absent(workspace, record):
    scope = workspace.add_scope(
        record.root,
        record.engagement,
        "DMZ",
        ScopeGroup.EXTERNAL,
        "198.51.100.0/24",
    )
    workspace.create_target(
        record.root,
        record.engagement,
        "web",
        addresses=[TargetAddress("198.51.100.25", scope.id)],
        primary_endpoint="198.51.100.25",
    )
    value = record.engagement.to_dict()
    for key in ("status", "authorization", "cleanup"):
        value.pop(key)
    for item in value["scope"]:
        for key in ("kind", "domain", "exclusions"):
            item.pop(key)
    for item in value["targets"]:
        item.pop("services")
    loaded = Engagement.from_dict(value)
    assert loaded.status.value == "active"
    assert loaded.authorization.window_state() == "none"
    assert loaded.cleanup == []


def test_authorization_window_defaults_validate_and_cleanup_blocks_delete(
    workspace, record
):
    engagement = Engagement.from_dict(record.engagement.to_dict())
    assert engagement.authorization.window_state() == "none"
    engagement.authorization = Authorization(
        authorized_by="ACME",
        reference="SOW-42",
        window_start="2026-08-31T10:00:00Z",
        window_end="2026-08-31T12:00:00Z",
    )
    engagement.validate()
    assert engagement.authorization.window_state(
        datetime(2026, 8, 31, 11, tzinfo=timezone.utc)
    ) == "inside"
    assert engagement.authorization.window_state(
        datetime(2026, 8, 31, 13, tzinfo=timezone.utc)
    ) == "outside"
    engagement.authorization.window_start = "2026-09-01T00:00:00Z"
    with pytest.raises(ValidationError, match="start"):
        engagement.validate()

    scope = workspace.add_scope(
        record.root, record.engagement, "LAN", ScopeGroup.INTERNAL, "10.20.0.0/24"
    )
    target = workspace.create_target(
        record.root,
        record.engagement,
        "host",
        addresses=[TargetAddress("10.20.0.5", scope.id)],
        primary_endpoint="10.20.0.5",
    )
    item = workspace.create_cleanup_item(
        record.root,
        record.engagement,
        target_id=target.id,
        kind=CleanupKind.FILE,
        location="/tmp/agent",
    )
    with pytest.raises(ConflictError, match="cleanup"):
        workspace.delete_target(record.root, record.engagement, target.id)
    workspace.mark_cleanup_removed(record.root, record.engagement, item.id)
    assert item.removed_at
    with pytest.raises(ConflictError, match="cleanup"):
        workspace.delete_target(record.root, record.engagement, target.id)


def test_service_import_merges_and_copies_external_provenance(
    workspace, record, tmp_path, monkeypatch
):
    scope = workspace.add_scope(
        record.root, record.engagement, "DMZ", ScopeGroup.EXTERNAL, "198.51.100.0/24"
    )
    target = workspace.create_target(
        record.root,
        record.engagement,
        "web",
        addresses=[TargetAddress("198.51.100.25", scope.id)],
        primary_endpoint="198.51.100.25",
    )
    xml = tmp_path / "services.xml"
    xml.write_text(
        """<?xml version='1.0'?>
<nmaprun><host><status state='up' reason='echo-reply'/>
<address addr='198.51.100.25' addrtype='ipv4'/><ports>
<port protocol='tcp' portid='443'><state state='open'/>
<service name='https' product='nginx' version='1.26' tunnel='ssl'/></port>
<port protocol='tcp' portid='22'><state state='closed'/></port>
<port protocol='udp' portid='137'><state state='open|filtered'/>
<service name='netbios-ns'/></port></ports></host></nmaprun>"""
    )
    relative = ".tacmux/imports/services.xml"
    candidates = parse_nmap_xml(xml, source=relative)
    assert [(item.port, item.protocol) for item in candidates[0].services] == [
        (443, "tcp"),
        (137, "udp"),
    ]
    decisions = reconcile_candidates(
        record.engagement, candidates, allowed_scope_ids={scope.id}
    )
    destination = record.root / relative
    changed = apply_reconciliation(
        workspace,
        record.root,
        record.engagement,
        decisions,
        allowed_scope_ids={scope.id},
        source_copy=(xml, destination),
    )
    assert changed == [target]
    assert len(target.services) == 2
    assert destination.read_text() == xml.read_text()

    second_destination = record.root / ".tacmux/imports/second.xml"
    before = target.services.copy()
    candidates = parse_nmap_xml(xml, source=".tacmux/imports/second.xml")
    decisions = reconcile_candidates(
        record.engagement, candidates, allowed_scope_ids={scope.id}
    )
    def fail_save(*_args):
        raise OSError("disk full")

    monkeypatch.setattr(workspace, "save", fail_save)
    with pytest.raises(OSError, match="disk full"):
        apply_reconciliation(
            workspace,
            record.root,
            record.engagement,
            decisions,
            allowed_scope_ids={scope.id},
            source_copy=(xml, second_destination),
        )
    assert record.engagement.target_by_id(target.id).services == before
    assert not second_destination.exists()

    sitrep = render_sitrep(record.engagement)
    assert "**Observed services:** 2" in sitrep
    assert "| udp | open\\|filtered |" in sitrep


def test_documents_include_owned_provenance_without_internal_json(
    workspace, record
):
    scope = workspace.add_scope(
        record.root,
        record.engagement,
        "DMZ",
        ScopeGroup.EXTERNAL,
        "198.51.100.0/24",
    )
    target = workspace.create_target(
        record.root,
        record.engagement,
        "web",
        addresses=[TargetAddress("198.51.100.25", scope.id)],
        primary_endpoint="198.51.100.25",
    )
    imported = record.root / ".tacmux/imports/services.xml"
    imported.parent.mkdir()
    imported.write_text("<nmaprun/>")
    target.services = [Service(443, "tcp", state="open", source=".tacmux/imports/services.xml")]
    workspace.save(record.root, record.engagement)
    job = record.root / ".tacmux/jobs/J0001"
    job.mkdir()
    (job / "status.json").write_text(
        json.dumps({"state": "succeeded", "private": "not displayed"})
    )
    (job / "results.xml").write_text("<nmaprun/>")
    (job / "nmap.log").write_text("scan complete")
    (job / "job.json").write_text('{"argv": ["private"]}')

    entries, truncated = DocumentsPane._evidence_entries(record)
    labels = [item[0] for item in entries]
    paths = [item[1] for item in entries]
    assert not truncated
    assert any(label.startswith("Imported provenance") for label in labels)
    assert "Discovery J0001 / results.xml" in labels
    assert "Discovery J0001 / nmap.log" in labels
    assert paths.count(imported.resolve()) == 1
    assert job / "status.json" not in paths
    assert job / "job.json" not in paths


def test_missing_evidence_is_reported_in_generated_sitrep(workspace, record):
    workspace.create_activity(
        record.root,
        record.engagement,
        summary="Established route",
        result=ActivityResult.CONFIRMED,
        target_id="",
        evidence="notes/missing-proof.txt",
    )
    warnings = workspace.missing_evidence(record.root, record.engagement)
    assert warnings == [
        "activity A0001 references missing evidence: notes/missing-proof.txt"
    ]
    assert warnings[0] in (record.root / "SITREP.md").read_text()


class _HookTmux:
    def __init__(self, engagement_id: str = ""):
        self.engagement_id = engagement_id

    def run(self, args, **_kwargs):
        if args[0] == "show-option":
            value = self.engagement_id if args[-1] == "@tacmux_engagement_id" else ""
            return subprocess.CompletedProcess(args, 0, value + "\n", "")
        if args[0] == "display-message":
            return subprocess.CompletedProcess(args, 0, "0\n", "")
        if args[0] == "show-environment":
            return subprocess.CompletedProcess(args, 1, "", "")
        return subprocess.CompletedProcess(args, 0, "", "")


def test_automatic_logging_is_bounded_to_tacmux_sessions(settings):
    assert LogController(settings, _HookTmux()).start("%1") is None
    widened = replace(settings, log_outside_tacmux=True)
    controller = LogController(widened, _HookTmux())
    assert controller._disabled("%1") is False
    assert LogController(settings, _HookTmux("E-0123456789ab"))._disabled("%1") is False
