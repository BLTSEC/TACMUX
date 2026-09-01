from __future__ import annotations

import json
from pathlib import Path
import stat

import pytest

from tacmux.archive import create_archive
from tacmux.config import load_settings
from tacmux.errors import ConflictError, SafetyError, ValidationError
from tacmux.model import (
    AccessLevel,
    AccessRecord,
    AssessmentType,
    Activity,
    ActivityResult,
    Authorization,
    AttackPath,
    AttackPathStep,
    FindingState,
    EngagementStatus,
    ScopeAvailability,
    ScopeGroup,
    Severity,
    TargetAddress,
)
from tacmux.render import attack_paths_text, mermaid_topology, topology_text


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_manifest_save_and_generated_document_render_are_separate(
    workspace, record, monkeypatch
):
    from tacmux import store

    writes: list[str] = []
    original_write = store.write_private_text

    def tracked_write(path: Path, text: str) -> None:
        writes.append(str(path.relative_to(record.root)))
        original_write(path, text)

    monkeypatch.setattr(store, "write_private_text", tracked_write)
    record.engagement.name = "Updated assessment"
    workspace.save(record.root, record.engagement)
    assert writes == [".tacmux/engagement.json"]

    writes.clear()
    workspace.render_documents(record.root, record.engagement)
    assert writes == ["SITREP.md"]
    writes.clear()
    workspace.render_documents(record.root, record.engagement)
    assert writes == []


def test_unchanged_generated_document_replaces_a_symlink(workspace, record):
    workspace.render_documents(record.root, record.engagement)
    sitrep = record.root / "SITREP.md"
    expected = sitrep.read_text()
    external = record.root.parent / "external-sitrep.md"
    external.write_text(expected)
    sitrep.unlink()
    sitrep.symlink_to(external)

    workspace.render_documents(record.root, record.engagement)

    assert sitrep.is_file()
    assert not sitrep.is_symlink()
    assert sitrep.read_text() == expected
    assert external.read_text() == expected

    sitrep.chmod(0o644)
    workspace.render_documents(record.root, record.engagement)
    assert mode(sitrep) == 0o600


def test_engagement_creation_frontloads_scope_before_workspace_commit(workspace):
    record = workspace.create_engagement(
        "ACME",
        "Front-loaded scope",
        AssessmentType.BOTH,
        initial_scope=[
            (
                "Internet perimeter",
                ScopeGroup.EXTERNAL,
                "198.51.100.25/32",
                ScopeAvailability.READY,
            ),
            (
                "Corporate LAN",
                ScopeGroup.INTERNAL,
                "10.77.10.0/24",
                ScopeAvailability.UNAVAILABLE,
            ),
        ],
    )
    assert [item.group for item in record.engagement.scope] == [
        ScopeGroup.EXTERNAL,
        ScopeGroup.INTERNAL,
    ]
    assert workspace.load(record.root).scope[1].availability == (
        ScopeAvailability.UNAVAILABLE
    )

    before = {item.root for item in workspace.list_engagements()}
    with pytest.raises(ValidationError, match="invalid IP"):
        workspace.create_engagement(
            "ACME",
            "Invalid scope",
            AssessmentType.EXTERNAL,
            initial_scope=[
                (
                    "Bad range",
                    ScopeGroup.EXTERNAL,
                    "not-a-network",
                    ScopeAvailability.READY,
                )
            ],
        )
    assert {item.root for item in workspace.list_engagements()} == before


def test_private_front_loaded_workspace_and_stable_target_identity(workspace, record):
    external = record.engagement.add_scope(
        "Internet perimeter", ScopeGroup.EXTERNAL, "198.51.100.0/24"
    )
    internal = record.engagement.add_scope(
        "Corporate LAN",
        ScopeGroup.INTERNAL,
        "10.77.10.0/24",
        ScopeAvailability.UNAVAILABLE,
    )
    workspace.save(record.root, record.engagement)
    target = workspace.create_target(
        record.root,
        record.engagement,
        "MAIL01",
        addresses=[
            TargetAddress("198.51.100.25", external.id),
            TargetAddress("10.77.10.5", internal.id),
        ],
        hostnames=["mail01.acme.test"],
        primary_endpoint="mail01.acme.test",
    )
    original_directory = target.directory
    workspace.rename_target(
        record.root, record.engagement, target.id, "Exchange Gateway"
    )

    assert target.directory == original_directory
    assert target.id == "T0001"
    assert mode(record.root) == 0o700
    assert mode(record.root / ".tacmux/engagement.json") == 0o600
    assert mode(record.root / "targets" / target.directory) == 0o700
    for phase in ("recon", "exploitation", "loot", "screenshots", "reports", "logs"):
        assert (record.root / "targets" / target.directory / phase).is_dir()
    manifest = json.loads((record.root / ".tacmux/engagement.json").read_text())
    assert manifest["schema"] == "tacmux.engagement/v2"
    assert manifest["client"] == "ACME"


def test_unresolved_and_hostname_only_targets_are_valid(workspace, record):
    unresolved = workspace.create_target(
        record.root, record.engagement, "Identity pending"
    )
    hostname_only = workspace.create_target(
        record.root,
        record.engagement,
        "Web application",
        hostnames=["portal.acme.test"],
        primary_endpoint="portal.acme.test",
    )

    loaded = workspace.load(record.root)
    assert not unresolved.addresses and not unresolved.hostnames
    assert unresolved.identity_state == "unresolved"
    assert hostname_only.identity_state == "hostname-only"
    assert loaded.target_by_id(unresolved.id).primary_endpoint == ""
    assert loaded.target_by_id(hostname_only.id).hostnames == ["portal.acme.test"]
    topology = topology_text(loaded)
    assert "UNASSIGNED" in topology
    assert "Identity pending" in topology and "unresolved" in topology
    assert "Web application" in topology and "hostname only" in topology
    sitrep = (record.root / "SITREP.md").read_text()
    assert "| Identity | Addresses |" in sitrep


def test_scope_qualified_addresses_allow_overlap_but_reject_duplicates(
    workspace, record
):
    external = record.engagement.add_scope(
        "External NAT", ScopeGroup.EXTERNAL, "10.0.0.0/24"
    )
    internal = record.engagement.add_scope(
        "Internal LAN", ScopeGroup.INTERNAL, "10.0.0.0/24"
    )
    workspace.save(record.root, record.engagement)
    workspace.create_target(
        record.root,
        record.engagement,
        "External host",
        addresses=[TargetAddress("10.0.0.10", external.id)],
        primary_endpoint="10.0.0.10",
    )
    workspace.create_target(
        record.root,
        record.engagement,
        "Internal host",
        addresses=[TargetAddress("10.0.0.10", internal.id)],
        primary_endpoint="10.0.0.10",
    )
    with pytest.raises(ConflictError, match="already belongs"):
        workspace.create_target(
            record.root,
            record.engagement,
            "Duplicate",
            addresses=[TargetAddress("10.0.0.10", internal.id)],
            primary_endpoint="10.0.0.10",
        )


def test_confirmed_records_drive_access_and_attack_paths(workspace, record):
    scope = record.engagement.add_scope("LAN", ScopeGroup.INTERNAL, "10.20.0.0/24")
    target = workspace.create_target(
        record.root,
        record.engagement,
        "files01",
        addresses=[TargetAddress("10.20.0.20", scope.id)],
        primary_endpoint="10.20.0.20",
    )
    failed = Activity(
        "A0001", "LLMNR responder attempt", ActivityResult.FAILED, target.id
    )
    confirmed = Activity(
        "A0002", "Read deployment share", ActivityResult.CONFIRMED, target.id
    )
    access = AccessRecord(
        "AR0001",
        "svc_deploy",
        "ACME",
        target.id,
        "SMB",
        AccessLevel.AUTHENTICATED,
    )
    record.engagement.activities.extend([failed, confirmed])
    record.engagement.access.append(access)
    record.engagement.attack_paths.append(
        AttackPath("P0001", "Invalid path", [AttackPathStep("activity", failed.id)])
    )
    with pytest.raises(ValidationError, match="unconfirmed"):
        record.engagement.validate()
    record.engagement.attack_paths.clear()
    record.engagement.attack_paths.append(
        AttackPath(
            "P0001",
            "Share to authenticated access",
            [
                AttackPathStep("activity", confirmed.id),
                AttackPathStep("access", access.id),
            ],
        )
    )
    workspace.save(record.root, record.engagement)

    assert record.engagement.strongest_access(target.id) == AccessLevel.AUTHENTICATED
    path_text = attack_paths_text(record.engagement)
    assert "Authenticated" in path_text
    assert "LLMNR" not in path_text


def test_finding_documents_generated_records_and_target_delete_guard(workspace, record):
    scope = record.engagement.add_scope(
        "Perimeter", ScopeGroup.EXTERNAL, "203.0.113.5/32"
    )
    target = workspace.create_target(
        record.root,
        record.engagement,
        "vpn",
        addresses=[TargetAddress("203.0.113.5", scope.id)],
        primary_endpoint="203.0.113.5",
    )
    finding = workspace.create_finding(
        record.root,
        record.engagement,
        title="Initial access through VPN appliance",
        severity=Severity.HIGH,
        state=FindingState.CONFIRMED,
        target_ids=[target.id],
    )
    assert (record.root / finding.document).is_file()
    with pytest.raises(ConflictError, match=f"finding {finding.id}"):
        workspace.delete_target(record.root, record.engagement, target.id)
    workspace.delete_record(record.root, record.engagement, "finding", finding.id)
    assert not (record.root / finding.document).exists()
    target_root = record.root / "targets" / target.directory
    (target_root / "recon/proof.txt").write_text("evidence")
    workspace.delete_target(record.root, record.engagement, target.id)
    assert not target_root.exists()
    assert target.id not in {item.id for item in record.engagement.targets}


def test_engagement_delete_removes_live_tree_and_preserves_archive(
    workspace, record
):
    scope = record.engagement.add_scope(
        "Perimeter", ScopeGroup.EXTERNAL, "198.51.100.10/32"
    )
    target = workspace.create_target(
        record.root,
        record.engagement,
        "gateway",
        addresses=[TargetAddress("198.51.100.10", scope.id)],
        primary_endpoint="198.51.100.10",
    )
    evidence = record.root / "targets" / target.directory / "recon/proof.txt"
    evidence.write_text("captured evidence")
    job_root = record.root / ".tacmux/jobs/J0001"
    job_root.mkdir()
    (job_root / "status.json").write_text('{"state": "completed"}\n')
    archive, manifest = create_archive(
        record.root,
        workspace.settings.archive_dir,
        kind="engagements",
        engagement_id=record.engagement.id,
        object_id=record.engagement.id,
    )
    workspace.delete_engagement(record.engagement.id)

    assert not record.root.exists()
    assert workspace.list_engagements() == []
    assert workspace.get_last_engagement() == ""
    assert archive.is_file() and manifest.is_file()
    assert not any((workspace.settings.workspace / ".tacmux/deleting").iterdir())


def test_engagement_delete_rejects_symlinked_and_mismatched_roots(
    workspace, record, tmp_path
):
    outside = tmp_path / "outside" / record.root.name
    outside.parent.mkdir()
    record.root.rename(outside)
    record.root.symlink_to(outside, target_is_directory=True)
    with pytest.raises(SafetyError, match="symlinked engagement"):
        workspace.delete_engagement(record.engagement.id)
    assert outside.is_dir()

    record.root.unlink()
    mismatched = workspace.settings.workspace / "E-ffffffffffff-wrong-id"
    outside.rename(mismatched)
    with pytest.raises(SafetyError, match="does not match"):
        workspace.delete_engagement(record.engagement.id)
    assert mismatched.is_dir()


def test_engagement_delete_rolls_back_if_state_update_fails(
    workspace, record, monkeypatch
):
    def fail_state(_engagement_id: str) -> None:
        raise OSError("state is read-only")

    monkeypatch.setattr(workspace, "set_last_engagement", fail_state)
    with pytest.raises(OSError, match="state is read-only"):
        workspace.delete_engagement(record.engagement.id)
    assert record.root.is_dir()
    assert workspace.find(record.engagement.id).root == record.root


def test_engagement_delete_reports_quarantined_cleanup_failure(
    workspace, record, monkeypatch
):
    def fail_cleanup(_path) -> None:
        raise OSError("filesystem refused removal")

    monkeypatch.setattr("tacmux.store.shutil.rmtree", fail_cleanup)
    with pytest.raises(SafetyError, match="cleanup is incomplete"):
        workspace.delete_engagement(record.engagement.id)
    assert not record.root.exists()
    staged = list((workspace.settings.workspace / ".tacmux/deleting").iterdir())
    assert len(staged) == 1
    assert staged[0].name.startswith(record.engagement.id)
    assert workspace.get_last_engagement() == ""


def test_target_delete_reports_quarantined_cleanup_failure(
    workspace, record, monkeypatch
):
    target = workspace.create_target(
        record.root, record.engagement, "mistaken target"
    )

    def fail_cleanup(_path) -> None:
        raise OSError("filesystem refused removal")

    monkeypatch.setattr("tacmux.store.shutil.rmtree", fail_cleanup)
    with pytest.raises(SafetyError, match="cleanup is incomplete") as error:
        workspace.delete_target(record.root, record.engagement, target.id)
    staged = list((record.root / ".tacmux/deleting").iterdir())
    assert len(staged) == 1
    assert str(staged[0]) in str(error.value)
    assert not record.engagement.targets


def test_terminal_topology_separates_network_map_and_attack_path(workspace, record):
    external = record.engagement.add_scope(
        "DMZ", ScopeGroup.EXTERNAL, "198.51.100.0/24"
    )
    pivot = workspace.create_target(
        record.root,
        record.engagement,
        "mail01",
        addresses=[TargetAddress("198.51.100.25", external.id)],
        primary_endpoint="198.51.100.25",
    )
    internal = record.engagement.add_scope(
        "Corp LAN",
        ScopeGroup.INTERNAL,
        "10.77.10.0/24",
        ScopeAvailability.READY,
        via_target_id=pivot.id,
    )
    workspace.create_target(
        record.root,
        record.engagement,
        "dc01",
        addresses=[TargetAddress("10.77.10.10", internal.id)],
        primary_endpoint="10.77.10.10",
    )
    workspace.save(record.root, record.engagement)
    topology = topology_text(record.engagement)
    assert "EXTERNAL" in topology and "INTERNAL" in topology
    assert "via mail01" in topology and "dc01" in topology
    assert "flowchart LR" in mermaid_topology(record.engagement)
    assert "No confirmed attack paths" in attack_paths_text(record.engagement)


def test_config_rejects_string_booleans(tmp_path, monkeypatch):
    config = tmp_path / "config.toml"
    config.write_text('[behavior]\nauto_log = "false"\n')
    monkeypatch.setenv("TACMUX_CONFIG", str(config))
    with pytest.raises(ValidationError, match="true or false"):
        load_settings()


def test_config_expands_the_supplied_environment_mapping(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text('[paths]\nworkspace = "$EVIDENCE/work"\n')
    settings = load_settings(
        {
            "HOME": str(tmp_path / "home"),
            "EVIDENCE": str(tmp_path / "evidence"),
            "TACMUX_CONFIG": str(config),
        }
    )
    assert settings.workspace == tmp_path / "evidence/work"
    assert settings.archive_dir == tmp_path / "home/archives"


def test_manifest_rejects_unsupported_schema(record):
    value = record.engagement.to_dict()
    value["schema"] = "tacmux.engagement/v99"
    from tacmux.model import Engagement

    with pytest.raises(ValidationError, match="unsupported"):
        Engagement.from_dict(value)


def test_manifest_types_counters_state_and_concurrent_writes_are_safe(
    workspace, record
):
    from tacmux.model import Engagement

    value = record.engagement.to_dict()
    value["logging_enabled"] = "false"
    with pytest.raises(ValidationError, match="logging_enabled"):
        Engagement.from_dict(value)

    value = record.engagement.to_dict()
    value["client"] = ["ACME"]
    with pytest.raises(ValidationError, match="client must be a string"):
        Engagement.from_dict(value)

    value = record.engagement.to_dict()
    value["scope"] = ["not an object"]
    with pytest.raises(ValidationError, match="scope must be a list of objects"):
        Engagement.from_dict(value)

    scope = record.engagement.add_scope("LAN", ScopeGroup.INTERNAL, "10.20.0.0/24")
    target = workspace.create_target(
        record.root,
        record.engagement,
        "first",
        addresses=[TargetAddress("10.20.0.10", scope.id)],
        primary_endpoint="10.20.0.10",
    )
    value = record.engagement.to_dict()
    value["counters"] = {}
    loaded = Engagement.from_dict(value)
    assert loaded.next_id("target", "T") == "T0002"
    assert target.id == "T0001"

    first = workspace.load(record.root)
    stale = workspace.load(record.root)
    first.name = "First writer"
    workspace.save(record.root, first)
    stale.name = "Stale writer"
    with pytest.raises(ConflictError, match="another TACMUX process"):
        workspace.save(record.root, stale)
    assert workspace.load(record.root).name == "First writer"

    settings = workspace.settings
    settings.state_file.write_text("[]")
    assert workspace.get_last_engagement() == ""


def test_ipv6_addresses_are_normalized_before_primary_validation(workspace, record):
    scope = record.engagement.add_scope(
        "IPv6 LAN", ScopeGroup.INTERNAL, "2001:db8::/64"
    )
    target = workspace.create_target(
        record.root,
        record.engagement,
        "ipv6-host",
        addresses=[TargetAddress("2001:0db8::1", scope.id)],
        primary_endpoint="2001:0db8::1",
    )
    assert target.addresses[0].value == "2001:db8::1"
    assert target.primary_endpoint == "2001:db8::1"


def test_ui_state_updates_preserve_engagement_selection(workspace, record):
    assert workspace.get_last_engagement() == record.engagement.id

    workspace.set_last_engagement("E-0123456789ab")
    state = json.loads(workspace.settings.state_file.read_text())
    assert state == {
        "last_engagement_id": "E-0123456789ab",
        "schema": "tacmux.state/v1",
    }
    assert mode(workspace.settings.state_file) == 0o600
    assert mode(workspace.settings.state_file.with_suffix(".lock")) == 0o600


def test_ui_state_recovers_from_malformed_json(workspace):
    workspace.settings.state_file.write_text("not json")
    workspace.set_last_engagement("E-0123456789ab")
    assert workspace.get_last_engagement() == "E-0123456789ab"


@pytest.mark.parametrize(
    "operation",
    [
        "add_scope",
        "update_scope",
        "add_address",
        "remove_address",
        "replace_hostnames",
        "set_primary",
        "create_access",
        "create_activity",
        "create_attack_path",
        "update_record",
    ],
)
def test_manifest_mutations_restore_complete_state_after_save_failure(
    workspace, record, monkeypatch, operation
):
    scope = workspace.add_scope(
        record.root,
        record.engagement,
        "LAN",
        ScopeGroup.INTERNAL,
        "10.90.0.0/24",
    )
    target = workspace.create_target(
        record.root,
        record.engagement,
        "host",
        addresses=[TargetAddress("10.90.0.10", scope.id)],
        hostnames=["host.acme.test"],
        primary_endpoint="10.90.0.10",
    )
    access = workspace.create_access(
        record.root,
        record.engagement,
        target.id,
        principal="operator",
        authority="ACME",
        method="SSH",
        level=AccessLevel.USER_EXECUTION,
        evidence="",
    )
    activity = workspace.create_activity(
        record.root,
        record.engagement,
        summary="Confirmed route",
        result=ActivityResult.CONFIRMED,
        target_id=target.id,
        evidence="",
    )
    operations = {
        "add_scope": lambda: workspace.add_scope(
            record.root,
            record.engagement,
            "DMZ",
            ScopeGroup.EXTERNAL,
            "198.51.100.0/24",
        ),
        "update_scope": lambda: workspace.update_scope(
            record.root,
            record.engagement,
            scope.id,
            label="Renamed LAN",
            group=ScopeGroup.INTERNAL,
            network="10.90.0.0/24",
            availability=ScopeAvailability.READY,
            via_target_id="",
        ),
        "add_address": lambda: workspace.add_target_address(
            record.root,
            record.engagement,
            target.id,
            "10.90.0.11",
            scope.id,
        ),
        "remove_address": lambda: workspace.remove_target_address(
            record.root, record.engagement, target.id, 0
        ),
        "replace_hostnames": lambda: workspace.replace_target_hostnames(
            record.root, record.engagement, target.id, ["new.acme.test"]
        ),
        "set_primary": lambda: workspace.set_primary_endpoint(
            record.root, record.engagement, target.id, "host.acme.test"
        ),
        "create_access": lambda: workspace.create_access(
            record.root,
            record.engagement,
            target.id,
            principal="admin",
            authority="ACME",
            method="WinRM",
            level=AccessLevel.ADMINISTRATIVE_EXECUTION,
            evidence="",
        ),
        "create_activity": lambda: workspace.create_activity(
            record.root,
            record.engagement,
            summary="New activity",
            result=ActivityResult.CONFIRMED,
            target_id=target.id,
            evidence="",
        ),
        "create_attack_path": lambda: workspace.create_attack_path(
            record.root,
            record.engagement,
            "Validated access",
            [("access", access.id, "Obtained execution")],
        ),
        "update_record": lambda: workspace.update_record(
            record.root,
            record.engagement,
            "activity",
            activity.id,
            {
                "summary": "Changed",
                "result": ActivityResult.CONFIRMED,
                "target_id": target.id,
                "evidence": "",
            },
        ),
    }
    before = record.engagement.to_dict()

    def fail_save(*_):
        raise OSError("disk full")

    monkeypatch.setattr(workspace, "save", fail_save)
    with pytest.raises(OSError, match="disk full"):
        operations[operation]()
    assert record.engagement.to_dict() == before


def test_target_creation_restores_counter_and_directory_after_save_failure(
    workspace, record, monkeypatch
):
    before = record.engagement.to_dict()

    def fail_save(*_):
        raise OSError("disk full")

    monkeypatch.setattr(workspace, "save", fail_save)
    with pytest.raises(OSError, match="disk full"):
        workspace.create_target(record.root, record.engagement, "mistake")
    assert record.engagement.to_dict() == before
    assert not list((record.root / "targets").iterdir())


def test_target_staging_failure_restores_counter_and_directory(workspace, record):
    scope = workspace.add_scope(
        record.root,
        record.engagement,
        "LAN",
        ScopeGroup.INTERNAL,
        "10.91.0.0/24",
    )
    before = record.engagement.to_dict()
    with pytest.raises(ValidationError, match="outside scope"):
        workspace.create_target(
            record.root,
            record.engagement,
            "invalid",
            addresses=[TargetAddress("192.0.2.10", scope.id)],
            primary_endpoint="192.0.2.10",
        )
    assert record.engagement.to_dict() == before
    assert not list((record.root / "targets").iterdir())


def test_finding_creation_restores_counter_and_document_after_save_failure(
    workspace, record, monkeypatch
):
    target = workspace.create_target(record.root, record.engagement, "host")
    before = record.engagement.to_dict()

    def fail_save(*_):
        raise OSError("disk full")

    monkeypatch.setattr(workspace, "save", fail_save)
    with pytest.raises(OSError, match="disk full"):
        workspace.create_finding(
            record.root,
            record.engagement,
            title="Temporary finding",
            severity=Severity.LOW,
            state=FindingState.CONFIRMED,
            target_ids=[target.id],
        )
    assert record.engagement.to_dict() == before
    assert not (record.root / "findings/F0001.md").exists()


def test_structured_records_can_be_removed_before_target_deletion(workspace, record):
    scope = record.engagement.add_scope("LAN", ScopeGroup.INTERNAL, "10.30.0.0/24")
    target = workspace.create_target(
        record.root,
        record.engagement,
        "host",
        addresses=[TargetAddress("10.30.0.10", scope.id)],
        primary_endpoint="10.30.0.10",
    )
    access = AccessRecord(
        "AR0001",
        "operator",
        "ACME",
        target.id,
        "SSH",
        AccessLevel.USER_EXECUTION,
    )
    record.engagement.access.append(access)
    path = AttackPath(
        "P0001", "Validated access", [AttackPathStep("access", access.id)]
    )
    record.engagement.attack_paths.append(path)
    workspace.save(record.root, record.engagement)

    with pytest.raises(ConflictError, match="attack path"):
        workspace.delete_record(record.root, record.engagement, "access", access.id)
    workspace.delete_record(record.root, record.engagement, "attack_path", path.id)
    workspace.delete_record(record.root, record.engagement, "access", access.id)
    workspace.delete_target(record.root, record.engagement, target.id)
    workspace.delete_scope(record.root, record.engagement, scope.id)
    assert not record.engagement.targets and not record.engagement.scope


def test_closed_engagement_freezes_workspace_mutations_until_reopened(
    workspace, record
):
    target = workspace.create_target(record.root, record.engagement, "review host")
    stale_record = type(record)(record.root, workspace.load(record.root))
    workspace.set_status(record.root, record.engagement, EngagementStatus.CLOSED)

    blocked = [
        lambda: workspace.add_scope(
            record.root,
            record.engagement,
            "LAN",
            ScopeGroup.INTERNAL,
            "10.50.0.0/24",
        ),
        lambda: workspace.update_engagement_details(
            record.root,
            record.engagement,
            client="ACME Updated",
            name=record.engagement.name,
            assessment_type=record.engagement.assessment_type,
            logging_enabled=True,
            authorization=Authorization(),
        ),
        lambda: workspace.create_target(
            record.root, record.engagement, "late target"
        ),
        lambda: workspace.rename_target(
            record.root, record.engagement, target.id, "renamed"
        ),
        lambda: workspace.create_activity(
            record.root,
            record.engagement,
            summary="late activity",
            result=ActivityResult.NO_RESULT,
            target_id=target.id,
            evidence="",
        ),
        lambda: workspace.append_note(record, target, "late note"),
        lambda: workspace.delete_target(
            record.root, record.engagement, target.id
        ),
    ]
    for mutation in blocked:
        with pytest.raises(ConflictError, match="closed"):
            mutation()
    with pytest.raises(ConflictError, match="closed"):
        workspace.append_note(
            stale_record,
            stale_record.engagement.targets[0],
            "note from a stale shell",
        )

    workspace.set_status(record.root, record.engagement, EngagementStatus.ACTIVE)
    scope = workspace.add_scope(
        record.root,
        record.engagement,
        "LAN",
        ScopeGroup.INTERNAL,
        "10.50.0.0/24",
    )
    assert scope.label == "LAN"
