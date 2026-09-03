from __future__ import annotations

import json
import os
import subprocess

import pytest

from tacmux import sitrep
from tacmux.config import Settings
from tacmux.errors import ConflictError, SafetyError, ValidationError
from tacmux.workspace import (
    CaptureRecord,
    TARGET_DIRECTORIES,
    Workspace,
    parse_nmap_ports,
)


def test_create_engagement_and_target_tree(workspace, engagement):
    key_directory = engagement / "credentials/keys"
    assert key_directory.is_dir()
    assert key_directory.stat().st_mode & 0o777 == 0o700
    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    target = engagement / "targets" / "WEB01"
    assert all((target / name).is_dir() for name in TARGET_DIRECTORIES)
    details = workspace.target_details(engagement, "WEB01")
    assert details["Endpoint"][0] == "192.0.2.10"
    assert details["Status"][0] == "new"
    assert details["Capture Route"][0] == "WEB01"
    assert (target.stat().st_mode & 0o777) == 0o700
    assert (engagement / "SITREP.md").stat().st_mode & 0o777 == 0o600


def test_target_list_is_endpoint_only_private_and_replaceable(workspace, engagement):
    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    workspace.add_target(engagement, "DB01", "192.0.2.20")

    path, count = workspace.write_target_list(engagement, ["DB01", "WEB01", "DB01"])
    assert count == 2
    assert path == engagement / "targets.txt"
    assert path.read_text() == "192.0.2.20\n192.0.2.10\n"
    assert path.stat().st_mode & 0o777 == 0o600

    with pytest.raises(ValidationError, match="unknown target"):
        workspace.write_target_list(engagement, ["WEB01", "MISSING"])
    assert path.read_text() == "192.0.2.20\n192.0.2.10\n"

    _, count = workspace.write_target_list(engagement, [])
    assert count == 0
    assert path.read_text() == ""


def test_existing_engagement_repairs_missing_key_directory(workspace, engagement):
    key_directory = engagement / "credentials/keys"
    key_directory.rmdir()

    workspace.require_engagement(engagement)

    assert key_directory.is_dir()
    assert key_directory.stat().st_mode & 0o777 == 0o700


def test_operations_tasks_cleanup_and_credentials(workspace, engagement):
    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    workspace.add_event(engagement, "WEB01", "success", "Obtained shell", "via web")
    task = workspace.add_task(engagement, "WEB01", "Enumerate SMB", "after pivot")
    workspace.complete_task(engagement, task)
    cleanup = workspace.add_cleanup(engagement, "WEB01", "Remove payload")
    workspace.complete_cleanup(engagement, cleanup)
    credential = workspace.add_credential(
        engagement, "ACME\\alice", "p:a|ss\\word", "password", "WEB01"
    )
    workspace.confirm_credential(
        engagement, credential, "WEB01", "user", "SMB", "validated"
    )

    text = workspace.read(engagement)
    assert sitrep.read_events(text)[0].summary == "Obtained shell"
    tasks = sitrep.read_tasks(text, "TODO")
    assert tasks[0].identifier == task
    assert tasks[0].complete
    assert sitrep.read_tasks(text, "CLEANUP")[0].complete
    credential_row = sitrep.read_global(text, "CREDENTIALS")[0]
    assert credential_row[5] == "WEB01 · SMB · user"
    assert credential_row[7]
    assert credential_row[8] == "[WEB01 / SMB] validated"
    details = workspace.target_details(engagement, "WEB01")
    assert details["Access"][0] == "user"
    assert details["Principal"][0] == "ACME\\alice"
    assert (
        engagement / "credentials/creds.txt"
    ).read_text() == "ACME\\alice:p:a|ss\\word\n"
    assert (engagement / "credentials/passwords.txt").read_text() == "p:a|ss\\word\n"


def test_completed_task_ids_are_not_reused(workspace, engagement):
    first = workspace.add_task(engagement, "ENGAGEMENT", "First task")
    workspace.complete_task(engagement, first)
    second = workspace.add_task(engagement, "ENGAGEMENT", "Second task")
    assert (first, second) == ("T001", "T002")


def test_tasks_can_be_completed_manually_and_reopened(workspace, engagement):
    identifier = workspace.add_task(engagement, "ENGAGEMENT", "Review evidence")
    path = engagement / "SITREP.md"
    path.write_text(
        path.read_text().replace(f"- [ ] {identifier}:", f"- [x] {identifier}:")
    )
    assert sitrep.read_tasks(workspace.read(engagement), "TODO")[0].complete
    workspace.reopen_task(engagement, identifier)
    task = sitrep.read_tasks(workspace.read(engagement), "TODO")[0]
    assert not task.complete
    assert task.completed_at == ""


def test_external_sitrep_is_canonical_and_workspace_link_is_strict(tmp_path):
    notes = tmp_path / "notes"
    notes.mkdir()
    settings = Settings(
        workspace=tmp_path / "workspace",
        config_file=tmp_path / "config.toml",
        sitrep_root=notes,
    )
    workspace = Workspace(settings)
    engagement = workspace.create_engagement("ACME")
    link = engagement / "SITREP.md"
    physical = notes / "ACME/SITREP.md"
    assert link.is_symlink()
    assert link.resolve() == physical
    workspace.add_event(engagement, "ENGAGEMENT", "info", "Started")
    assert sitrep.read_events(physical.read_text())[0].summary == "Started"
    assert physical.stat().st_mode & 0o777 == 0o600

    image = tmp_path / "CleanShot proof @2x.png"
    image.write_bytes(b"\x89PNG\r\n\x1a\nproof")
    workspace.add_event(
        engagement,
        "ENGAGEMENT",
        "success",
        "Captured proof",
        images=[image],
    )
    assert (notes / "ACME/images/CleanShot proof @2x.png").is_file()
    assert "(<images/CleanShot proof @2x.png>)" in physical.read_text()

    link.unlink()
    outside = tmp_path / "outside.md"
    outside.write_text(physical.read_text())
    os.symlink(outside, link)
    assert not workspace.is_engagement(engagement)


def test_external_sitrep_collision_preserves_existing_notes(tmp_path):
    notes = tmp_path / "notes"
    existing = notes / "ACME"
    existing.mkdir(parents=True)
    sentinel = existing / "keep.md"
    sentinel.write_text("operator notes\n")
    workspace = Workspace(
        Settings(
            workspace=tmp_path / "workspace",
            config_file=tmp_path / "config.toml",
            sitrep_root=notes,
        )
    )
    with pytest.raises(ConflictError, match="already exist"):
        workspace.create_engagement("ACME")
    assert sentinel.read_text() == "operator notes\n"
    assert not (tmp_path / "workspace/ACME").exists()


def test_external_sitrep_requires_a_real_configured_root(tmp_path):
    notes = tmp_path / "missing-notes"
    workspace = Workspace(
        Settings(
            workspace=tmp_path / "workspace",
            config_file=tmp_path / "config.toml",
            sitrep_root=notes,
        )
    )
    with pytest.raises(SafetyError, match="configured SITREP root"):
        workspace.create_engagement("ACME")
    assert not (tmp_path / "workspace/ACME").exists()


def test_mutation_refuses_intervening_editor_change(workspace, engagement, monkeypatch):
    original = sitrep.append_event

    def concurrent_edit(text, event):
        (engagement / "SITREP.md").write_text(text + "\nexternal edit\n")
        return original(text, event)

    monkeypatch.setattr(sitrep, "append_event", concurrent_edit)
    with pytest.raises(ConflictError, match="another editor"):
        workspace.add_event(engagement, "ENGAGEMENT", "info", "Started")
    assert workspace.read(engagement).endswith("external edit\n")


def test_image_copy_is_removed_when_event_commit_conflicts(
    workspace, engagement, tmp_path, monkeypatch
):
    image = tmp_path / "proof.png"
    image.write_bytes(b"\x89PNG\r\n\x1a\nproof")
    original = sitrep.append_event

    def concurrent_edit(text, event):
        (engagement / "SITREP.md").write_text(text + "\nexternal edit\n")
        return original(text, event)

    monkeypatch.setattr(sitrep, "append_event", concurrent_edit)
    with pytest.raises(ConflictError, match="another editor"):
        workspace.add_event(
            engagement,
            "ENGAGEMENT",
            "success",
            "Captured proof",
            images=[image],
        )
    assert not (engagement / "images/proof.png").exists()


def test_capture_inspection_and_image_attachment(
    workspace, engagement, tmp_path, monkeypatch
):
    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    evidence = engagement / "captures/WEB01/recon"
    evidence.mkdir(parents=True)
    (evidence / "scan.txt").write_text("result\n")
    payload = {
        "schema_version": 1,
        "capture": {
            "id": "11111111-2222-3333-4444-555555555555",
            "status": "completed",
            "effective_tool": "nmap",
            "path": "WEB01/recon/scan.txt",
            "command": "nmap -sV 192.0.2.10",
        },
    }
    monkeypatch.setattr(
        "tacmux.workspace.shutil.which", lambda name: f"/usr/bin/{name}"
    )
    monkeypatch.setattr(
        "tacmux.workspace.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, json.dumps(payload), ""
        ),
    )
    capture = workspace.inspect_capture(engagement, "WEB01")
    image = tmp_path / "proof.png"
    image.write_bytes(b"\x89PNG\r\n\x1a\nproof")
    identifier = workspace.add_event(
        engagement,
        "WEB01",
        "success",
        "Service identified",
        capture=capture,
        images=[image],
    )
    event = sitrep.read_events(workspace.read(engagement))[0]
    assert event.identifier == identifier
    assert event.capture_id == payload["capture"]["id"]
    assert "![Service identified](<images/proof.png>)" in event.body
    assert "nmap -sV 192.0.2.10" in event.body
    assert (engagement / "images/proof.png").read_bytes() == image.read_bytes()

    with pytest.raises(ConflictError, match="already attached"):
        workspace.add_event(
            engagement, "WEB01", "success", "Duplicate", capture=capture
        )


def test_image_links_use_literal_angle_bracket_paths_for_obsidian(
    workspace, engagement, tmp_path
):
    image = tmp_path / "CleanShot 2026-09-02 at 23.55.07@2x.png"
    image.write_bytes(b"\x89PNG\r\n\x1a\nproof")

    workspace.add_event(
        engagement,
        "ENGAGEMENT",
        "success",
        "Captured proof",
        images=[image],
    )

    event = sitrep.read_events(workspace.read(engagement))[0]
    assert "(<images/CleanShot 2026-09-02 at 23.55.07@2x.png>)" in event.body
    assert "%20" not in event.body
    assert "%40" not in event.body


def test_capture_inspection_rejects_another_route(workspace, engagement, monkeypatch):
    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    evidence = engagement / "captures/OTHER/recon"
    evidence.mkdir(parents=True)
    (evidence / "scan.txt").write_text("result\n")
    payload = {
        "capture": {
            "id": "capture-1",
            "status": "completed",
            "effective_tool": "nmap",
            "path": "OTHER/recon/scan.txt",
            "command": "nmap -sV 192.0.2.20",
        }
    }
    monkeypatch.setattr("tacmux.workspace.shutil.which", lambda _name: "/usr/bin/cap")
    monkeypatch.setattr(
        "tacmux.workspace.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, json.dumps(payload), ""
        ),
    )

    with pytest.raises(ValidationError, match="another route"):
        workspace.inspect_capture(engagement, "WEB01")


def test_image_attachment_rejects_links_and_bad_signatures(
    workspace, engagement, tmp_path
):
    image = tmp_path / "proof.png"
    image.write_text("not an image")
    with pytest.raises(ValidationError, match="does not match"):
        workspace.add_event(
            engagement, "ENGAGEMENT", "info", "Bad image", images=[image]
        )

    real = tmp_path / "real.png"
    real.write_bytes(b"\x89PNG\r\n\x1a\nproof")
    linked = tmp_path / "linked.png"
    os.symlink(real, linked)
    with pytest.raises(ValidationError, match="missing or unsafe"):
        workspace.add_event(
            engagement, "ENGAGEMENT", "info", "Linked image", images=[linked]
        )

    unsafe_name = tmp_path / "proof#fragment.png"
    unsafe_name.write_bytes(b"\x89PNG\r\n\x1a\nproof")
    with pytest.raises(ValidationError, match="image filename"):
        workspace.add_event(
            engagement, "ENGAGEMENT", "info", "Unsafe name", images=[unsafe_name]
        )


def test_capture_without_image_has_placeholder(workspace, engagement):
    capture = CaptureRecord("capture-1", "completed", "nmap", "ops/scan.txt", "nmap")
    identifier = workspace.add_event(
        engagement, "ENGAGEMENT", "success", "Discovery complete", capture=capture
    )
    event = next(
        value
        for value in sitrep.read_events(workspace.read(engagement))
        if value.identifier == identifier
    )
    assert "**Image:** _Not attached._" in event.body
    assert "Evidence supporting: Discovery complete" in event.body


def test_hash_uses_first_colon_and_generated_files(workspace, engagement):
    workspace.add_credential(engagement, "alice", "aad3b435:31d6cfe0", "hash")
    assert (engagement / "credentials/users.txt").read_text() == "alice\n"
    assert (engagement / "credentials/hashes.txt").read_text() == "aad3b435:31d6cfe0\n"
    assert (engagement / "credentials/passwords.txt").read_text() == ""


def test_identity_mutation_validates_manual_edits_and_syncs_credentials(
    workspace, engagement
):
    text = workspace.read(engagement)
    rows = sitrep.read_global(text, "CREDENTIALS")
    rows.append(["C001", "alice", "password", "secret", "manual", "", "now", "", ""])
    (engagement / "SITREP.md").write_text(
        sitrep.write_global(text, "CREDENTIALS", rows)
    )
    os.chmod(engagement / "SITREP.md", 0o644)

    workspace.mutate(engagement, lambda value: value)

    assert (engagement / "credentials/creds.txt").read_text() == "alice:secret\n"
    assert (engagement / "SITREP.md").stat().st_mode & 0o777 == 0o600


def test_credential_confirmations_upsert_and_never_lower_target_access(
    workspace, engagement
):
    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    workspace.add_target(engagement, "DB01", "192.0.2.20")
    credential = workspace.add_credential(
        engagement, "ACME\\alice", "secret", "password"
    )

    workspace.confirm_credential(
        engagement, credential, "WEB01", "user", "SMB", "first"
    )
    workspace.confirm_credential(
        engagement, credential, "WEB01", "admin", "SMB", "elevated"
    )
    workspace.confirm_credential(
        engagement, credential, "DB01", "authenticated", "MSSQL"
    )

    row = sitrep.read_global(workspace.read(engagement), "CREDENTIALS")[0]
    assert sitrep.parse_confirmed_access(row[5]) == [
        ("WEB01", "SMB", "admin"),
        ("DB01", "MSSQL", "authenticated"),
    ]
    assert row[8] == "[WEB01 / SMB] first; [WEB01 / SMB] elevated"
    assert workspace.target_details(engagement, "WEB01")["Access"][0] == "admin"
    assert (
        workspace.target_details(engagement, "WEB01")["Method/Path"][0]
        == f"Credential {credential} via SMB"
    )

    workspace.confirm_credential(
        engagement, credential, "WEB01", "user", "SSH", "also valid"
    )
    details = workspace.target_details(engagement, "WEB01")
    assert details["Access"][0] == "admin"
    assert details["Method/Path"][0] == f"Credential {credential} via SMB"


def test_confirmed_credentials_follow_rename_and_block_delete(workspace, engagement):
    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    credential = workspace.add_credential(engagement, "alice", "secret", "password")
    workspace.confirm_credential(
        engagement, credential, "WEB01", "authenticated", "HTTPS", "validated"
    )

    workspace.rename_target(engagement, "WEB01", "APP01")
    row = sitrep.read_global(workspace.read(engagement), "CREDENTIALS")[0]
    assert row[5] == "APP01 · HTTPS · authenticated"
    assert row[8] == "[APP01 / HTTPS] validated"
    with pytest.raises(ConflictError, match="confirmed credentials"):
        workspace.delete_target(engagement, "APP01")


def test_manual_heading_rename_can_be_completed_safely(workspace, engagement):
    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    credential = workspace.add_credential(engagement, "alice", "secret", "password")
    workspace.confirm_credential(
        engagement, credential, "WEB01", "user", "HTTPS", "validated"
    )
    workspace.add_event(
        engagement, "WEB01", "success", "WEB01 appears in historical prose"
    )
    workspace.add_task(engagement, "WEB01", "Review service")
    workspace.add_cleanup(engagement, "WEB01", "Remove test file")
    capture = engagement / "captures/WEB01/recon/evidence.txt"
    capture.parent.mkdir(parents=True)
    capture.write_text("evidence\n")

    path = engagement / "SITREP.md"
    path.write_text(path.read_text().replace("### WEB01\n", "### MAIL\n", 1))
    manually_renamed = workspace.read(engagement)
    problem = (
        "target identity mismatch: directory WEB01 has SITREP heading MAIL; "
        "restore the heading or run: tm target rename WEB01 MAIL"
    )
    assert workspace.validate(engagement) == [problem]
    with pytest.raises(ValidationError, match="tm target rename WEB01 MAIL"):
        workspace.target_details(engagement, "WEB01")

    with pytest.raises(ValidationError, match="tm target rename WEB01 MAIL"):
        workspace.repair_scaffolding(engagement, {"WEB01": "192.0.2.10"})
    assert workspace.read(engagement) == manually_renamed

    workspace.rename_target(engagement, "WEB01", "MAIL")
    updated = workspace.read(engagement)
    assert workspace.targets(engagement) == ["MAIL"]
    assert workspace.target_details(engagement, "MAIL")["Endpoint"][0] == "192.0.2.10"
    assert workspace.target_details(engagement, "MAIL")["Capture Route"][0] == "WEB01"
    assert capture.read_text() == "evidence\n"
    assert sitrep.read_events(updated)[0].target == "MAIL"
    assert sitrep.read_events(updated)[0].summary == "WEB01 appears in historical prose"
    assert sitrep.read_tasks(updated, "TODO")[0].target == "MAIL"
    assert sitrep.read_tasks(updated, "CLEANUP")[0].target == "MAIL"
    credential_row = sitrep.read_global(updated, "CREDENTIALS")[0]
    assert credential_row[5] == "MAIL · HTTPS · user"
    assert credential_row[8] == "[MAIL / HTTPS] validated"


def test_ambiguous_heading_drift_blocks_sync_and_rename(workspace, engagement):
    workspace.add_target(engagement, "OLD1", "192.0.2.10")
    workspace.add_target(engagement, "OLD2", "192.0.2.20")
    path = engagement / "SITREP.md"
    changed = path.read_text().replace("### OLD1\n", "### NEW1\n", 1)
    changed = changed.replace("### OLD2\n", "### NEW2\n", 1)
    path.write_text(changed)

    with pytest.raises(ValidationError, match="directories missing SITREP headings"):
        workspace.repair_scaffolding(engagement, {})
    with pytest.raises(ValidationError, match="target identity mismatch"):
        workspace.rename_target(engagement, "OLD1", "NEW1")
    assert workspace.read(engagement) == changed
    assert workspace.targets(engagement) == ["OLD1", "OLD2"]


def test_confirmation_delimiters_are_reserved(workspace, engagement):
    with pytest.raises(ValidationError, match="cannot contain"):
        workspace.add_target(engagement, "WEB;01", "192.0.2.10")
    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    credential = workspace.add_credential(engagement, "alice", "secret", "password")
    with pytest.raises(ValidationError, match="service cannot contain"):
        workspace.confirm_credential(
            engagement, credential, "WEB01", "user", "SMB·ADMIN"
        )


def test_target_delete_refuses_history_then_removes_mistake(workspace, engagement):
    workspace.add_target(engagement, "KEEP", "192.0.2.10")
    workspace.add_event(engagement, "KEEP", "info", "Observed service")
    with pytest.raises(ConflictError, match="operations log"):
        workspace.delete_target(engagement, "KEEP")

    workspace.add_target(engagement, "MISTAKE", "192.0.2.11")
    workspace.delete_target(engagement, "MISTAKE")
    assert not (engagement / "targets/MISTAKE").exists()
    assert "MISTAKE" not in {
        section.name for section in sitrep.target_sections(workspace.read(engagement))
    }


def test_target_rename_keeps_route_after_capture(workspace, engagement):
    workspace.add_target(engagement, "OLD", "192.0.2.20")
    capture = engagement / "captures/OLD/recon"
    capture.mkdir(parents=True)
    (capture / "evidence.txt").write_text("evidence")
    workspace.rename_target(engagement, "OLD", "NEW")
    assert workspace.target_details(engagement, "NEW")["Capture Route"][0] == "OLD"
    assert capture.is_dir()


def test_capture_route_cannot_silently_orphan_existing_files(workspace, engagement):
    workspace.add_target(engagement, "WEB01", "192.0.2.20")
    capture = engagement / "captures/WEB01/recon"
    capture.mkdir(parents=True)
    (capture / "evidence.txt").write_text("evidence")
    with pytest.raises(ValidationError, match="unassigned capture route"):
        workspace.set_target_detail(engagement, "WEB01", "Capture Route", "DIFFERENT")


def test_parse_and_merge_nmap_ports_preserves_notes(workspace, engagement):
    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    rows = parse_nmap_ports(
        "22/tcp open ssh OpenSSH 9.2\n53/udp open domain dnsmasq\nnot-a-port\n"
    )
    assert rows == [
        ["22", "tcp", "open", "ssh", "OpenSSH 9.2"],
        ["53", "udp", "open", "domain", "dnsmasq"],
    ]
    workspace.merge_ports(engagement, "WEB01", rows)
    text = workspace.read(engagement)
    current = sitrep.read_target(text, "WEB01", "PORTS")
    current[0][6] = "banner checked"
    workspace.mutate(
        engagement, lambda value: sitrep.write_target(value, "WEB01", "PORTS", current)
    )
    workspace.merge_ports(
        engagement, "WEB01", [["22", "tcp", "open", "ssh", "OpenSSH 9.3"]]
    )
    updated = sitrep.read_target(workspace.read(engagement), "WEB01", "PORTS")
    assert updated[0][4] == "OpenSSH 9.3"
    assert updated[0][6] == "banner checked"


def test_linked_target_is_not_inventory(workspace, engagement, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(outside, engagement / "targets/LINK")
    assert workspace.targets(engagement) == []


def test_invalid_status_is_rejected(workspace, engagement):
    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    with pytest.raises(ValidationError, match="status"):
        workspace.set_target_detail(engagement, "WEB01", "Status", "maybe")


def test_sync_restores_absent_empty_global_and_port_tables(workspace, engagement):
    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    text = workspace.read(engagement)
    todo_start = text.index("<!-- TACMUX:TODO:START -->")
    todo_end = text.index("<!-- TACMUX:TODO:END -->") + len("<!-- TACMUX:TODO:END -->")
    text = text[:todo_start] + text[todo_end:]
    port_start = text.index("<!-- TACMUX:PORTS:START -->")
    port_end = text.index("<!-- TACMUX:PORTS:END -->") + len(
        "<!-- TACMUX:PORTS:END -->"
    )
    (engagement / "SITREP.md").write_text(text[:port_start] + text[port_end:])

    assert workspace.repair_scaffolding(engagement, {}) == []
    repaired = workspace.read(engagement)
    assert sitrep.read_tasks(repaired, "TODO") == []
    assert sitrep.read_target(repaired, "WEB01", "PORTS") == []


def test_sync_repairs_scaffolding_and_reports_reference_problems(workspace, engagement):
    text = workspace.read(engagement)
    text = sitrep.write_tasks(
        text,
        "TODO",
        [sitrep.Task("T001", "MISSING", "Review missing host")],
    )
    (engagement / "SITREP.md").write_text(text)

    assert workspace.repair_scaffolding(engagement, {}) == [
        "todo references missing target: MISSING"
    ]
