from __future__ import annotations

import os

import pytest

from tacmux import sitrep
from tacmux.errors import ConflictError, ValidationError
from tacmux.workspace import TARGET_DIRECTORIES, parse_nmap_ports


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


def test_existing_engagement_repairs_missing_key_directory(workspace, engagement):
    key_directory = engagement / "credentials/keys"
    key_directory.rmdir()

    workspace.require_engagement(engagement)

    assert key_directory.is_dir()
    assert key_directory.stat().st_mode & 0o777 == 0o700


def test_narrative_tasks_cleanup_and_credentials(workspace, engagement):
    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    workspace.add_narrative(engagement, "WEB01", "success", "Obtained shell", "via web")
    task = workspace.add_task(engagement, "WEB01", "Enumerate SMB", "after pivot")
    workspace.complete_task(engagement, task)
    cleanup = workspace.add_cleanup(engagement, "WEB01", "Remove payload")
    workspace.complete_cleanup(engagement, cleanup)
    credential = workspace.add_credential(
        engagement, "ACME\\alice", "p:a|ss\\word", "password", "WEB01"
    )
    check = workspace.add_credential_check(
        engagement, credential, "WEB01", "worked", "user", "SMB"
    )

    text = workspace.read(engagement)
    assert sitrep.read_global(text, "NARRATIVE")[0][3] == "Obtained shell"
    assert sitrep.read_global(text, "TODO") == []
    assert sitrep.read_global(text, "COMPLETED")[0][0] == task
    assert sitrep.read_global(text, "CLEANUP")[0][3] == "complete"
    assert sitrep.read_global(text, "CREDENTIAL_CHECKS")[0][0] == check
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
    rows.append(["C001", "alice", "password", "secret", "manual", "now", ""])
    (engagement / "SITREP.md").write_text(
        sitrep.write_global(text, "CREDENTIALS", rows)
    )
    os.chmod(engagement / "SITREP.md", 0o644)

    workspace.mutate(engagement, lambda value: value)

    assert (engagement / "credentials/creds.txt").read_text() == "alice:secret\n"
    assert (engagement / "SITREP.md").stat().st_mode & 0o777 == 0o600


def test_target_delete_refuses_history_then_removes_mistake(workspace, engagement):
    workspace.add_target(engagement, "KEEP", "192.0.2.10")
    workspace.add_narrative(engagement, "KEEP", "info", "Observed service")
    with pytest.raises(ConflictError, match="narrative"):
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
    assert sitrep.read_global(repaired, "TODO") == []
    assert sitrep.read_target(repaired, "WEB01", "PORTS") == []
