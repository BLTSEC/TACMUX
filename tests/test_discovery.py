from __future__ import annotations

import json
from pathlib import Path
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
    run_job,
)
from tacmux.errors import ConflictError, ValidationError
from tacmux.model import ScopeAvailability, ScopeGroup, TargetAddress


FIXTURES = Path(__file__).parent / "fixtures"


class RecordingTmux:
    def __init__(self):
        self.calls: list[list[str]] = []
        self.sessions: set[str] = set()

    def job_session_name(self, engagement, job_id: str) -> str:
        return f"tacmux-{engagement.id}-job-{job_id}"

    def run(self, args):
        self.calls.append(list(args))
        if args[0] == "new-session":
            self.sessions.add(args[args.index("-s") + 1])
        elif args[0] == "kill-session":
            self.sessions.discard(args[args.index("-t") + 1].strip("=:"))
        return subprocess.CompletedProcess(args, 0, "", "")

    def has_session(self, session_name: str) -> bool:
        return session_name in self.sessions


def test_nmap_xml_and_pasted_hosts_are_strictly_parsed():
    candidates = parse_nmap_xml(FIXTURES / "discovery.xml")
    assert [item.addresses[0] for item in candidates] == [
        "198.51.100.25",
        "198.51.100.40",
    ]
    assert candidates[0].hostnames == ["mail.acme.test"]
    pasted = parse_host_lines(
        "10.0.0.1 host-a\n10.0.0.1 duplicate\n# comment\n10.0.0.2"
    )
    assert len(pasted) == 2 and pasted[0].hostnames == ["host-a"]
    with pytest.raises(ValidationError, match="line 1"):
        parse_host_lines("not-an-ip host")


def test_reconciliation_requires_review_and_supports_second_interface_merge(
    workspace, record
):
    external = record.engagement.add_scope(
        "DMZ", ScopeGroup.EXTERNAL, "198.51.100.0/24"
    )
    internal = record.engagement.add_scope("LAN", ScopeGroup.INTERNAL, "10.77.10.0/24")
    host = workspace.create_target(
        record.root,
        record.engagement,
        "MAIL",
        addresses=[TargetAddress("198.51.100.25", external.id)],
        hostnames=["mail.acme.test"],
        primary_endpoint="mail.acme.test",
    )
    decisions = reconcile_candidates(
        record.engagement,
        [DiscoveryCandidate(["10.77.10.5"], ["mail.acme.test"], "echo-reply")],
        allowed_scope_ids={internal.id},
    )
    assert decisions[0].action == "add"
    assert decisions[0].merge_target_id == host.id
    assert "operator must choose" in decisions[0].note
    decisions[0].action = "merge"
    changed = apply_reconciliation(workspace, record.root, record.engagement, decisions)
    assert changed == [host]
    assert {(item.scope_id, item.value) for item in host.addresses} == {
        (external.id, "198.51.100.25"),
        (internal.id, "10.77.10.5"),
    }


def test_overlapping_selected_scope_is_ignored_instead_of_guessed(record):
    first = record.engagement.add_scope("Segment A", ScopeGroup.INTERNAL, "10.0.0.0/24")
    second = record.engagement.add_scope(
        "Segment B", ScopeGroup.INTERNAL, "10.0.0.0/25"
    )
    decision = reconcile_candidates(
        record.engagement,
        [DiscoveryCandidate(["10.0.0.10"])],
        allowed_scope_ids={first.id, second.id},
    )[0]
    assert decision.action == "ignore"
    assert "more than one" in decision.note


def test_discovery_job_uses_only_fixed_host_identification_profile(
    monkeypatch, workspace, record, settings
):
    ready = record.engagement.add_scope("DMZ", ScopeGroup.EXTERNAL, "198.51.100.0/24")
    blocked = record.engagement.add_scope(
        "LAN", ScopeGroup.INTERNAL, "10.0.0.0/24", ScopeAvailability.UNAVAILABLE
    )
    workspace.save(record.root, record.engagement)
    tmux = RecordingTmux()
    jobs = DiscoveryJobs(settings, tmux)
    monkeypatch.setattr(
        "tacmux.discovery.shutil.which", lambda name: f"/usr/bin/{name}"
    )
    value = jobs.create(record.root, record.engagement, [ready.id])
    assert value["argv"][:4] == ["nmap", "-sn", "--reason", "-oX"]
    assert value["argv"][-1] == "198.51.100.0/24"
    assert tmux.calls[0][:6] == [
        "new-session",
        "-d",
        "-s",
        value["session"],
        "-c",
        str(record.root / ".tacmux/jobs/J0001"),
    ]
    status = json.loads((record.root / ".tacmux/jobs/J0001/status.json").read_text())
    assert status["state"] == "queued" and status["session"] == value["session"]
    with pytest.raises(ConflictError, match="unavailable"):
        jobs.create(record.root, record.engagement, [blocked.id])


def test_run_job_records_success_and_failure(tmp_path):
    executable = tmp_path / "fake-nmap"
    executable.write_text("#!/bin/sh\nprintf '<nmaprun></nmaprun>' > \"$2\"\n")
    executable.chmod(0o700)
    job_root = tmp_path / "job"
    job_root.mkdir()
    job = {
        "schema": "tacmux.discovery-job/v1",
        "id": "J0001",
        "argv": [str(executable), "-oX", str(job_root / "results.xml")],
        "log_path": str(job_root / "nmap.log"),
        "state": "queued",
    }
    job_file = job_root / "job.json"
    job_file.write_text(json.dumps(job))
    assert run_job(job_file) == 0
    status = json.loads((job_root / "status.json").read_text())
    assert status["state"] == "succeeded" and status["exit_code"] == 0

    job["argv"] = [str(tmp_path / "missing-command")]
    job_file.write_text(json.dumps(job))
    assert run_job(job_file) == 127
    status = json.loads((job_root / "status.json").read_text())
    assert status["state"] == "failed"


def test_reconciliation_rolls_back_all_targets_when_commit_fails(
    monkeypatch, workspace, record
):
    scope = record.engagement.add_scope("LAN", ScopeGroup.INTERNAL, "10.40.0.0/24")
    existing = workspace.create_target(
        record.root,
        record.engagement,
        "existing",
        addresses=[TargetAddress("10.40.0.10", scope.id)],
        primary_endpoint="10.40.0.10",
    )
    decisions = [
        Reconciliation(
            DiscoveryCandidate(["10.40.0.11"]),
            [TargetAddress("10.40.0.11", scope.id)],
            "merge",
            merge_target_id=existing.id,
        ),
        Reconciliation(
            DiscoveryCandidate(["10.40.0.12"]),
            [TargetAddress("10.40.0.12", scope.id)],
            "add",
        ),
    ]
    before_manifest = (record.root / ".tacmux/engagement.json").read_text()
    before_directories = {item.name for item in (record.root / "targets").iterdir()}

    def fail_save(*_):
        raise OSError("disk full")

    monkeypatch.setattr(workspace, "save", fail_save)
    with pytest.raises(OSError, match="disk full"):
        apply_reconciliation(workspace, record.root, record.engagement, decisions)
    assert (record.root / ".tacmux/engagement.json").read_text() == before_manifest
    assert {
        item.name for item in (record.root / "targets").iterdir()
    } == before_directories
    restored = record.engagement.target_by_id(existing.id)
    assert [item.value for item in restored.addresses] == ["10.40.0.10"]


def test_discovery_jobs_can_be_cancelled_and_marked_imported(
    monkeypatch, workspace, record, settings
):
    scope = record.engagement.add_scope("LAN", ScopeGroup.INTERNAL, "10.50.0.0/24")
    workspace.save(record.root, record.engagement)
    tmux = RecordingTmux()
    jobs = DiscoveryJobs(settings, tmux)
    monkeypatch.setattr(
        "tacmux.discovery.shutil.which", lambda name: f"/usr/bin/{name}"
    )
    job = jobs.create(record.root, record.engagement, [scope.id])
    assert jobs.cancel(record.root, record.engagement, job["id"])
    assert jobs.list(record.root)[0]["state"] == "cancelled"

    status_path = record.root / ".tacmux/jobs" / job["id"] / "status.json"
    value = json.loads(status_path.read_text())
    value["state"] = "succeeded"
    status_path.write_text(json.dumps(value))
    jobs.mark_imported(record.root, job["id"])
    assert jobs.list(record.root)[0]["imported_at"]
