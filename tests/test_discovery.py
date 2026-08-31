from __future__ import annotations

import json
from pathlib import Path
import subprocess
from concurrent.futures import ThreadPoolExecutor

import pytest

from tacmux.discovery import (
    DiscoveryCandidate,
    DiscoveryJobs,
    Reconciliation,
    ScanPace,
    ScanProfile,
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
    with pytest.raises(ValidationError, match="line 1"):
        parse_host_lines("10.0.0.3 host-b unexpected")


def test_malformed_nmap_address_is_a_validation_error(tmp_path):
    xml = tmp_path / "malformed.xml"
    xml.write_text(
        '<nmaprun><host><status state="up" reason="echo-reply"/>'
        '<address addr="not-an-ip" addrtype="ipv4"/></host></nmaprun>'
    )
    with pytest.raises(ValidationError, match="host 1.*invalid IP address"):
        parse_nmap_xml(xml)


def test_nmap_xml_encoding_errors_are_wrapped_and_utf16_provenance_is_exact(
    tmp_path, workspace, record
):
    unknown = tmp_path / "unknown.xml"
    unknown.write_bytes(
        b"<?xml version='1.0' encoding='x-tacmux-unknown'?><nmaprun/>"
    )
    with pytest.raises(ValidationError, match="cannot parse Nmap XML"):
        parse_nmap_xml(unknown)

    scope = workspace.add_scope(
        record.root,
        record.engagement,
        "DMZ",
        ScopeGroup.EXTERNAL,
        "198.51.100.0/24",
    )
    source = tmp_path / "utf16.xml"
    source.write_bytes(
        """<?xml version='1.0' encoding='UTF-16'?>
<nmaprun><host><status state='up' reason='echo-reply'/>
<address addr='198.51.100.25' addrtype='ipv4'/><ports>
<port protocol='tcp' portid='443'><state state='open'/>
<service name='https'/></port></ports></host></nmaprun>""".encode("utf-16")
    )
    relative = ".tacmux/imports/utf16.xml"
    candidates = parse_nmap_xml(source, source=relative)
    decisions = reconcile_candidates(
        record.engagement, candidates, allowed_scope_ids={scope.id}
    )
    destination = record.root / relative
    apply_reconciliation(
        workspace,
        record.root,
        record.engagement,
        decisions,
        allowed_scope_ids={scope.id},
        source_copy=(source, destination),
    )
    assert destination.read_bytes() == source.read_bytes()


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
    changed = apply_reconciliation(
        workspace,
        record.root,
        record.engagement,
        decisions,
        allowed_scope_ids={internal.id},
    )
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


def test_out_of_scope_discovery_cannot_be_promoted_to_addressless_target(
    workspace, record
):
    scope = record.engagement.add_scope(
        "DMZ", ScopeGroup.EXTERNAL, "198.51.100.0/24"
    )
    workspace.save(record.root, record.engagement)
    decision = reconcile_candidates(
        record.engagement,
        [
            DiscoveryCandidate(
                ["203.0.113.10"], ["outside.example.test"], "echo-reply"
            )
        ],
        allowed_scope_ids={scope.id},
    )[0]
    assert decision.allowed_actions == ("ignore",)
    assert not decision.fully_scope_qualified

    before = record.engagement.to_dict()
    before_directories = {item.name for item in (record.root / "targets").iterdir()}
    decision.action = "add"
    with pytest.raises(ValidationError, match="not allowed"):
        apply_reconciliation(
            workspace,
            record.root,
            record.engagement,
            [decision],
            allowed_scope_ids={scope.id},
        )
    assert record.engagement.to_dict() == before
    assert {
        item.name for item in (record.root / "targets").iterdir()
    } == before_directories


def test_partially_mapped_discovery_candidate_is_ignore_only(record):
    scope = record.engagement.add_scope(
        "LAN", ScopeGroup.INTERNAL, "10.20.0.0/24"
    )
    decision = reconcile_candidates(
        record.engagement,
        [DiscoveryCandidate(["10.20.0.10", "192.0.2.10"], ["dual.example.test"])],
        allowed_scope_ids={scope.id},
    )[0]
    assert [item.value for item in decision.addresses] == ["10.20.0.10"]
    assert decision.allowed_actions == ("ignore",)
    assert not decision.fully_scope_qualified
    assert "outside selected scope: 192.0.2.10" in decision.note


def test_apply_reconciliation_rederives_scope_and_ignores_forged_addresses(
    workspace, record
):
    scope = record.engagement.add_scope(
        "DMZ", ScopeGroup.EXTERNAL, "198.51.100.0/24"
    )
    workspace.save(record.root, record.engagement)
    forged = Reconciliation(
        DiscoveryCandidate(["203.0.113.99"], ["outside.example.test"]),
        [TargetAddress("198.51.100.25", scope.id)],
        "add",
    )
    before = record.engagement.to_dict()
    with pytest.raises(ValidationError, match="not allowed"):
        apply_reconciliation(
            workspace,
            record.root,
            record.engagement,
            [forged],
            allowed_scope_ids={scope.id},
        )
    assert record.engagement.to_dict() == before


def test_discovery_uses_scope_qualified_ip_as_primary_endpoint(workspace, record):
    scope = record.engagement.add_scope(
        "DMZ", ScopeGroup.EXTERNAL, "198.51.100.0/24"
    )
    workspace.save(record.root, record.engagement)
    decisions = reconcile_candidates(
        record.engagement,
        [DiscoveryCandidate(["198.51.100.25"], ["untrusted.ptr.invalid"])],
        allowed_scope_ids={scope.id},
    )
    target = apply_reconciliation(
        workspace,
        record.root,
        record.engagement,
        decisions,
        allowed_scope_ids={scope.id},
    )[0]
    assert target.primary_endpoint == "198.51.100.25"
    assert target.hostnames == ["untrusted.ptr.invalid"]


def test_exact_address_match_allows_merge_or_ignore_but_not_add(workspace, record):
    scope = record.engagement.add_scope(
        "LAN", ScopeGroup.INTERNAL, "10.21.0.0/24"
    )
    target = workspace.create_target(
        record.root,
        record.engagement,
        "host",
        addresses=[TargetAddress("10.21.0.10", scope.id)],
        primary_endpoint="10.21.0.10",
    )
    decision = reconcile_candidates(
        record.engagement,
        [DiscoveryCandidate(["10.21.0.10"], ["host.example.test"])],
        allowed_scope_ids={scope.id},
    )[0]
    assert decision.action == "merge"
    assert decision.merge_target_id == target.id
    assert decision.allowed_actions == ("merge", "ignore")
    decision.action = "add"
    with pytest.raises(ValidationError, match="not allowed"):
        apply_reconciliation(
            workspace,
            record.root,
            record.engagement,
            [decision],
            allowed_scope_ids={scope.id},
        )


def test_discovery_job_uses_only_fixed_host_identification_profile(
    monkeypatch, workspace, record, settings
):
    ready = record.engagement.add_scope(
        "DMZ",
        ScopeGroup.EXTERNAL,
        "198.51.100.0/24",
        exclusions=["198.51.100.254/32"],
    )
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
    assert value["argv"][:5] == [
        "nmap",
        "-sn",
        "--reason",
        "--exclude",
        "198.51.100.254/32",
    ]
    assert "-oX" in value["argv"]
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
    job_spec = json.loads((record.root / ".tacmux/jobs/J0001/job.json").read_text())
    assert "argv" not in job_spec
    with pytest.raises(ConflictError, match="unavailable"):
        jobs.create(record.root, record.engagement, [blocked.id])


def test_run_job_rebuilds_command_and_output_paths(
    monkeypatch, tmp_path, workspace, record, settings
):
    scope = record.engagement.add_scope(
        "DMZ",
        ScopeGroup.EXTERNAL,
        "198.51.100.0/24",
        exclusions=["198.51.100.254/32"],
    )
    workspace.save(record.root, record.engagement)
    jobs = DiscoveryJobs(settings, RecordingTmux(), workspace)
    monkeypatch.setattr("tacmux.discovery.shutil.which", lambda name: "/usr/bin/nmap")
    job = jobs.create(record.root, record.engagement, [scope.id])
    job_root = record.root / ".tacmux/jobs" / job["id"]
    job_file = job_root / "job.json"
    value = json.loads(job_file.read_text())
    outside = tmp_path / "must-not-change"
    outside.write_text("preserved")
    value["argv"] = ["sh", "-c", "exit 99"]
    value["xml_path"] = str(outside)
    value["log_path"] = str(outside)
    job_file.write_text(json.dumps(value))
    calls = []

    def fake_run(argv, *, stdout, stderr, check):
        calls.append(list(argv))
        Path(argv[argv.index("-oX") + 1]).write_text("<nmaprun></nmaprun>")
        stdout.write(b"scan complete\n")
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr("tacmux.discovery.subprocess.run", fake_run)
    assert run_job(settings, job_file) == 0
    assert calls == [
        [
            "/usr/bin/nmap",
            "-sn",
            "--reason",
            "--exclude",
            "198.51.100.254/32",
            "-oX",
            str(job_root / "results.xml"),
            "198.51.100.0/24",
        ]
    ]
    assert outside.read_text() == "preserved"
    status = json.loads((job_root / "status.json").read_text())
    assert status["state"] == "succeeded" and status["exit_code"] == 0
    assert status["log_path"] == str(job_root / "nmap.log")
    with pytest.raises(ConflictError, match="not queued"):
        run_job(settings, job_file)
    assert len(calls) == 1


def test_run_job_rejects_tampered_identity_and_records_failure(
    monkeypatch, workspace, record, settings
):
    scope = record.engagement.add_scope("DMZ", ScopeGroup.EXTERNAL, "198.51.100.0/24")
    workspace.save(record.root, record.engagement)
    jobs = DiscoveryJobs(settings, RecordingTmux(), workspace)
    monkeypatch.setattr("tacmux.discovery.shutil.which", lambda name: "/usr/bin/nmap")
    job = jobs.create(record.root, record.engagement, [scope.id])
    job_root = record.root / ".tacmux/jobs" / job["id"]
    job_file = job_root / "job.json"
    value = json.loads(job_file.read_text())
    value["engagement_id"] = "E-000000000000"
    job_file.write_text(json.dumps(value))

    with pytest.raises(ValidationError, match="different engagement"):
        run_job(settings, job_file)
    status = json.loads((job_root / "status.json").read_text())
    assert status["state"] == "failed" and status["exit_code"] == 127


def test_run_job_records_execution_failure(monkeypatch, workspace, record, settings):
    scope = record.engagement.add_scope("DMZ", ScopeGroup.EXTERNAL, "198.51.100.0/24")
    workspace.save(record.root, record.engagement)
    jobs = DiscoveryJobs(settings, RecordingTmux(), workspace)
    monkeypatch.setattr("tacmux.discovery.shutil.which", lambda name: "/usr/bin/nmap")
    job = jobs.create(record.root, record.engagement, [scope.id])
    job_root = record.root / ".tacmux/jobs" / job["id"]

    def fail_run(*_args, **_kwargs):
        raise OSError("cannot execute")

    monkeypatch.setattr("tacmux.discovery.subprocess.run", fail_run)
    assert run_job(settings, job_root / "job.json") == 127
    status = json.loads((job_root / "status.json").read_text())
    assert status["state"] == "failed" and status["exit_code"] == 127


def test_run_job_rejects_files_outside_workspace(tmp_path, settings):
    job_file = tmp_path / "job.json"
    job_file.write_text("{}")
    with pytest.raises(ValidationError, match="configured workspace"):
        run_job(settings, job_file)


def test_cancelled_job_does_not_start_if_runner_arrives_late(
    monkeypatch, workspace, record, settings
):
    scope = record.engagement.add_scope("DMZ", ScopeGroup.EXTERNAL, "198.51.100.0/24")
    workspace.save(record.root, record.engagement)
    tmux = RecordingTmux()
    jobs = DiscoveryJobs(settings, tmux, workspace)
    monkeypatch.setattr("tacmux.discovery.shutil.which", lambda name: "/usr/bin/nmap")
    job = jobs.create(record.root, record.engagement, [scope.id])
    assert jobs.cancel(record.root, record.engagement, job["id"])

    def must_not_run(*_args, **_kwargs):
        raise AssertionError("cancelled discovery executed")

    monkeypatch.setattr("tacmux.discovery.subprocess.run", must_not_run)
    job_file = record.root / ".tacmux/jobs" / job["id"] / "job.json"
    assert run_job(settings, job_file) == 130
    assert jobs.list(record.root)[0]["state"] == "cancelled"


def _nmap_xml(*hosts: tuple[str, list[int], str]) -> str:
    body = []
    for address, ports, product in hosts:
        address_type = "ipv6" if ":" in address else "ipv4"
        port_xml = "".join(
            f"<port protocol='tcp' portid='{port}'><state state='open'/>"
            f"<service name='{'ssh' if port == 22 else 'https'}' "
            f"product='{product}' version='1.0'/></port>"
            for port in ports
        )
        body.append(
            "<host><status state='up' reason='echo-reply'/>"
            f"<address addr='{address}' addrtype='{address_type}'/>"
            f"<ports>{port_xml}</ports></host>"
        )
    return "<nmaprun>" + "".join(body) + "</nmaprun>"


def test_enhanced_job_revalidates_hosts_and_targets_sv_to_discovered_ports(
    monkeypatch, workspace, record, settings
):
    scope = record.engagement.add_scope(
        "DMZ", ScopeGroup.EXTERNAL, "198.51.100.0/24"
    )
    workspace.save(record.root, record.engagement)
    jobs = DiscoveryJobs(settings, RecordingTmux(), workspace)
    monkeypatch.setattr("tacmux.discovery.shutil.which", lambda _name: "/usr/bin/nmap")
    job = jobs.create(
        record.root,
        record.engagement,
        [scope.id],
        profile=ScanProfile.TCP_SERVICES,
        pace=ScanPace.FAST,
    )
    calls: list[list[str]] = []

    def fake_run(argv, *, stdout, stderr, check):
        calls.append(list(argv))
        output = Path(argv[argv.index("-oX") + 1])
        if output.name.startswith("host-discovery"):
            output.write_text(
                _nmap_xml(
                    ("198.51.100.25", [], ""),
                    ("203.0.113.99", [], ""),
                )
            )
        elif output.name.startswith("tcp-ports"):
            assert argv[-1:] == ["198.51.100.25"]
            output.write_text(_nmap_xml(("198.51.100.25", [22, 443], "")))
        else:
            assert "-sV" in argv and argv[argv.index("-p") + 1] == "22,443"
            assert argv[-1:] == ["198.51.100.25"]
            output.write_text(_nmap_xml(("198.51.100.25", [22, 443], "OpenSSH")))
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr("tacmux.discovery.subprocess.run", fake_run)
    job_file = record.root / ".tacmux/jobs" / job["id"] / "job.json"
    assert run_job(settings, job_file) == 0
    assert len(calls) == 3
    assert "-p-" in calls[1] and "-T4" in calls[1]
    assert "-T4" in calls[2]
    assert all("203.0.113.99" not in argv for argv in calls[1:])
    status = jobs.list(record.root)[0]
    assert status["state"] == "succeeded"
    assert len(status["result_paths"]) == 3
    candidates = jobs.candidates(record.root, job["id"])
    accepted = next(item for item in candidates if "198.51.100.25" in item.addresses)
    assert [(item.port, item.product) for item in accepted.services] == [
        (22, "OpenSSH"),
        (443, "OpenSSH"),
    ]
    decisions = reconcile_candidates(
        record.engagement, candidates, allowed_scope_ids={scope.id}
    )
    rogue = next(item for item in decisions if item.candidate.addresses == ["203.0.113.99"])
    assert rogue.allowed_actions == ("ignore",)


def test_enhanced_job_preserves_partial_host_results_when_port_scan_fails(
    monkeypatch, workspace, record, settings
):
    scope = record.engagement.add_scope(
        "DMZ", ScopeGroup.EXTERNAL, "198.51.100.0/24"
    )
    workspace.save(record.root, record.engagement)
    jobs = DiscoveryJobs(settings, RecordingTmux(), workspace)
    monkeypatch.setattr("tacmux.discovery.shutil.which", lambda _name: "/usr/bin/nmap")
    job = jobs.create(
        record.root,
        record.engagement,
        [scope.id],
        profile=ScanProfile.TCP_SERVICES,
    )

    def fake_run(argv, *, stdout, stderr, check):
        output = Path(argv[argv.index("-oX") + 1])
        if output.name.startswith("host-discovery"):
            output.write_text(_nmap_xml(("198.51.100.25", [], "")))
            return subprocess.CompletedProcess(argv, 0)
        return subprocess.CompletedProcess(argv, 2)

    monkeypatch.setattr("tacmux.discovery.subprocess.run", fake_run)
    job_file = record.root / ".tacmux/jobs" / job["id"] / "job.json"
    assert run_job(settings, job_file) == 2
    status = jobs.list(record.root)[0]
    assert status["state"] == "partial"
    assert status["result_paths"] == ["host-discovery-ipv4.xml"]
    assert jobs.candidates(record.root, job["id"])[0].addresses == ["198.51.100.25"]


def test_enhanced_ipv6_job_uses_ipv6_mode_and_skips_sv_without_ports(
    monkeypatch, workspace, record, settings
):
    scope = record.engagement.add_scope(
        "IPv6 LAN", ScopeGroup.INTERNAL, "2001:db8::/64"
    )
    workspace.save(record.root, record.engagement)
    jobs = DiscoveryJobs(settings, RecordingTmux(), workspace)
    monkeypatch.setattr("tacmux.discovery.shutil.which", lambda _name: "/usr/bin/nmap")
    job = jobs.create(
        record.root,
        record.engagement,
        [scope.id],
        profile=ScanProfile.TCP_SERVICES,
    )
    calls: list[list[str]] = []

    def fake_run(argv, *, stdout, stderr, check):
        calls.append(list(argv))
        output = Path(argv[argv.index("-oX") + 1])
        output.write_text(_nmap_xml(("2001:db8::25", [], "")))
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr("tacmux.discovery.subprocess.run", fake_run)
    job_file = record.root / ".tacmux/jobs" / job["id"] / "job.json"
    assert run_job(settings, job_file) == 0
    assert len(calls) == 2
    assert all("-6" in argv for argv in calls)
    assert not any("-sV" in argv for argv in calls)


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
    before_engagement = record.engagement.to_dict()
    before_directories = {item.name for item in (record.root / "targets").iterdir()}

    def fail_save(*_):
        raise OSError("disk full")

    monkeypatch.setattr(workspace, "save", fail_save)
    with pytest.raises(OSError, match="disk full"):
        apply_reconciliation(
            workspace,
            record.root,
            record.engagement,
            decisions,
            allowed_scope_ids={scope.id},
        )
    assert (record.root / ".tacmux/engagement.json").read_text() == before_manifest
    assert record.engagement.to_dict() == before_engagement
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


def test_discovery_job_ids_are_allocated_under_lock(
    monkeypatch, workspace, record, settings
):
    scope = record.engagement.add_scope("LAN", ScopeGroup.INTERNAL, "10.60.0.0/24")
    workspace.save(record.root, record.engagement)
    jobs = DiscoveryJobs(settings, RecordingTmux(), workspace)
    monkeypatch.setattr("tacmux.discovery.shutil.which", lambda name: "/usr/bin/nmap")
    with ThreadPoolExecutor(max_workers=2) as executor:
        identifiers = {
            future.result()["id"]
            for future in [
                executor.submit(
                    jobs.create, record.root, record.engagement, [scope.id]
                )
                for _ in range(2)
            ]
        }
    assert identifiers == {"J0001", "J0002"}
