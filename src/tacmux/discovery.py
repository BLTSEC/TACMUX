"""Scope-bounded Nmap discovery jobs and explicit result reconciliation."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Iterable, Sequence
import xml.etree.ElementTree as ET

from .config import Settings
from .errors import ConflictError, ExternalToolError, ValidationError
from .model import Engagement, ScopeAvailability, Target, TargetAddress
from .store import Workspace, _private_directory, write_private_json
from .tmux import TmuxService


JOB_SCHEMA = "tacmux.discovery-job/v1"


@dataclass(slots=True)
class DiscoveryCandidate:
    addresses: list[str]
    hostnames: list[str] = field(default_factory=list)
    reason: str = ""

    @property
    def display_name(self) -> str:
        return self.hostnames[0] if self.hostnames else self.addresses[0]


@dataclass(slots=True)
class Reconciliation:
    candidate: DiscoveryCandidate
    addresses: list[TargetAddress]
    action: str
    merge_target_id: str = ""
    note: str = ""


def parse_nmap_xml(path: Path) -> list[DiscoveryCandidate]:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise ValidationError(f"cannot parse Nmap XML {path}: {exc}") from exc
    candidates: list[DiscoveryCandidate] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        addresses = [
            item.get("addr", "")
            for item in host.findall("address")
            if item.get("addrtype") in {"ipv4", "ipv6"} and item.get("addr")
        ]
        hostnames = [
            item.get("name", "")
            for item in host.findall("hostnames/hostname")
            if item.get("name")
        ]
        if addresses:
            candidates.append(
                DiscoveryCandidate(
                    addresses=addresses,
                    hostnames=sorted(set(hostnames)),
                    reason=status.get("reason", ""),
                )
            )
    return candidates


def parse_host_lines(text: str) -> list[DiscoveryCandidate]:
    candidates: list[DiscoveryCandidate] = []
    seen: set[str] = set()
    for number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        try:
            address = str(ipaddress.ip_address(fields[0]))
        except ValueError as exc:
            raise ValidationError(f"line {number}: expected IP [hostname]") from exc
        if address in seen:
            continue
        seen.add(address)
        candidates.append(
            DiscoveryCandidate(
                addresses=[address],
                hostnames=[fields[1]] if len(fields) > 1 else [],
                reason="pasted",
            )
        )
    return candidates


def reconcile_candidates(
    engagement: Engagement,
    candidates: Iterable[DiscoveryCandidate],
    *,
    allowed_scope_ids: set[str] | None = None,
) -> list[Reconciliation]:
    scopes = [
        item
        for item in engagement.scope
        if allowed_scope_ids is None or item.id in allowed_scope_ids
    ]
    results: list[Reconciliation] = []
    for candidate in candidates:
        addresses: list[TargetAddress] = []
        ambiguous = False
        for raw_address in candidate.addresses:
            address = ipaddress.ip_address(raw_address)
            matching = [
                item for item in scopes if address in ipaddress.ip_network(item.network)
            ]
            if len(matching) != 1:
                ambiguous = True
                continue
            addresses.append(TargetAddress(str(address), matching[0].id))
        if ambiguous or not addresses:
            results.append(
                Reconciliation(
                    candidate=candidate,
                    addresses=addresses,
                    action="ignore",
                    note="out of scope or matches more than one selected scope entry",
                )
            )
            continue
        matches: set[str] = set()
        for target in engagement.targets:
            keys = {(item.scope_id, item.value) for item in target.addresses}
            if any((item.scope_id, item.value) in keys for item in addresses):
                matches.add(target.id)
        if len(matches) == 1:
            results.append(
                Reconciliation(
                    candidate=candidate,
                    addresses=addresses,
                    action="merge",
                    merge_target_id=next(iter(matches)),
                    note="scope-qualified address match",
                )
            )
        elif matches:
            results.append(
                Reconciliation(
                    candidate=candidate,
                    addresses=addresses,
                    action="ignore",
                    note="candidate matches multiple existing targets",
                )
            )
        else:
            candidate_names = {
                item.casefold().rstrip(".") for item in candidate.hostnames
            }
            hostname_matches = [
                target.id
                for target in engagement.targets
                if candidate_names
                & {item.casefold().rstrip(".") for item in target.hostnames}
            ]
            if len(hostname_matches) == 1:
                results.append(
                    Reconciliation(
                        candidate=candidate,
                        addresses=addresses,
                        action="add",
                        merge_target_id=hostname_matches[0],
                        note="possible second interface: matching hostname; operator must choose Add or Merge",
                    )
                )
            else:
                results.append(
                    Reconciliation(
                        candidate=candidate, addresses=addresses, action="add"
                    )
                )
    return results


def apply_reconciliation(
    workspace: Workspace,
    engagement_root: Path,
    engagement: Engagement,
    decisions: Sequence[Reconciliation],
) -> list[Target]:
    snapshot = deepcopy(engagement)
    changed: list[Target] = []
    created_roots: list[Path] = []
    try:
        for decision in decisions:
            if decision.action == "ignore":
                continue
            if decision.action == "merge":
                target = engagement.target_by_id(decision.merge_target_id)
                existing = {(item.scope_id, item.value) for item in target.addresses}
                target.addresses.extend(
                    item
                    for item in decision.addresses
                    if (item.scope_id, item.value) not in existing
                )
                target.hostnames = sorted(
                    set(target.hostnames + decision.candidate.hostnames)
                )
                if not target.primary_endpoint:
                    target.primary_endpoint = (
                        target.hostnames[0]
                        if target.hostnames
                        else decision.addresses[0].value
                    )
                changed.append(target)
            elif decision.action == "add":
                primary = (
                    decision.candidate.hostnames[0]
                    if decision.candidate.hostnames
                    else decision.addresses[0].value
                )
                target = workspace.stage_target(
                    engagement_root,
                    engagement,
                    decision.candidate.display_name,
                    addresses=decision.addresses,
                    hostnames=decision.candidate.hostnames,
                    primary_endpoint=primary,
                )
                created_roots.append(engagement_root / "targets" / target.directory)
                changed.append(target)
            else:
                raise ValidationError(
                    f"unknown reconciliation action: {decision.action}"
                )
        engagement.validate()
        workspace.save(engagement_root, engagement)
    except BaseException:
        for item in fields(Engagement):
            setattr(engagement, item.name, deepcopy(getattr(snapshot, item.name)))
        for target_root in created_roots:
            shutil.rmtree(target_root, ignore_errors=True)
        raise
    return list({target.id: target for target in changed}.values())


class DiscoveryJobs:
    def __init__(self, settings: Settings, tmux: TmuxService | None = None):
        self.settings = settings
        self.tmux = tmux or TmuxService(settings)

    def list(self, engagement_root: Path) -> list[dict]:
        jobs: list[dict] = []
        for path in sorted((engagement_root / ".tacmux/jobs").glob("J*/status.json")):
            try:
                with path.open(encoding="utf-8") as stream:
                    value = json.load(stream)
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(value, dict) or value.get("schema") != JOB_SCHEMA:
                continue
            jobs.append(value)
        return jobs

    def active(self, engagement_root: Path) -> list[dict]:
        return [
            item
            for item in self.list(engagement_root)
            if item.get("state") in {"queued", "running"}
        ]

    def cancel(
        self, engagement_root: Path, engagement: Engagement, job_id: str
    ) -> bool:
        job = next(
            (item for item in self.list(engagement_root) if item.get("id") == job_id),
            None,
        )
        if job is None:
            raise ValidationError(f"unknown discovery job: {job_id}")
        if job.get("state") not in {"queued", "running"}:
            return False
        session = str(
            job.get("session") or self.tmux.job_session_name(engagement, job_id)
        )
        if self.tmux.has_session(session):
            self.tmux.run(["kill-session", "-t", f"={session}:"])
        job["state"] = "cancelled"
        job["finished_at"] = (
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        )
        job["exit_code"] = None
        write_private_json(
            engagement_root / ".tacmux/jobs" / job_id / "status.json", job
        )
        return True

    def cancel_all(self, engagement_root: Path, engagement: Engagement) -> int:
        cancelled = 0
        for job in self.active(engagement_root):
            cancelled += int(self.cancel(engagement_root, engagement, str(job["id"])))
        return cancelled

    def mark_imported(self, engagement_root: Path, job_id: str) -> None:
        job = next(
            (item for item in self.list(engagement_root) if item.get("id") == job_id),
            None,
        )
        if job is None:
            raise ValidationError(f"unknown discovery job: {job_id}")
        job["imported_at"] = (
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        )
        write_private_json(
            engagement_root / ".tacmux/jobs" / job_id / "status.json", job
        )

    def create(
        self,
        engagement_root: Path,
        engagement: Engagement,
        scope_ids: Sequence[str],
    ) -> dict:
        if not shutil.which("nmap"):
            raise ExternalToolError(
                "Nmap is not installed; XML and pasted-host import remain available"
            )
        selected = [engagement.scope_by_id(item) for item in scope_ids]
        if not selected:
            raise ValidationError("select at least one scope entry")
        unavailable = [
            item.label
            for item in selected
            if item.availability != ScopeAvailability.READY
        ]
        if unavailable:
            raise ConflictError("scope is unavailable: " + ", ".join(unavailable))
        jobs_root = engagement_root / ".tacmux/jobs"
        _private_directory(jobs_root)
        existing = [
            int(path.name[1:]) for path in jobs_root.glob("J[0-9][0-9][0-9][0-9]")
        ]
        job_id = f"J{(max(existing, default=0) + 1):04d}"
        job_root = jobs_root / job_id
        _private_directory(job_root)
        xml_path = job_root / "results.xml"
        log_path = job_root / "nmap.log"
        argv = [
            "nmap",
            "-sn",
            "--reason",
            "-oX",
            str(xml_path),
            *[item.network for item in selected],
        ]
        value = {
            "schema": JOB_SCHEMA,
            "id": job_id,
            "engagement_id": engagement.id,
            "scope_ids": list(scope_ids),
            "state": "queued",
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "started_at": None,
            "finished_at": None,
            "exit_code": None,
            "imported_at": None,
            "argv": argv,
            "xml_path": str(xml_path),
            "log_path": str(log_path),
        }
        job_file = job_root / "job.json"
        session = self.tmux.job_session_name(engagement, job_id)
        value["session"] = session
        write_private_json(job_file, value)
        write_private_json(job_root / "status.json", value)
        command = [
            sys.executable,
            "-m",
            "tacmux.cli",
            "_internal",
            "run-job",
            str(job_file),
        ]
        try:
            self.tmux.run(
                ["new-session", "-d", "-s", session, "-c", str(job_root), *command]
            )
        except ExternalToolError as exc:
            value["state"] = "failed"
            value["error"] = str(exc)
            value["finished_at"] = (
                datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            )
            write_private_json(job_root / "status.json", value)
            raise
        return value


def run_job(job_file: Path) -> int:
    try:
        with job_file.open(encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"cannot read discovery job: {exc}") from exc
    if value.get("schema") != JOB_SCHEMA:
        raise ValidationError("unsupported discovery job schema")
    status_path = job_file.parent / "status.json"
    value["state"] = "running"
    value["started_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    write_private_json(status_path, value)
    log_path = Path(value["log_path"])
    try:
        descriptor = os.open(log_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "wb") as log:
            result = subprocess.run(
                value["argv"], stdout=log, stderr=subprocess.STDOUT, check=False
            )
        value["exit_code"] = result.returncode
        value["state"] = "succeeded" if result.returncode == 0 else "failed"
    except OSError as exc:
        value["state"] = "failed"
        value["error"] = str(exc)
        value["exit_code"] = 127
    value["finished_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    write_private_json(status_path, value)
    return int(value["exit_code"] or 0)
