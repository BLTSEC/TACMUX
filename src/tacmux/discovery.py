"""Scope-bounded Nmap discovery jobs and explicit result reconciliation."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Iterable, Sequence
import xml.etree.ElementTree as ET

from .config import Settings
from .errors import ConflictError, ExternalToolError, ValidationError
from .model import Engagement, ScopeAvailability, Target, TargetAddress
from .store import (
    Workspace,
    _private_directory,
    restore_engagement_state,
    write_private_json,
)
from .tmux import TmuxService


JOB_SCHEMA = "tacmux.discovery-job/v1"


@dataclass(slots=True)
class DiscoveryCandidate:
    addresses: list[str]
    hostnames: list[str] = field(default_factory=list)
    reason: str = ""

    @property
    def display_name(self) -> str:
        if self.hostnames:
            return self.hostnames[0]
        if self.addresses:
            return self.addresses[0]
        return "unnamed discovery candidate"


@dataclass(slots=True)
class Reconciliation:
    candidate: DiscoveryCandidate
    addresses: list[TargetAddress]
    action: str
    merge_target_id: str = ""
    note: str = ""
    allowed_actions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.allowed_actions:
            return
        if self.action == "add":
            self.allowed_actions = ("add", "merge", "ignore")
        elif self.action == "merge":
            self.allowed_actions = ("merge", "ignore")
        else:
            self.allowed_actions = ("ignore",)

    @property
    def fully_scope_qualified(self) -> bool:
        return bool(self.addresses) and len(self.addresses) == len(
            self.candidate.addresses
        )

    def validate_action(self) -> None:
        if self.action not in self.allowed_actions:
            raise ValidationError(
                f"discovery action {self.action!r} is not allowed for "
                f"{self.candidate.display_name}"
            )
        if self.action == "ignore":
            return
        if not self.fully_scope_qualified:
            raise ValidationError(
                f"cannot accept {self.candidate.display_name}: every discovered "
                "address must match exactly one selected scope entry"
            )
        if self.action == "merge" and not self.merge_target_id:
            raise ValidationError("choose an existing target before merging")


def parse_nmap_xml(path: Path) -> list[DiscoveryCandidate]:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise ValidationError(f"cannot parse Nmap XML {path}: {exc}") from exc
    candidates: list[DiscoveryCandidate] = []
    for host_index, host in enumerate(root.findall("host"), 1):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        addresses: list[str] = []
        for item in host.findall("address"):
            raw_address = item.get("addr", "")
            if item.get("addrtype") not in {"ipv4", "ipv6"} or not raw_address:
                continue
            try:
                addresses.append(str(ipaddress.ip_address(raw_address)))
            except ValueError as exc:
                raise ValidationError(
                    f"Nmap XML host {host_index} contains an invalid IP address: "
                    f"{raw_address}"
                ) from exc
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
        unmatched: list[str] = []
        ambiguous: list[str] = []
        for raw_address in candidate.addresses:
            try:
                address = ipaddress.ip_address(raw_address)
            except ValueError as exc:
                raise ValidationError(
                    f"discovery candidate contains an invalid IP address: {raw_address}"
                ) from exc
            matching = [
                item for item in scopes if address in ipaddress.ip_network(item.network)
            ]
            if not matching:
                unmatched.append(str(address))
                continue
            if len(matching) > 1:
                ambiguous.append(str(address))
                continue
            addresses.append(TargetAddress(str(address), matching[0].id))
        if unmatched or ambiguous or not addresses:
            reasons: list[str] = []
            if unmatched:
                reasons.append("outside selected scope: " + ", ".join(unmatched))
            if ambiguous:
                reasons.append(
                    "matches more than one selected scope entry: "
                    + ", ".join(ambiguous)
                )
            if not reasons:
                reasons.append("candidate has no scope-qualified address")
            results.append(
                Reconciliation(
                    candidate=candidate,
                    addresses=addresses,
                    action="ignore",
                    note="; ".join(reasons),
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
    *,
    allowed_scope_ids: set[str],
) -> list[Target]:
    if not allowed_scope_ids:
        raise ValidationError("discovery commit requires at least one scope entry")
    for scope_id in allowed_scope_ids:
        engagement.scope_by_id(scope_id)
    snapshot = deepcopy(engagement)
    changed: list[Target] = []
    created_roots: list[Path] = []
    try:
        for requested in decisions:
            canonical = reconcile_candidates(
                engagement,
                [requested.candidate],
                allowed_scope_ids=allowed_scope_ids,
            )[0]
            canonical.action = requested.action
            if requested.action == "merge":
                if (
                    canonical.allowed_actions == ("merge", "ignore")
                    and canonical.merge_target_id
                    and requested.merge_target_id != canonical.merge_target_id
                ):
                    raise ValidationError(
                        f"{requested.candidate.display_name} already belongs to "
                        f"{canonical.merge_target_id}"
                    )
                canonical.merge_target_id = requested.merge_target_id
            canonical.validate_action()
            if canonical.action == "ignore":
                continue
            if canonical.action == "merge":
                target = engagement.target_by_id(canonical.merge_target_id)
                existing = {(item.scope_id, item.value) for item in target.addresses}
                target.addresses.extend(
                    item
                    for item in canonical.addresses
                    if (item.scope_id, item.value) not in existing
                )
                target.hostnames = sorted(
                    set(target.hostnames + canonical.candidate.hostnames)
                )
                if not target.primary_endpoint:
                    target.primary_endpoint = canonical.addresses[0].value
                changed.append(target)
            elif canonical.action == "add":
                target = workspace.stage_target(
                    engagement_root,
                    engagement,
                    canonical.candidate.display_name,
                    addresses=canonical.addresses,
                    hostnames=canonical.candidate.hostnames,
                    primary_endpoint=canonical.addresses[0].value,
                )
                created_roots.append(engagement_root / "targets" / target.directory)
                changed.append(target)
            else:
                raise ValidationError(
                    f"unknown reconciliation action: {canonical.action}"
                )
        engagement.validate()
        workspace.save(engagement_root, engagement)
    except BaseException:
        restore_engagement_state(engagement, snapshot)
        for target_root in created_roots:
            shutil.rmtree(target_root, ignore_errors=True)
        raise
    return list({target.id: target for target in changed}.values())


class DiscoveryJobs:
    def __init__(
        self,
        settings: Settings,
        tmux: TmuxService | None = None,
        workspace: Workspace | None = None,
    ):
        self.settings = settings
        self.tmux = tmux or TmuxService(settings)
        self.workspace = workspace or Workspace(settings)

    def list(self, engagement_root: Path) -> list[dict]:
        jobs: list[dict] = []
        for path in sorted((engagement_root / ".tacmux/jobs").glob("J*/status.json")):
            try:
                with path.open(encoding="utf-8") as stream:
                    value = json.load(stream)
            except (OSError, json.JSONDecodeError):
                continue
            job_id = path.parent.name
            if (
                not isinstance(value, dict)
                or value.get("schema") != JOB_SCHEMA
                or value.get("id") != job_id
                or not re.fullmatch(r"J[0-9]{4,}", job_id)
                or not isinstance(value.get("scope_ids"), list)
                or any(not isinstance(item, str) for item in value["scope_ids"])
            ):
                continue
            value["xml_path"] = str(path.parent / "results.xml")
            value["log_path"] = str(path.parent / "nmap.log")
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
        with self.workspace.lock(engagement_root):
            job = next(
                (
                    item
                    for item in self.list(engagement_root)
                    if item.get("id") == job_id
                ),
                None,
            )
            if job is None:
                raise ValidationError(f"unknown discovery job: {job_id}")
            if job.get("state") not in {"queued", "running"}:
                return False
            session = self.tmux.job_session_name(engagement, job_id)
            if self.tmux.has_session(session):
                self.tmux.run(["kill-session", "-t", f"={session}:"])
            job["session"] = session
            job["state"] = "cancelled"
            job["finished_at"] = _utc_now()
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
        with self.workspace.lock(engagement_root):
            job = next(
                (
                    item
                    for item in self.list(engagement_root)
                    if item.get("id") == job_id
                ),
                None,
            )
            if job is None:
                raise ValidationError(f"unknown discovery job: {job_id}")
            job["imported_at"] = _utc_now()
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
        if len(scope_ids) != len(set(scope_ids)):
            raise ValidationError("select each scope entry only once")
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
        with self.workspace.lock(engagement_root):
            current = self.workspace.load(engagement_root)
            if current.revision != engagement.revision:
                raise ConflictError(
                    "engagement changed in another TACMUX process; refresh and retry"
                )
            _private_directory(jobs_root)
            existing = [
                int(path.name[1:])
                for path in jobs_root.iterdir()
                if path.is_dir() and re.fullmatch(r"J[0-9]{4,}", path.name)
            ]
            job_id = f"J{(max(existing, default=0) + 1):04d}"
            job_root = jobs_root / job_id
            job_root.mkdir(mode=0o700)
            os.chmod(job_root, 0o700)
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
                "created_at": _utc_now(),
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
            value["finished_at"] = _utc_now()
            with self.workspace.lock(engagement_root):
                write_private_json(job_root / "status.json", value)
            raise
        return value


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _job_location(settings: Settings, job_file: Path) -> tuple[Path, Path, str]:
    try:
        resolved = job_file.resolve(strict=True)
        workspace_root = settings.workspace.resolve(strict=True)
        relative = resolved.relative_to(workspace_root)
    except (OSError, ValueError) as exc:
        raise ValidationError(
            "discovery job must be an existing file inside the configured workspace"
        ) from exc
    parts = relative.parts
    if (
        len(parts) != 5
        or parts[1:3] != (".tacmux", "jobs")
        or not re.fullmatch(r"J[0-9]{4,}", parts[3])
        or parts[4] != "job.json"
    ):
        raise ValidationError("discovery job has an invalid workspace path")
    return workspace_root / parts[0], resolved.parent, parts[3]


def _load_job(job_file: Path) -> dict:
    try:
        with job_file.open(encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"cannot read discovery job: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError("discovery job must contain a JSON object")
    return value


def _current_job_status(
    settings: Settings,
    workspace: Workspace,
    engagement_root: Path,
    job_id: str,
) -> dict | None:
    return next(
        (
            item
            for item in DiscoveryJobs(settings, workspace=workspace).list(
                engagement_root
            )
            if item.get("id") == job_id
        ),
        None,
    )


def run_job(settings: Settings, job_file: Path) -> int:
    engagement_root, job_root, job_id = _job_location(settings, job_file)
    workspace = Workspace(settings)
    status_path = job_root / "status.json"
    value: dict = {}
    with workspace.lock(engagement_root):
        current = _current_job_status(
            settings, workspace, engagement_root, job_id
        )
        if current is not None and current.get("state") == "cancelled":
            return 130
        if current is None or current.get("state") != "queued":
            raise ConflictError(
                f"discovery job {job_id} is not queued and will not be started"
            )
    try:
        value = _load_job(job_file.resolve(strict=True))
        if value.get("schema") != JOB_SCHEMA:
            raise ValidationError("unsupported discovery job schema")
        if value.get("id") != job_id:
            raise ValidationError("discovery job ID does not match its directory")
        engagement = workspace.load(engagement_root)
        if value.get("engagement_id") != engagement.id:
            raise ValidationError("discovery job belongs to a different engagement")
        scope_ids = value.get("scope_ids")
        if (
            not isinstance(scope_ids, list)
            or not scope_ids
            or any(not isinstance(item, str) for item in scope_ids)
            or len(scope_ids) != len(set(scope_ids))
        ):
            raise ValidationError("discovery job has invalid scope IDs")
        selected = [engagement.scope_by_id(item) for item in scope_ids]
        unavailable = [
            item.label
            for item in selected
            if item.availability != ScopeAvailability.READY
        ]
        if unavailable:
            raise ValidationError(
                "discovery job scope is unavailable: " + ", ".join(unavailable)
            )
        nmap = shutil.which("nmap")
        if not nmap:
            raise ExternalToolError("Nmap is not installed")
        xml_path = job_root / "results.xml"
        log_path = job_root / "nmap.log"
        value.update(
            {
                "id": job_id,
                "engagement_id": engagement.id,
                "scope_ids": scope_ids,
                "session": TmuxService(settings).job_session_name(engagement, job_id),
                "argv": [
                    nmap,
                    "-sn",
                    "--reason",
                    "-oX",
                    str(xml_path),
                    *[item.network for item in selected],
                ],
                "xml_path": str(xml_path),
                "log_path": str(log_path),
                "state": "running",
                "started_at": _utc_now(),
                "finished_at": None,
                "exit_code": None,
            }
        )
        value.pop("error", None)
    except (ExternalToolError, ValidationError) as exc:
        failure = {
            "schema": JOB_SCHEMA,
            "id": job_id,
            "engagement_id": value.get("engagement_id", ""),
            "scope_ids": value.get("scope_ids", [])
            if isinstance(value.get("scope_ids", []), list)
            else [],
            "state": "failed",
            "finished_at": _utc_now(),
            "exit_code": 127,
            "error": str(exc),
        }
        with workspace.lock(engagement_root):
            current = _current_job_status(
                settings, workspace, engagement_root, job_id
            )
            if current is not None and current.get("state") == "queued":
                write_private_json(status_path, failure)
        raise

    with workspace.lock(engagement_root):
        current = _current_job_status(
            settings, workspace, engagement_root, job_id
        )
        if current is not None and current.get("state") == "cancelled":
            return 130
        if current is None or current.get("state") != "queued":
            raise ConflictError(
                f"discovery job {job_id} is not queued and will not be started"
            )
        write_private_json(status_path, value)

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
    value["finished_at"] = _utc_now()
    with workspace.lock(engagement_root):
        current = _current_job_status(
            settings, workspace, engagement_root, job_id
        )
        if current is not None and current.get("state") == "cancelled":
            return 130
        write_private_json(status_path, value)
    return int(value["exit_code"] or 0)
