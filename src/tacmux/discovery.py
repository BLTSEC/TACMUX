"""Scope-bounded Nmap discovery jobs and explicit result reconciliation."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
import ipaddress
from itertools import combinations
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import BinaryIO, Iterable, Sequence
import xml.etree.ElementTree as ET

from .config import Settings
from .errors import ConflictError, ExternalToolError, SafetyError, ValidationError
from .model import (
    Engagement,
    ScopeEntry,
    ScopeAvailability,
    ScopeKind,
    Service,
    Target,
    TargetAddress,
    hostname_matches,
    merge_services,
    normalize_hostname,
)
from .store import (
    Workspace,
    _private_directory,
    contained_path,
    contained_regular_file,
    require_contained_parent,
    restore_engagement_state,
    write_private_bytes,
    write_private_json,
)
from .tmux import TmuxService


JOB_SCHEMA = "tacmux.discovery-job/v1"
JOB_SPEC_FIELDS = (
    "schema",
    "id",
    "engagement_id",
    "scope_ids",
    "profile",
    "pace",
    "created_at",
    "session",
)
JOB_STATUS_FIELDS = (
    *JOB_SPEC_FIELDS,
    "phase",
    "state",
    "started_at",
    "finished_at",
    "exit_code",
    "imported_at",
    "result_paths",
    "artifacts",
    "error",
)


def _job_document(value: dict, fields: Sequence[str]) -> dict:
    """Return the portable subset allowed in a discovery JSON document."""

    return {key: value[key] for key in fields if key in value}


def _write_job_status(path: Path, value: dict) -> None:
    write_private_json(path, _job_document(value, JOB_STATUS_FIELDS))


class ScanProfile(StrEnum):
    HOSTS = "hosts"
    TCP_SERVICES = "tcp-services"


class ScanPace(StrEnum):
    CAREFUL = "careful"
    FAST = "fast"


def _validated_scan_scopes(
    engagement: Engagement, scope_ids: Sequence[str]
) -> list[ScopeEntry]:
    if len(scope_ids) != len(set(scope_ids)):
        raise ValidationError("select each scope entry only once")
    selected = [engagement.scope_by_id(item) for item in scope_ids]
    if not selected:
        raise ValidationError("select at least one scope entry")
    domains = [item.label for item in selected if item.kind != ScopeKind.NETWORK]
    if domains:
        raise ValidationError(
            "domain scope entries cannot be scanned by TACMUX; import a host list instead"
        )
    unavailable = [
        item.label
        for item in selected
        if item.availability != ScopeAvailability.READY
    ]
    if unavailable:
        raise ConflictError("scope is unavailable: " + ", ".join(unavailable))
    for left, right in combinations(selected, 2):
        left_network = ipaddress.ip_network(left.network)
        right_network = ipaddress.ip_network(right.network)
        if (
            left_network.version == right_network.version
            and left_network.overlaps(right_network)
        ):
            raise ValidationError(
                "overlapping scope entries must be discovered in separate jobs: "
                f"{left.label}, {right.label}"
            )
    return selected


def _scan_argv(
    nmap: str,
    xml_path: Path,
    scopes: Sequence[ScopeEntry],
    *,
    ipv6: bool = False,
) -> list[str]:
    exclusions = sorted({item for scope in scopes for item in scope.exclusions})
    argv = [nmap]
    if ipv6:
        argv.append("-6")
    argv.extend(["-sn", "--reason"])
    if exclusions:
        argv.extend(["--exclude", ",".join(exclusions)])
    argv.extend(["-oX", str(xml_path), *[item.network for item in scopes]])
    return argv


def _port_scan_argv(
    nmap: str,
    xml_path: Path,
    addresses: Sequence[str],
    pace: ScanPace,
    *,
    ipv6: bool = False,
) -> list[str]:
    argv = [nmap]
    if ipv6:
        argv.append("-6")
    argv.extend(["-Pn", "-p-", "--open", "--reason"])
    if pace == ScanPace.FAST:
        argv.append("-T4")
    argv.extend(["-oX", str(xml_path), *addresses])
    return argv


def _service_scan_argv(
    nmap: str,
    xml_path: Path,
    addresses: Sequence[str],
    ports: Sequence[int],
    pace: ScanPace,
    *,
    ipv6: bool = False,
) -> list[str]:
    if not addresses or not ports:
        raise ValidationError("service detection requires hosts and open TCP ports")
    argv = [nmap]
    if ipv6:
        argv.append("-6")
    argv.extend(["-Pn", "-sV", "--open", "-p", ",".join(map(str, ports))])
    if pace == ScanPace.FAST:
        argv.append("-T4")
    argv.extend(["-oX", str(xml_path), *addresses])
    return argv


def _scan_profile(value: object) -> ScanProfile:
    try:
        return ScanProfile(str(value or ScanProfile.HOSTS.value))
    except ValueError as exc:
        raise ValidationError("unknown discovery scan profile") from exc


def _scan_pace(value: object) -> ScanPace:
    try:
        return ScanPace(str(value or ScanPace.CAREFUL.value))
    except ValueError as exc:
        raise ValidationError("unknown discovery scan pace") from exc


@dataclass(slots=True)
class DiscoveryCandidate:
    addresses: list[str]
    hostnames: list[str] = field(default_factory=list)
    reason: str = ""
    services: list[Service] = field(default_factory=list)

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
    hostname_scope_id: str = ""

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
        return (
            bool(self.addresses)
            and len(self.addresses) == len(self.candidate.addresses)
        ) or (not self.candidate.addresses and bool(self.hostname_scope_id))

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


def parse_nmap_xml(path: Path, *, source: str = "") -> list[DiscoveryCandidate]:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError, LookupError, UnicodeError) as exc:
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
        hostnames: list[str] = []
        for item in host.findall("hostnames/hostname"):
            raw_hostname = item.get("name", "")
            if not raw_hostname:
                continue
            try:
                hostnames.append(normalize_hostname(raw_hostname))
            except ValidationError:
                continue
        services: list[Service] = []
        for port in host.findall("ports/port"):
            protocol = port.get("protocol", "")
            raw_port = port.get("portid", "")
            try:
                port_number = int(raw_port)
            except ValueError as exc:
                raise ValidationError(
                    f"Nmap XML host {host_index} contains an invalid port: {raw_port}"
                ) from exc
            if not 1 <= port_number <= 65535 or protocol not in {
                "tcp",
                "udp",
                "sctp",
            }:
                raise ValidationError(
                    f"Nmap XML host {host_index} contains an invalid service endpoint: "
                    f"{raw_port}/{protocol or 'unknown'}"
                )
            state_element = port.find("state")
            state = state_element.get("state", "") if state_element is not None else ""
            if protocol == "udp":
                keep = state in {"open", "open|filtered"}
            else:
                keep = state == "open"
            if not keep:
                continue
            service = port.find("service")
            services.append(
                Service(
                    port=port_number,
                    protocol=protocol,
                    name=service.get("name", "") if service is not None else "",
                    product=service.get("product", "") if service is not None else "",
                    version=service.get("version", "") if service is not None else "",
                    extra=service.get("extrainfo", "") if service is not None else "",
                    tunnel=service.get("tunnel", "") if service is not None else "",
                    state=state,
                    source=source,
                )
            )
        if addresses:
            candidates.append(
                DiscoveryCandidate(
                    addresses=addresses,
                    hostnames=sorted(set(hostnames)),
                    reason=status.get("reason", ""),
                    services=merge_services([], services),
                )
            )
    return candidates


def merge_discovery_candidates(
    groups: Iterable[Iterable[DiscoveryCandidate]],
) -> list[DiscoveryCandidate]:
    """Overlay host, port, and service results that share an IP address."""

    merged: list[DiscoveryCandidate] = []
    for group in groups:
        for candidate in group:
            matching = [
                item
                for item in merged
                if set(item.addresses) & set(candidate.addresses)
            ]
            if not matching:
                merged.append(
                    DiscoveryCandidate(
                        addresses=list(candidate.addresses),
                        hostnames=list(candidate.hostnames),
                        reason=candidate.reason,
                        services=list(candidate.services),
                    )
                )
                continue
            primary = matching[0]
            primary.addresses = sorted(set(primary.addresses + candidate.addresses))
            primary.hostnames = sorted(set(primary.hostnames + candidate.hostnames))
            primary.services = merge_services(primary.services, candidate.services)
            if not primary.reason:
                primary.reason = candidate.reason
            for duplicate in matching[1:]:
                primary.addresses = sorted(set(primary.addresses + duplicate.addresses))
                primary.hostnames = sorted(set(primary.hostnames + duplicate.hostnames))
                primary.services = merge_services(primary.services, duplicate.services)
                merged.remove(duplicate)
    return sorted(merged, key=lambda item: tuple(item.addresses))


def parse_nmap_results(
    paths: Sequence[tuple[Path, str]],
) -> list[DiscoveryCandidate]:
    return merge_discovery_candidates(
        parse_nmap_xml(path, source=source) for path, source in paths
    )


def parse_host_lines(text: str) -> list[DiscoveryCandidate]:
    candidates: list[DiscoveryCandidate] = []
    seen: set[tuple[str, str]] = set()
    address_candidates: dict[str, DiscoveryCandidate] = {}
    for number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) > 2:
            raise ValidationError(
                f"line {number}: expected IP [hostname] or hostname"
            )
        try:
            address = str(ipaddress.ip_address(fields[0]))
        except ValueError:
            if len(fields) != 1:
                raise ValidationError(
                    f"line {number}: expected IP [hostname] or hostname"
                )
            try:
                hostname = normalize_hostname(fields[0])
            except ValidationError as exc:
                raise ValidationError(
                    f"line {number}: expected IP [hostname] or hostname"
                ) from exc
            key = ("hostname", hostname)
            if key in seen:
                continue
            seen.add(key)
            candidates.append(
                DiscoveryCandidate(addresses=[], hostnames=[hostname], reason="pasted")
            )
            continue
        hostnames: list[str] = []
        if len(fields) > 1:
            try:
                hostnames = [normalize_hostname(fields[1])]
            except ValidationError as exc:
                raise ValidationError(
                    f"line {number}: expected IP [hostname] or hostname"
                ) from exc
        existing = address_candidates.get(address)
        if existing is not None:
            existing.hostnames = sorted(set(existing.hostnames + hostnames))
            continue
        candidate = DiscoveryCandidate(
            addresses=[address],
            hostnames=hostnames,
            reason="pasted",
        )
        address_candidates[address] = candidate
        candidates.append(candidate)
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
        if not candidate.addresses:
            if not candidate.hostnames:
                results.append(
                    Reconciliation(
                        candidate=candidate,
                        addresses=[],
                        action="ignore",
                        note="candidate has no address or hostname",
                    )
                )
                continue
            hostname = normalize_hostname(candidate.hostnames[0])
            raw_matches = [
                item
                for item in scopes
                if item.kind == ScopeKind.DOMAIN
                and hostname_matches(item.domain, hostname)
            ]
            matching = [item for item in raw_matches if item.matches_hostname(hostname)]
            if not matching:
                note = (
                    f"excluded by {raw_matches[0].label}"
                    if raw_matches
                    else "outside selected domain scope"
                )
                results.append(
                    Reconciliation(candidate, [], "ignore", note=note)
                )
                continue
            if len(matching) > 1:
                results.append(
                    Reconciliation(
                        candidate,
                        [],
                        "ignore",
                        note="matches more than one selected domain entry",
                    )
                )
                continue
            existing = [
                target.id
                for target in engagement.targets
                if hostname in target.hostnames
            ]
            if len(existing) == 1:
                results.append(
                    Reconciliation(
                        candidate,
                        [],
                        "merge",
                        merge_target_id=existing[0],
                        note=f"hostname match in {matching[0].label}",
                        hostname_scope_id=matching[0].id,
                    )
                )
            elif existing:
                results.append(
                    Reconciliation(
                        candidate,
                        [],
                        "ignore",
                        note="candidate matches multiple existing targets",
                    )
                )
            else:
                results.append(
                    Reconciliation(
                        candidate,
                        [],
                        "add",
                        note=f"matched domain scope: {matching[0].label}",
                        hostname_scope_id=matching[0].id,
                    )
                )
            continue
        addresses: list[TargetAddress] = []
        unmatched: list[str] = []
        ambiguous: list[str] = []
        excluded: list[str] = []
        for raw_address in candidate.addresses:
            try:
                address = ipaddress.ip_address(raw_address)
            except ValueError as exc:
                raise ValidationError(
                    f"discovery candidate contains an invalid IP address: {raw_address}"
                ) from exc
            matching: list[ScopeEntry] = []
            for item in scopes:
                if item.kind != ScopeKind.NETWORK:
                    continue
                network = ipaddress.ip_network(item.network)
                if address.version == network.version and address in network:
                    matching.append(item)
            if not matching:
                unmatched.append(str(address))
                continue
            allowed = [item for item in matching if item.contains(address)]
            if not allowed:
                excluded.append(str(address))
                continue
            if len(allowed) > 1:
                ambiguous.append(str(address))
                continue
            addresses.append(TargetAddress(str(address), allowed[0].id))
        if unmatched or ambiguous or excluded or not addresses:
            reasons: list[str] = []
            if unmatched:
                reasons.append("outside selected scope: " + ", ".join(unmatched))
            if ambiguous:
                reasons.append(
                    "matches more than one selected scope entry: "
                    + ", ".join(ambiguous)
                )
            if excluded:
                reasons.append("excluded from selected scope: " + ", ".join(excluded))
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
            existing_hostname_matches = [
                target.id
                for target in engagement.targets
                if candidate_names
                & {item.casefold().rstrip(".") for item in target.hostnames}
            ]
            if len(existing_hostname_matches) == 1:
                results.append(
                    Reconciliation(
                        candidate=candidate,
                        addresses=addresses,
                        action="add",
                        merge_target_id=existing_hostname_matches[0],
                        note=(
                            "possible second interface: matching hostname; "
                            "operator must choose Add or Merge"
                        ),
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
    source_copy: tuple[Path, Path] | None = None,
) -> list[Target]:
    workspace.require_active(engagement)
    if not allowed_scope_ids:
        raise ValidationError("discovery commit requires at least one scope entry")
    for scope_id in allowed_scope_ids:
        engagement.scope_by_id(scope_id)
    snapshot = deepcopy(engagement)
    changed: list[Target] = []
    created_roots: list[Path] = []
    copied_source: Path | None = None
    services_accepted = False
    try:
        with workspace.lock(engagement_root):
            workspace._assert_current_revision(engagement_root, engagement)
            workspace.require_active(engagement)
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
                    existing = {
                        (item.scope_id, item.value) for item in target.addresses
                    }
                    target.addresses.extend(
                        item
                        for item in canonical.addresses
                        if (item.scope_id, item.value) not in existing
                    )
                    target.hostnames = sorted(
                        set(target.hostnames + canonical.candidate.hostnames)
                    )
                    target.services = merge_services(
                        target.services, canonical.candidate.services
                    )
                    services_accepted = services_accepted or bool(
                        canonical.candidate.services
                    )
                    if not target.primary_endpoint:
                        target.primary_endpoint = (
                            canonical.addresses[0].value
                            if canonical.addresses
                            else canonical.candidate.hostnames[0]
                        )
                    changed.append(target)
                elif canonical.action == "add":
                    target = workspace.stage_target(
                        engagement_root,
                        engagement,
                        canonical.candidate.display_name,
                        addresses=canonical.addresses,
                        hostnames=canonical.candidate.hostnames,
                        primary_endpoint=(
                            canonical.addresses[0].value
                            if canonical.addresses
                            else canonical.candidate.hostnames[0]
                        ),
                        services=canonical.candidate.services,
                    )
                    created_roots.append(
                        engagement_root / "targets" / target.directory
                    )
                    changed.append(target)
                    services_accepted = services_accepted or bool(
                        canonical.candidate.services
                    )
                else:
                    raise ValidationError(
                        f"unknown reconciliation action: {canonical.action}"
                    )
            engagement.normalize()
            engagement.validate()
            if source_copy is not None and services_accepted:
                source, destination = source_copy
                require_contained_parent(engagement_root, destination.parent)
                _private_directory(destination.parent)
                require_contained_parent(engagement_root, destination)
                write_private_bytes(destination, source.read_bytes(), replace=False)
                copied_source = destination
            workspace.save(engagement_root, engagement, True)
    except BaseException:
        restore_engagement_state(engagement, snapshot)
        for target_root in created_roots:
            shutil.rmtree(target_root, ignore_errors=True)
        if copied_source is not None:
            copied_source.unlink(missing_ok=True)
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
        self.workspace._require_engagement_root(engagement_root)
        jobs_root = engagement_root / ".tacmux/jobs"
        if not jobs_root.is_dir() or not contained_path(engagement_root, jobs_root):
            raise SafetyError(
                f"discovery job directory is missing or unsafe: {jobs_root}"
            )
        jobs: list[dict] = []
        for path in sorted(jobs_root.glob("J*/status.json")):
            if not contained_regular_file(engagement_root, path):
                continue
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
            result_names = value.get("result_paths", ["results.xml"])
            if (
                not isinstance(result_names, list)
                or any(
                    not isinstance(item, str)
                    or not item
                    or Path(item).name != item
                    for item in result_names
                )
            ):
                continue
            artifact_names = value.get("artifacts", result_names)
            if not isinstance(artifact_names, list):
                artifact_names = result_names
            normalized_artifacts: list[str] = []
            for item in artifact_names:
                name = item.get("path") if isinstance(item, dict) else item
                if isinstance(name, str) and name and Path(name).name == name:
                    normalized_artifacts.append(name)
            job = _job_document(value, JOB_STATUS_FIELDS)
            job["result_paths"] = result_names
            job["artifact_paths"] = [
                str(path.parent / item) for item in normalized_artifacts
            ]
            job["xml_path"] = str(
                path.parent / (result_names[0] if result_names else "results.xml")
            )
            job["log_path"] = str(path.parent / "nmap.log")
            jobs.append(job)
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
            _write_job_status(
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
            self.workspace.require_active(self.workspace.load(engagement_root))
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
            _write_job_status(
                engagement_root / ".tacmux/jobs" / job_id / "status.json", job
            )

    def candidates(
        self, engagement_root: Path, job_id: str
    ) -> list[DiscoveryCandidate]:
        job = next(
            (item for item in self.list(engagement_root) if item["id"] == job_id),
            None,
        )
        if job is None:
            raise ValidationError(f"unknown discovery job: {job_id}")
        paths: list[tuple[Path, str]] = []
        for name in job.get("result_paths", []):
            path = engagement_root / ".tacmux/jobs" / job_id / str(name)
            if not contained_regular_file(engagement_root, path):
                continue
            paths.append((path, path.relative_to(engagement_root).as_posix()))
        if not paths:
            raise ValidationError(f"discovery job {job_id} has no importable results")
        return parse_nmap_results(paths)

    def create(
        self,
        engagement_root: Path,
        engagement: Engagement,
        scope_ids: Sequence[str],
        *,
        profile: ScanProfile | str = ScanProfile.HOSTS,
        pace: ScanPace | str = ScanPace.CAREFUL,
    ) -> dict:
        self.workspace.require_active(engagement)
        if not shutil.which("nmap"):
            raise ExternalToolError(
                "Nmap is not installed; XML and pasted-host import remain available"
            )
        _validated_scan_scopes(engagement, scope_ids)
        selected_profile = _scan_profile(profile)
        selected_pace = _scan_pace(pace)
        jobs_root = engagement_root / ".tacmux/jobs"
        with self.workspace.lock(engagement_root):
            current = self.workspace.load(engagement_root)
            if current.revision != engagement.revision:
                raise ConflictError(
                    "engagement changed in another TACMUX process; refresh and retry"
                )
            self.workspace.require_active(current)
            _private_directory(jobs_root)
            existing = [
                int(path.name[1:])
                for path in jobs_root.iterdir()
                if path.is_dir() and re.fullmatch(r"J[0-9]{4,}", path.name)
            ]
            job_id = f"J{(max(existing, default=0) + 1):04d}"
            job_root = jobs_root / job_id
            require_contained_parent(engagement_root, job_root)
            job_root.mkdir(mode=0o700)
            os.chmod(job_root, 0o700)
            value = {
                "schema": JOB_SCHEMA,
                "id": job_id,
                "engagement_id": engagement.id,
                "scope_ids": list(scope_ids),
                "profile": selected_profile.value,
                "pace": selected_pace.value,
                "phase": "queued",
                "state": "queued",
                "created_at": _utc_now(),
                "started_at": None,
                "finished_at": None,
                "exit_code": None,
                "imported_at": None,
                "result_paths": ["results.xml"]
                if selected_profile == ScanProfile.HOSTS
                else [],
                "artifacts": ["results.xml"]
                if selected_profile == ScanProfile.HOSTS
                else [],
            }
            job_file = job_root / "job.json"
            session = self.tmux.job_session_name(engagement, job_id)
            value["session"] = session
            write_private_json(job_file, _job_document(value, JOB_SPEC_FIELDS))
            _write_job_status(job_root / "status.json", value)
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
                _write_job_status(job_root / "status.json", value)
            raise
        return next(
            item for item in self.list(engagement_root) if item["id"] == job_id
        )


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


class _JobCancelled(Exception):
    pass


def _scope_families(scopes: Sequence[ScopeEntry]) -> dict[int, list[ScopeEntry]]:
    families: dict[int, list[ScopeEntry]] = {4: [], 6: []}
    for scope in scopes:
        families[ipaddress.ip_network(scope.network).version].append(scope)
    return {version: items for version, items in families.items() if items}


def _validated_stage_addresses(
    candidates: Iterable[DiscoveryCandidate], scopes: Sequence[ScopeEntry]
) -> dict[int, list[str]]:
    addresses: dict[int, set[str]] = {4: set(), 6: set()}
    for candidate in candidates:
        for raw_address in candidate.addresses:
            try:
                address = ipaddress.ip_address(raw_address)
            except ValueError:
                continue
            matching = [scope for scope in scopes if scope.contains(address)]
            if len(matching) == 1:
                addresses[address.version].add(str(address))
    return {
        version: sorted(items, key=ipaddress.ip_address)
        for version, items in addresses.items()
        if items
    }


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
        workspace.require_active(engagement)
        if not contained_regular_file(engagement_root, job_file):
            raise SafetyError(
                f"discovery job definition is linked or unsafe: {job_file}"
            )
        for destination in (status_path, job_root / "nmap.log"):
            require_contained_parent(engagement_root, destination)
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
        try:
            selected = _validated_scan_scopes(engagement, scope_ids)
        except ConflictError as exc:
            raise ValidationError(str(exc)) from exc
        profile = _scan_profile(value.get("profile"))
        pace = _scan_pace(value.get("pace"))
        nmap = shutil.which("nmap")
        if not nmap:
            raise ExternalToolError("Nmap is not installed")
        log_path = job_root / "nmap.log"
        value.update(
            {
                "id": job_id,
                "engagement_id": engagement.id,
                "scope_ids": scope_ids,
                "profile": profile.value,
                "pace": pace.value,
                "phase": "starting",
                "session": TmuxService(settings).job_session_name(engagement, job_id),
                "result_paths": [],
                "artifacts": [],
                "state": "running",
                "started_at": _utc_now(),
                "finished_at": None,
                "exit_code": None,
            }
        )
        value.pop("error", None)
    except (ConflictError, ExternalToolError, SafetyError, ValidationError) as exc:
        failure = {
            "schema": JOB_SCHEMA,
            "id": job_id,
            "engagement_id": value.get("engagement_id", ""),
            "scope_ids": value.get("scope_ids", [])
            if isinstance(value.get("scope_ids", []), list)
            else [],
            "profile": value.get("profile", ScanProfile.HOSTS.value),
            "pace": value.get("pace", ScanPace.CAREFUL.value),
            "phase": "validation",
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
                _write_job_status(status_path, failure)
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
        _write_job_status(status_path, value)

    def publish(phase: str) -> None:
        value["phase"] = phase
        with workspace.lock(engagement_root):
            current = _current_job_status(
                settings, workspace, engagement_root, job_id
            )
            if current is not None and current.get("state") == "cancelled":
                raise _JobCancelled
            _write_job_status(status_path, value)

    failures: list[str] = []
    failure_code = 0

    def execute(
        phase: str, argv: list[str], artifact: str, log: BinaryIO
    ) -> bool:
        nonlocal failure_code
        if artifact not in value["artifacts"]:
            value["artifacts"].append(artifact)
        publish(phase)
        log.write(f"\n=== {phase} ===\n$ {' '.join(argv)}\n".encode())
        log.flush()
        try:
            result = subprocess.run(
                argv, stdout=log, stderr=subprocess.STDOUT, check=False
            )
        except OSError as exc:
            failure_code = 127
            failures.append(f"{phase}: {exc}")
            return False
        if result.returncode:
            failure_code = result.returncode
            failures.append(f"{phase}: Nmap exited with {result.returncode}")
            return False
        return True

    try:
        descriptor = os.open(log_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "wb") as log:
            if profile == ScanProfile.HOSTS:
                families = _scope_families(selected)
                for version, scopes in families.items():
                    name = (
                        "results.xml"
                        if len(families) == 1
                        else f"results-{'ipv6' if version == 6 else 'ipv4'}.xml"
                    )
                    xml_path = job_root / name
                    phase = (
                        "host-discovery"
                        if len(families) == 1
                        else f"host-discovery-{'ipv6' if version == 6 else 'ipv4'}"
                    )
                    argv = _scan_argv(
                        nmap, xml_path, scopes, ipv6=version == 6
                    )
                    if execute(phase, argv, name, log):
                        value["result_paths"].append(name)
            else:
                host_candidates: list[DiscoveryCandidate] = []
                for version, scopes in _scope_families(selected).items():
                    suffix = "ipv6" if version == 6 else "ipv4"
                    xml_path = job_root / f"host-discovery-{suffix}.xml"
                    argv = _scan_argv(
                        nmap, xml_path, scopes, ipv6=version == 6
                    )
                    if not execute(
                        f"host-discovery-{suffix}", argv, xml_path.name, log
                    ):
                        continue
                    try:
                        parsed = parse_nmap_xml(
                            xml_path,
                            source=xml_path.relative_to(engagement_root).as_posix(),
                        )
                    except ValidationError as exc:
                        failure_code = failure_code or 1
                        failures.append(f"host-discovery-{suffix}: {exc}")
                        continue
                    host_candidates.extend(parsed)
                    value["result_paths"].append(xml_path.name)

                live_by_family = _validated_stage_addresses(
                    host_candidates, selected
                )
                port_candidates: list[DiscoveryCandidate] = []
                for version, addresses in live_by_family.items():
                    suffix = "ipv6" if version == 6 else "ipv4"
                    xml_path = job_root / f"tcp-ports-{suffix}.xml"
                    argv = _port_scan_argv(
                        nmap,
                        xml_path,
                        addresses,
                        pace,
                        ipv6=version == 6,
                    )
                    if not execute(f"tcp-ports-{suffix}", argv, xml_path.name, log):
                        continue
                    try:
                        parsed = parse_nmap_xml(
                            xml_path,
                            source=xml_path.relative_to(engagement_root).as_posix(),
                        )
                    except ValidationError as exc:
                        failure_code = failure_code or 1
                        failures.append(f"tcp-ports-{suffix}: {exc}")
                        continue
                    port_candidates.extend(parsed)
                    value["result_paths"].append(xml_path.name)

                live = {
                    address
                    for addresses in live_by_family.values()
                    for address in addresses
                }
                ports_by_host: dict[str, set[int]] = {item: set() for item in live}
                for candidate in port_candidates:
                    ports = {
                        service.port
                        for service in candidate.services
                        if service.protocol == "tcp" and service.state == "open"
                    }
                    for address in candidate.addresses:
                        if address in ports_by_host:
                            ports_by_host[address].update(ports)

                grouped: dict[tuple[int, tuple[int, ...]], list[str]] = {}
                for address, ports in ports_by_host.items():
                    if not ports:
                        continue
                    version = ipaddress.ip_address(address).version
                    grouped.setdefault((version, tuple(sorted(ports))), []).append(address)
                counters = {4: 0, 6: 0}
                for (version, ports), addresses in sorted(grouped.items()):
                    counters[version] += 1
                    suffix = "ipv6" if version == 6 else "ipv4"
                    name = f"service-detection-{suffix}-{counters[version]:03d}.xml"
                    xml_path = job_root / name
                    argv = _service_scan_argv(
                        nmap,
                        xml_path,
                        sorted(addresses, key=ipaddress.ip_address),
                        ports,
                        pace,
                        ipv6=version == 6,
                    )
                    if not execute(
                        f"service-detection-{suffix}-{counters[version]:03d}",
                        argv,
                        name,
                        log,
                    ):
                        continue
                    try:
                        parse_nmap_xml(xml_path)
                    except ValidationError as exc:
                        failure_code = failure_code or 1
                        failures.append(f"{name}: {exc}")
                        continue
                    value["result_paths"].append(name)
    except _JobCancelled:
        return 130
    except (OSError, ValidationError) as exc:
        failure_code = failure_code or 127
        failures.append(str(exc))

    if failures:
        value["error"] = "; ".join(failures)
    else:
        value.pop("error", None)
    value["exit_code"] = failure_code
    value["state"] = (
        "succeeded"
        if not failures
        else "partial"
        if value.get("result_paths")
        else "failed"
    )
    value["phase"] = "complete"
    value["finished_at"] = _utc_now()
    with workspace.lock(engagement_root):
        current = _current_job_status(
            settings, workspace, engagement_root, job_id
        )
        if current is not None and current.get("state") == "cancelled":
            return 130
        _write_job_status(status_path, value)
    return int(value["exit_code"] or 0)
