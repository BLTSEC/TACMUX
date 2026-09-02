"""Foreground host identification and explicit editor review."""

from __future__ import annotations

import ipaddress
from pathlib import Path
import shutil
import subprocess
from typing import Sequence

from .config import Settings
from .errors import ExternalToolError, ValidationError
from .interaction import confirm, edit_text
from .workspace import Workspace, validate_name


def run_host_discovery(network: str) -> str:
    try:
        if "/" in network:
            destination = str(ipaddress.ip_network(network, strict=False))
        else:
            destination = str(ipaddress.ip_address(network))
    except ValueError as exc:
        raise ValidationError("discovery destination must be an IP or CIDR") from exc
    binary = shutil.which("nmap")
    if binary is None:
        raise ExternalToolError("nmap is not installed")
    if not confirm(f"Run authorized host discovery against {destination}?"):
        raise ValidationError("discovery cancelled")
    result = subprocess.run(
        [
            binary,
            *(
                ["-6"]
                if ipaddress.ip_network(destination, strict=False).version == 6
                else []
            ),
            "-sn",
            "--reason",
            "-oG",
            "-",
            destination,
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise ExternalToolError((result.stderr or "nmap failed").strip())
    return result.stdout


def review_candidates(
    settings: Settings, candidates: Sequence[tuple[str, str]]
) -> list[tuple[str, str]]:
    unique: dict[str, tuple[str, str]] = {}
    for name, endpoint in candidates:
        unique[endpoint] = (name, endpoint)
    if not unique:
        raise ValidationError("no hosts were identified")
    lines = [
        "# Delete unwanted hosts, rename targets in column one, then save.",
        "# Format: TARGET_NAME<TAB>ENDPOINT",
        *(f"{name}\t{endpoint}" for name, endpoint in unique.values()),
        "",
    ]
    reviewed = edit_text(settings, "\n".join(lines), suffix=".targets")
    result: list[tuple[str, str]] = []
    names: set[str] = set()
    endpoints: set[str] = set()
    for number, line in enumerate(reviewed.splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        name, separator, endpoint = line.partition("\t")
        if not separator:
            raise ValidationError(f"candidate line {number} must contain a tab")
        name = validate_name(name, "target name")
        if name.casefold() in {"engagement", "ops"}:
            raise ValidationError(f"candidate line {number} uses reserved name: {name}")
        endpoint = endpoint.strip()
        try:
            endpoint = str(ipaddress.ip_address(endpoint))
        except ValueError as exc:
            raise ValidationError(
                f"candidate line {number} has an invalid IP: {endpoint}"
            ) from exc
        if name.casefold() in names:
            raise ValidationError(f"duplicate candidate target name: {name}")
        if endpoint in endpoints:
            raise ValidationError(f"duplicate candidate endpoint: {endpoint}")
        names.add(name.casefold())
        endpoints.add(endpoint)
        result.append((name, endpoint))
    if not result:
        raise ValidationError("candidate review accepted no hosts")
    return result


def create_reviewed_targets(
    workspace: Workspace, root: Path, candidates: Sequence[tuple[str, str]]
) -> tuple[list[str], list[str]]:
    existing_endpoints = {
        workspace.target_details(root, target)["Endpoint"][0]: target
        for target in workspace.targets(root)
    }
    created: list[str] = []
    skipped: list[str] = []
    for name, endpoint in candidates:
        if endpoint in existing_endpoints or workspace.target_exists(root, name):
            skipped.append(f"{name} ({endpoint})")
            continue
        workspace.add_target(root, name, endpoint)
        created.append(name)
    return created, skipped
