"""Deterministic terminal and Markdown situation rendering."""

from __future__ import annotations

from typing import Iterable, Mapping

from .errors import ValidationError
from .model import (
    AccessLevel,
    AttackPathStep,
    Engagement,
    FindingState,
    ScopeGroup,
    ScopeKind,
    Target,
)


ACCESS_LABELS = {
    AccessLevel.AUTHENTICATED: "Authenticated",
    AccessLevel.USER_EXECUTION: "User Execution",
    AccessLevel.ADMINISTRATIVE_EXECUTION: "Administrative Execution",
    AccessLevel.PRIVILEGED_EXECUTION: "Privileged Execution",
}


def md_escape(value: object) -> str:
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def mermaid_label(value: object) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace('"', "&quot;")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def md_link_text(value: object) -> str:
    return md_escape(value).replace("]", "\\]")


def target_label(engagement: Engagement, target: Target) -> str:
    level = engagement.strongest_access(target.id)
    suffix = f" — {ACCESS_LABELS[level]}" if level else ""
    return f"{target.display_name} [{target.id}]{suffix}"


def topology_text(engagement: Engagement, *, ascii_only: bool = False) -> str:
    branch = "+-" if ascii_only else "├─"
    last_branch = "`-" if ascii_only else "└─"
    continuation = "| " if ascii_only else "│ "
    lines: list[str] = []
    for group in (ScopeGroup.EXTERNAL, ScopeGroup.INTERNAL):
        scopes = [item for item in engagement.scope if item.group == group]
        lines.append(group.value.upper())
        if not scopes:
            lines.append(f"{last_branch} No declared scope")
            continue
        for scope_index, scope in enumerate(scopes):
            scope_branch = last_branch if scope_index == len(scopes) - 1 else branch
            availability = (
                "" if scope.availability.value == "ready" else " [unavailable]"
            )
            via = ""
            exclusions = (
                f" [excluding {', '.join(scope.exclusions)}]"
                if scope.exclusions
                else ""
            )
            if scope.via_target_id:
                try:
                    via_target = engagement.target_by_id(scope.via_target_id)
                    via = f" via {via_target.display_name}"
                except ValidationError:
                    via = f" via {scope.via_target_id}"
            lines.append(
                f"{scope_branch} {scope.label}: {scope.spec}{exclusions}{availability}{via}"
            )
            members: list[tuple[Target, list[str]]] = []
            for target in engagement.targets:
                if scope.kind == ScopeKind.NETWORK:
                    identities = [
                        item.value
                        for item in target.addresses
                        if item.scope_id == scope.id
                    ]
                else:
                    identities = [
                        item for item in target.hostnames if scope.matches_hostname(item)
                    ]
                if identities:
                    members.append((target, identities))
            prefix = "  " if scope_index == len(scopes) - 1 else continuation
            if not members:
                lines.append(f"{prefix}{last_branch} No identified hosts")
            for target_index, (target, addresses) in enumerate(members):
                target_branch = (
                    last_branch if target_index == len(members) - 1 else branch
                )
                lines.append(
                    f"{prefix}{target_branch} {target_label(engagement, target)} "
                    f"({', '.join(addresses)})"
                )
    unassigned = [
        target
        for target in engagement.targets
        if not target.addresses
        and not any(engagement.hostname_scope(item) for item in target.hostnames)
    ]
    if unassigned:
        lines.append("UNASSIGNED")
        for target_index, target in enumerate(unassigned):
            target_branch = (
                last_branch if target_index == len(unassigned) - 1 else branch
            )
            identity = target.identity_state.replace("-", " ")
            lines.append(
                f"{target_branch} {target_label(engagement, target)} ({identity})"
            )
    return "\n".join(lines).rstrip() + "\n"


def _reference_label(engagement: Engagement, step: AttackPathStep) -> str:
    if step.ref_type == "access":
        for record in engagement.access:
            if record.id == step.ref_id:
                target = engagement.target_by_id(record.target_id)
                authority = f"{record.authority}\\" if record.authority else ""
                method = f" via {record.method}" if record.method else ""
                return (
                    f"{authority}{record.principal} → {target.display_name}: "
                    f"{ACCESS_LABELS[record.level]}{method}"
                )
    elif step.ref_type == "activity":
        for activity in engagement.activities:
            if activity.id == step.ref_id:
                return activity.summary
    elif step.ref_type == "finding":
        for finding in engagement.findings:
            if finding.id == step.ref_id:
                return f"Finding: {finding.title}"
    return f"{step.ref_type}:{step.ref_id}"


def attack_paths_text(engagement: Engagement) -> str:
    if not engagement.attack_paths:
        return "No confirmed attack paths.\n"
    lines: list[str] = []
    for path in engagement.attack_paths:
        lines.append(f"{path.name} [{path.id}]")
        for index, step in enumerate(path.steps, 1):
            narrative = f" — {step.narrative}" if step.narrative else ""
            lines.append(f"  {index}. {_reference_label(engagement, step)}{narrative}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def mermaid_topology(engagement: Engagement) -> str:
    lines = ["flowchart LR"]
    for group in (ScopeGroup.EXTERNAL, ScopeGroup.INTERNAL):
        lines.append(f"  subgraph group_{group.value}[{group.value.title()}]")
        for scope in engagement.scope:
            if scope.group != group:
                continue
            label = f"{mermaid_label(scope.label)}\\n{mermaid_label(scope.spec)}"
            if scope.exclusions:
                label += f"\\nexcept {mermaid_label(', '.join(scope.exclusions))}"
            lines.append(f'    scope_{scope.id}["{label}"]')
        lines.append("  end")
    unassigned = [
        target
        for target in engagement.targets
        if not target.addresses
        and not any(engagement.hostname_scope(item) for item in target.hostnames)
    ]
    if unassigned:
        lines.extend(
            [
                "  subgraph group_unassigned[No scope-qualified address]",
                '    unassigned_anchor["Unassigned"]',
                "  end",
            ]
        )
    for target in engagement.targets:
        label = mermaid_label(target.display_name)
        level = engagement.strongest_access(target.id)
        if level:
            label += f"\\n{ACCESS_LABELS[level]}"
        lines.append(f'  target_{target.id}["{label}"]')
        lines.extend(
            f"  scope_{address.scope_id} --- target_{target.id}"
            for address in target.addresses
        )
        for scope in engagement.domain_entries:
            if any(scope.matches_hostname(item) for item in target.hostnames):
                lines.append(f"  scope_{scope.id} --- target_{target.id}")
        if target in unassigned:
            lines.append(f"  unassigned_anchor -.- target_{target.id}")
    lines.extend(
        f"  target_{scope.via_target_id} -->|pivot| scope_{scope.id}"
        for scope in engagement.scope
        if scope.via_target_id
    )
    return "\n".join(lines) + "\n"


def render_activity_markdown(engagement: Engagement) -> str:
    lines = [
        "# Activity Log",
        "",
        "> Generated by TACMUX from recorded activity. Edit records through TACMUX.",
        "",
        "| UTC | Result | Target | Activity | Evidence |",
        "|---|---|---|---|---|",
    ]
    for activity in sorted(engagement.activities, key=lambda item: item.occurred_at):
        target = ""
        if activity.target_id:
            target = engagement.target_by_id(activity.target_id).display_name
        evidence = f"`{activity.evidence}`" if activity.evidence else ""
        lines.append(
            f"| {md_escape(activity.occurred_at)} | {md_escape(activity.result.value)} | "
            f"{md_escape(target)} | {md_escape(activity.summary)} | {evidence} |"
        )
    return "\n".join(lines) + "\n"


def render_attack_path_markdown(engagement: Engagement) -> str:
    lines = [
        "# Attack Paths",
        "",
        "> Generated by TACMUX. Only confirmed activities, findings, and access records are eligible.",
        "",
    ]
    if not engagement.attack_paths:
        lines.append("No confirmed attack paths have been recorded.")
    for path in engagement.attack_paths:
        lines.extend(
            [
                f"## {path.name} `{path.id}`",
                "",
                f"Created UTC: {md_escape(path.created_at) or '—'}",
                "",
            ]
        )
        for index, step in enumerate(path.steps, 1):
            label = _reference_label(engagement, step)
            narrative = f" — {step.narrative}" if step.narrative else ""
            lines.append(f"{index}. **{md_escape(label)}**{md_escape(narrative)}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_sitrep(
    engagement: Engagement,
    *,
    live_sessions: Iterable[str] = (),
    jobs: Iterable[Mapping[str, object]] = (),
    include_mermaid: bool = True,
    warnings: Iterable[str] = (),
) -> str:
    live = set(live_sessions)
    job_list = list(jobs)
    lines = [
        f"# SITREP — {engagement.client}: {engagement.name}",
        "",
        "> Generated by TACMUX. Do not edit this file directly.",
        "",
        f"- **Assessment:** {engagement.assessment_type.value}",
        f"- **Status:** {engagement.status.value}",
        f"- **Targets:** {len(engagement.targets)}",
        f"- **Open findings:** {sum(item.state != FindingState.CLOSED for item in engagement.findings)}",
        f"- **Observed services:** {sum(len(item.services) for item in engagement.targets)}",
        f"- **Outstanding cleanup:** {len(engagement.outstanding_cleanup)}",
        f"- **Live target sessions:** {len(live)}",
        f"- **Discovery jobs:** {len(job_list)}",
        "",
        "## Authorization",
        "",
        f"- **Authorized by:** {md_escape(engagement.authorization.authorized_by) or '—'}",
        f"- **Reference:** {md_escape(engagement.authorization.reference) or '—'}",
        f"- **Window start:** {md_escape(engagement.authorization.window_start) or '—'}",
        f"- **Window end:** {md_escape(engagement.authorization.window_end) or '—'}",
        f"- **Emergency contact:** {md_escape(engagement.authorization.emergency_contact) or '—'}",
        "",
        "## Scope",
        "",
        "| Group | Kind | Label | Scope | Exclusions | Availability | Access path |",
        "|---|---|---|---|---|---|---|",
    ]
    for scope in engagement.scope:
        via = ""
        if scope.via_target_id:
            via = engagement.target_by_id(scope.via_target_id).display_name
        lines.append(
            f"| {scope.group.value} | {scope.kind.value} | {md_escape(scope.label)} | "
            f"`{md_escape(scope.spec)}` | {md_escape(', '.join(scope.exclusions)) or '—'} | "
            f"{scope.availability.value} | {md_escape(via)} |"
        )
    lines.extend(
        [
            "",
            "## Targets and Confirmed Access",
            "",
            "| ID | Target | Identity | Addresses | Strongest confirmed access | Session |",
            "|---|---|---|---|---|---|",
        ]
    )
    for target in engagement.targets:
        level = engagement.strongest_access(target.id)
        access = ACCESS_LABELS[level] if level else "—"
        addresses = ", ".join(item.value for item in target.addresses) or "—"
        session = "running" if target.id in live else "stopped"
        lines.append(
            f"| `{target.id}` | {md_escape(target.display_name)} | "
            f"{target.identity_state.replace('-', ' ')} | {md_escape(addresses)} | "
            f"{access} | {session} |"
        )
    lines.extend(
        [
            "",
            "## Services",
            "",
            "| Target | Port | Proto | State | Service | Product / version | Source |",
            "|---|---:|---|---|---|---|---|",
        ]
    )
    for target in engagement.targets:
        for service in target.services:
            details = " ".join(
                value
                for value in (service.product, service.version, service.extra)
                if value
            )
            lines.append(
                f"| {md_escape(target.display_name)} | {service.port} | "
                f"{md_escape(service.protocol)} | {md_escape(service.state)} | "
                f"{md_escape(service.name)} | "
                f"{md_escape(details)} | {md_escape(service.source)} |"
            )
    lines.extend(
        [
            "",
            "## Network Topology",
            "",
            "```text",
            topology_text(engagement).rstrip(),
            "```",
        ]
    )
    if include_mermaid:
        lines.extend(
            [
                "",
                "### Mermaid Source",
                "",
                "```mermaid",
                mermaid_topology(engagement).rstrip(),
                "```",
            ]
        )
    lines.extend(
        [
            "",
            "## Confirmed Attack Paths",
            "",
            "```text",
            attack_paths_text(engagement).rstrip(),
            "```",
        ]
    )
    lines.extend(
        [
            "",
            "## Findings",
            "",
            "| ID | Created | Severity | State | Finding | Targets |",
            "|---|---|---|---|---|---|",
        ]
    )
    for finding in engagement.findings:
        targets = ", ".join(
            engagement.target_by_id(item).display_name for item in finding.target_ids
        )
        lines.append(
            f"| `{finding.id}` | {md_escape(finding.created_at) or '—'} | "
            f"{finding.severity.value} | {finding.state.value} | "
            f"[{md_link_text(finding.title)}]({finding.document}) | "
            f"{md_escape(targets)} |"
        )
    lines.extend(
        [
            "",
            "## Recent Activity",
            "",
            "| UTC | Result | Activity | Evidence |",
            "|---|---|---|---|",
        ]
    )
    for activity in sorted(engagement.activities, key=lambda item: item.occurred_at)[
        -20:
    ]:
        evidence = f"`{activity.evidence}`" if activity.evidence else ""
        lines.append(
            f"| {activity.occurred_at} | {activity.result.value} | "
            f"{md_escape(activity.summary)} | {evidence} |"
        )
    lines.extend(
        [
            "",
            "## Cleanup",
            "",
            "| ID | Target | Kind | Location | Created | Removed |",
            "|---|---|---|---|---|---|",
        ]
    )
    for item in engagement.cleanup:
        target = engagement.target_by_id(item.target_id)
        lines.append(
            f"| `{item.id}` | {md_escape(target.display_name)} | {item.kind.value} | "
            f"{md_escape(item.location)} | {md_escape(item.created_at)} | "
            f"{md_escape(item.removed_at) or '—'} |"
        )
    warning_list = list(warnings)
    hostname_only = [
        target
        for target in engagement.targets
        if not target.addresses
        and target.hostnames
        and not any(engagement.hostname_scope(item) for item in target.hostnames)
    ]
    if hostname_only:
        warning_list.append(
            f"{len(hostname_only)} hostname-only target(s) have no declared domain scope"
        )
    if warning_list:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {md_escape(item)}" for item in warning_list)
    return "\n".join(lines).rstrip() + "\n"
