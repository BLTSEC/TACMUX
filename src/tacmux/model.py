"""Versioned, dependency-free engagement domain model."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
import ipaddress
from pathlib import PurePosixPath
import re
from typing import Any
from uuid import uuid4

from .errors import ConflictError, ValidationError


SCHEMA = "tacmux.engagement/v2"
_MISSING = object()
_CREDENTIAL_SHAPES = (
    re.compile(
        r"(?i)(?<![0-9a-f])[0-9a-f]{32}:[0-9a-f]{32}(?![0-9a-f])"
    ),
    re.compile(r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----"),
    re.compile(
        r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])"
    ),
    re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{40,}(?![0-9a-f])"),
)


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError(f"{label} must be an object")
    return value


def _text(value: dict[str, Any], key: str, *, default: object = _MISSING) -> str:
    item = value.get(key, default)
    if item is _MISSING:
        raise ValidationError(f"manifest field {key} is required")
    if not isinstance(item, str):
        raise ValidationError(f"manifest field {key} must be a string")
    return item


def _objects(value: dict[str, Any], key: str) -> list[dict[str, Any]]:
    items = value.get(key, [])
    if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
        raise ValidationError(f"manifest field {key} must be a list of objects")
    return items


def _strings(value: dict[str, Any], key: str) -> list[str]:
    items = value.get(key, [])
    if not isinstance(items, list) or any(not isinstance(item, str) for item in items):
        raise ValidationError(f"manifest field {key} must be a list of strings")
    return items


def utc_now() -> str:
    return (
        datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    )


def looks_like_credential(value: str) -> bool:
    """Flag high-confidence credential shapes without rejecting operator data."""

    return any(pattern.search(value.strip()) for pattern in _CREDENTIAL_SHAPES)


class AssessmentType(StrEnum):
    EXTERNAL = "external"
    INTERNAL = "internal"
    BOTH = "both"
    SINGLE_MACHINE = "single_machine"


class ScopeGroup(StrEnum):
    EXTERNAL = "external"
    INTERNAL = "internal"


class ScopeAvailability(StrEnum):
    READY = "ready"
    UNAVAILABLE = "unavailable"


class ScopeKind(StrEnum):
    NETWORK = "network"
    DOMAIN = "domain"


class EngagementStatus(StrEnum):
    ACTIVE = "active"
    CLOSED = "closed"


class ActivityResult(StrEnum):
    CONFIRMED = "confirmed"
    FAILED = "failed"
    NO_RESULT = "no_result"


class AccessLevel(StrEnum):
    AUTHENTICATED = "authenticated"
    USER_EXECUTION = "user_execution"
    ADMINISTRATIVE_EXECUTION = "administrative_execution"
    PRIVILEGED_EXECUTION = "privileged_execution"


ACCESS_RANK = {
    AccessLevel.AUTHENTICATED: 1,
    AccessLevel.USER_EXECUTION: 2,
    AccessLevel.ADMINISTRATIVE_EXECUTION: 3,
    AccessLevel.PRIVILEGED_EXECUTION: 4,
}


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingState(StrEnum):
    DRAFT = "draft"
    CONFIRMED = "confirmed"
    CLOSED = "closed"


class CleanupKind(StrEnum):
    FILE = "file"
    ACCOUNT = "account"
    SERVICE = "service"
    SCHEDULED_TASK = "scheduled_task"
    CONFIG_CHANGE = "config_change"
    OTHER = "other"


HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*"
    r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$",
    re.IGNORECASE,
)
DOMAIN_PATTERN_RE = re.compile(
    r"^(?:\*\.)?(?=.{3,255}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+"
    r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$",
    re.IGNORECASE,
)


def normalize_hostname(value: str) -> str:
    normalized = value.strip().casefold().rstrip(".")
    if not normalized or not HOSTNAME_RE.fullmatch(normalized):
        raise ValidationError(f"invalid hostname: {value}")
    return normalized


def normalize_domain_pattern(value: str) -> str:
    normalized = value.strip().casefold().rstrip(".")
    if not DOMAIN_PATTERN_RE.fullmatch(normalized):
        raise ValidationError(f"invalid domain pattern: {value}")
    return normalized


def hostname_matches(pattern: str, hostname: str) -> bool:
    pattern = normalize_domain_pattern(pattern)
    hostname = normalize_hostname(hostname)
    if pattern.startswith("*."):
        return hostname.endswith("." + pattern[2:])
    return hostname == pattern


def pattern_inside(inner: str, outer: str) -> bool:
    inner = normalize_domain_pattern(inner)
    outer = normalize_domain_pattern(outer)
    if inner == outer:
        return True
    if not inner.startswith("*."):
        return hostname_matches(outer, inner)
    inner_suffix = inner[2:]
    if outer.startswith("*."):
        outer_suffix = outer[2:]
        return inner_suffix == outer_suffix or inner_suffix.endswith("." + outer_suffix)
    return False


def classify_scope(
    value: str, exclusions: list[str] | tuple[str, ...] = ()
) -> tuple[ScopeKind, str, str, list[str]]:
    try:
        parsed_network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        try:
            domain = normalize_domain_pattern(value)
        except ValidationError as exc:
            raise ValidationError(
                f"invalid IP, CIDR, or domain pattern: {value}"
            ) from exc
        return (
            ScopeKind.DOMAIN,
            "",
            domain,
            sorted(
                {normalize_domain_pattern(item) for item in exclusions if item.strip()}
            ),
        )
    normalized_exclusions: set[str] = set()
    for item in exclusions:
        if not item.strip():
            continue
        try:
            normalized_exclusions.add(
                str(ipaddress.ip_network(item.strip(), strict=False))
            )
        except ValueError as exc:
            raise ValidationError(f"invalid scope exclusion: {item}") from exc
    return ScopeKind.NETWORK, str(parsed_network), "", sorted(normalized_exclusions)


@dataclass(slots=True)
class ScopeEntry:
    id: str
    label: str
    group: ScopeGroup
    network: str
    availability: ScopeAvailability = ScopeAvailability.READY
    via_target_id: str = ""
    kind: ScopeKind = ScopeKind.NETWORK
    domain: str = ""
    exclusions: list[str] = field(default_factory=list)

    @property
    def spec(self) -> str:
        return self.network if self.kind == ScopeKind.NETWORK else self.domain

    def contains(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        if self.kind != ScopeKind.NETWORK:
            return False
        network = ipaddress.ip_network(self.network)
        if address.version != network.version:
            return False
        return address in network and not any(
            address in ipaddress.ip_network(exclusion) for exclusion in self.exclusions
        )

    def matches_hostname(self, hostname: str) -> bool:
        if self.kind != ScopeKind.DOMAIN or not hostname_matches(self.domain, hostname):
            return False
        return not any(hostname_matches(exclusion, hostname) for exclusion in self.exclusions)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ScopeEntry":
        value = _object(value, "scope entry")
        return cls(
            id=_text(value, "id"),
            label=_text(value, "label"),
            group=ScopeGroup(_text(value, "group")),
            network=_text(value, "network"),
            availability=ScopeAvailability(
                _text(value, "availability", default="ready")
            ),
            via_target_id=_text(value, "via_target_id", default=""),
            kind=ScopeKind(_text(value, "kind", default="network")),
            domain=_text(value, "domain", default=""),
            exclusions=_strings(value, "exclusions"),
        )


@dataclass(slots=True)
class TargetAddress:
    value: str
    scope_id: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "TargetAddress":
        value = _object(value, "target address")
        return cls(value=_text(value, "value"), scope_id=_text(value, "scope_id"))


@dataclass(slots=True)
class Service:
    port: int
    protocol: str
    name: str = ""
    product: str = ""
    version: str = ""
    extra: str = ""
    tunnel: str = ""
    state: str = "open"
    observed_at: str = field(default_factory=utc_now)
    source: str = ""

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Service":
        value = _object(value, "service")
        port = value.get("port")
        if isinstance(port, bool) or not isinstance(port, int):
            raise ValidationError("service port must be an integer")
        return cls(
            port=port,
            protocol=_text(value, "protocol"),
            name=_text(value, "name", default=""),
            product=_text(value, "product", default=""),
            version=_text(value, "version", default=""),
            extra=_text(value, "extra", default=""),
            tunnel=_text(value, "tunnel", default=""),
            state=_text(value, "state", default="open"),
            observed_at=_text(value, "observed_at", default=utc_now()),
            source=_text(value, "source", default=""),
        )


def merge_services(existing: list[Service], incoming: list[Service]) -> list[Service]:
    merged = {(item.port, item.protocol): item for item in existing}
    for item in incoming:
        key = (item.port, item.protocol)
        previous = merged.get(key)
        if previous is None:
            merged[key] = item
            continue
        merged[key] = Service(
            port=item.port,
            protocol=item.protocol,
            name=item.name or previous.name,
            product=item.product or previous.product,
            version=item.version or previous.version,
            extra=item.extra or previous.extra,
            tunnel=item.tunnel or previous.tunnel,
            state=item.state or previous.state,
            observed_at=item.observed_at or previous.observed_at,
            source=item.source or previous.source,
        )
    return sorted(merged.values(), key=lambda item: (item.protocol, item.port))


@dataclass(slots=True)
class Target:
    id: str
    display_name: str
    directory: str
    addresses: list[TargetAddress] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    primary_endpoint: str = ""
    created_at: str = field(default_factory=utc_now)
    services: list[Service] = field(default_factory=list)

    @property
    def identity_state(self) -> str:
        if self.addresses:
            return "scope-qualified"
        if self.hostnames:
            return "hostname-only"
        return "unresolved"

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Target":
        value = _object(value, "target")
        return cls(
            id=_text(value, "id"),
            display_name=_text(value, "display_name"),
            directory=_text(value, "directory"),
            addresses=[
                TargetAddress.from_dict(item) for item in _objects(value, "addresses")
            ],
            hostnames=_strings(value, "hostnames"),
            primary_endpoint=_text(value, "primary_endpoint", default=""),
            created_at=_text(value, "created_at", default=utc_now()),
            services=[Service.from_dict(item) for item in _objects(value, "services")],
        )


@dataclass(slots=True)
class AccessRecord:
    id: str
    principal: str
    authority: str
    target_id: str
    method: str
    level: AccessLevel
    observed_at: str = field(default_factory=utc_now)
    evidence: str = ""

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "AccessRecord":
        value = _object(value, "access record")
        return cls(
            id=_text(value, "id"),
            principal=_text(value, "principal"),
            authority=_text(value, "authority", default=""),
            target_id=_text(value, "target_id"),
            method=_text(value, "method", default=""),
            level=AccessLevel(_text(value, "level")),
            observed_at=_text(value, "observed_at", default=utc_now()),
            evidence=_text(value, "evidence", default=""),
        )


@dataclass(slots=True)
class Activity:
    id: str
    summary: str
    result: ActivityResult
    target_id: str = ""
    occurred_at: str = field(default_factory=utc_now)
    evidence: str = ""

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Activity":
        value = _object(value, "activity")
        return cls(
            id=_text(value, "id"),
            summary=_text(value, "summary"),
            result=ActivityResult(_text(value, "result")),
            target_id=_text(value, "target_id", default=""),
            occurred_at=_text(value, "occurred_at", default=utc_now()),
            evidence=_text(value, "evidence", default=""),
        )


@dataclass(slots=True)
class Finding:
    id: str
    title: str
    severity: Severity
    state: FindingState
    target_ids: list[str]
    evidence: list[str]
    document: str
    created_at: str = field(default_factory=utc_now)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Finding":
        value = _object(value, "finding")
        return cls(
            id=_text(value, "id"),
            title=_text(value, "title"),
            severity=Severity(_text(value, "severity")),
            state=FindingState(_text(value, "state")),
            target_ids=_strings(value, "target_ids"),
            evidence=_strings(value, "evidence"),
            document=_text(value, "document"),
            created_at=_text(value, "created_at", default=""),
        )


@dataclass(slots=True)
class AttackPathStep:
    ref_type: str
    ref_id: str
    narrative: str = ""

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "AttackPathStep":
        value = _object(value, "attack path step")
        return cls(
            ref_type=_text(value, "ref_type"),
            ref_id=_text(value, "ref_id"),
            narrative=_text(value, "narrative", default=""),
        )


@dataclass(slots=True)
class AttackPath:
    id: str
    name: str
    steps: list[AttackPathStep]
    created_at: str = field(default_factory=utc_now)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "AttackPath":
        value = _object(value, "attack path")
        return cls(
            id=_text(value, "id"),
            name=_text(value, "name"),
            steps=[AttackPathStep.from_dict(item) for item in _objects(value, "steps")],
            created_at=_text(value, "created_at", default=""),
        )


def parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"invalid UTC timestamp: {value}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValidationError(f"UTC timestamp must include a timezone: {value}")
    return parsed.astimezone(timezone.utc)


@dataclass(slots=True)
class Authorization:
    authorized_by: str = ""
    reference: str = ""
    window_start: str = ""
    window_end: str = ""
    emergency_contact: str = ""

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Authorization":
        value = _object(value, "authorization")
        return cls(
            authorized_by=_text(value, "authorized_by", default=""),
            reference=_text(value, "reference", default=""),
            window_start=_text(value, "window_start", default=""),
            window_end=_text(value, "window_end", default=""),
            emergency_contact=_text(value, "emergency_contact", default=""),
        )

    def window_state(self, now: datetime | None = None) -> str:
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        start = parse_utc(self.window_start) if self.window_start else None
        end = parse_utc(self.window_end) if self.window_end else None
        if start is None and end is None:
            return "none"
        if start is not None and now < start:
            return "outside"
        if end is not None and now > end:
            return "outside"
        return "inside"


@dataclass(slots=True)
class CleanupItem:
    id: str
    target_id: str
    kind: CleanupKind
    location: str
    sha256: str = ""
    note: str = ""
    created_at: str = field(default_factory=utc_now)
    removed_at: str = ""

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "CleanupItem":
        value = _object(value, "cleanup item")
        return cls(
            id=_text(value, "id"),
            target_id=_text(value, "target_id"),
            kind=CleanupKind(_text(value, "kind")),
            location=_text(value, "location"),
            sha256=_text(value, "sha256", default=""),
            note=_text(value, "note", default=""),
            created_at=_text(value, "created_at", default=utc_now()),
            removed_at=_text(value, "removed_at", default=""),
        )


def _safe_reference(value: str) -> bool:
    if not value:
        return True
    path = PurePosixPath(value)
    return not path.is_absolute() and ".." not in path.parts


@dataclass(slots=True)
class Engagement:
    id: str
    client: str
    name: str
    assessment_type: AssessmentType
    created_at: str = field(default_factory=utc_now)
    logging_enabled: bool = True
    status: EngagementStatus = EngagementStatus.ACTIVE
    authorization: Authorization = field(default_factory=Authorization)
    scope: list[ScopeEntry] = field(default_factory=list)
    targets: list[Target] = field(default_factory=list)
    access: list[AccessRecord] = field(default_factory=list)
    activities: list[Activity] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    attack_paths: list[AttackPath] = field(default_factory=list)
    cleanup: list[CleanupItem] = field(default_factory=list)
    counters: dict[str, int] = field(default_factory=dict)
    revision: int = 0
    schema: str = SCHEMA

    @classmethod
    def create(
        cls,
        client: str,
        name: str,
        assessment_type: AssessmentType,
        *,
        logging_enabled: bool = True,
    ) -> "Engagement":
        engagement = cls(
            id=f"E-{uuid4().hex[:12]}",
            client=client.strip(),
            name=name.strip(),
            assessment_type=assessment_type,
            logging_enabled=logging_enabled,
        )
        engagement.normalize()
        engagement.validate()
        return engagement

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Engagement":
        if not isinstance(value, dict):
            raise ValidationError("engagement manifest must contain a JSON object")
        if value.get("schema") != SCHEMA:
            raise ValidationError(
                f"unsupported engagement schema: {value.get('schema', '<missing>')}"
            )

        logging_enabled = value.get("logging_enabled", True)
        counters = value.get("counters", {})
        revision = value.get("revision", 0)
        if not isinstance(logging_enabled, bool):
            raise ValidationError("manifest logging_enabled must be true or false")
        if not isinstance(counters, dict) or any(
            not isinstance(key, str)
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
            for key, count in counters.items()
        ):
            raise ValidationError(
                "manifest counters must contain non-negative integers"
            )
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
            raise ValidationError("manifest revision must be a non-negative integer")
        try:
            engagement = cls(
                schema=SCHEMA,
                id=_text(value, "id"),
                client=_text(value, "client"),
                name=_text(value, "name"),
                assessment_type=AssessmentType(_text(value, "assessment_type")),
                created_at=_text(value, "created_at", default=utc_now()),
                logging_enabled=logging_enabled,
                status=EngagementStatus(_text(value, "status", default="active")),
                authorization=Authorization.from_dict(
                    _object(value.get("authorization", {}), "authorization")
                ),
                scope=[ScopeEntry.from_dict(item) for item in _objects(value, "scope")],
                targets=[Target.from_dict(item) for item in _objects(value, "targets")],
                access=[
                    AccessRecord.from_dict(item) for item in _objects(value, "access")
                ],
                activities=[
                    Activity.from_dict(item) for item in _objects(value, "activities")
                ],
                findings=[
                    Finding.from_dict(item) for item in _objects(value, "findings")
                ],
                attack_paths=[
                    AttackPath.from_dict(item)
                    for item in _objects(value, "attack_paths")
                ],
                cleanup=[
                    CleanupItem.from_dict(item) for item in _objects(value, "cleanup")
                ],
                counters=dict(counters),
                revision=revision,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError(f"invalid engagement manifest: {exc}") from exc
        engagement.normalize()
        engagement.validate()
        return engagement

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        return value

    def next_id(self, kind: str, prefix: str) -> str:
        existing = [
            int(identifier[len(prefix) :])
            for collection in (
                self.scope,
                self.targets,
                self.access,
                self.activities,
                self.findings,
                self.attack_paths,
                self.cleanup,
            )
            for identifier in (item.id for item in collection)
            if identifier.startswith(prefix) and identifier[len(prefix) :].isdigit()
        ]
        number = max([self.counters.get(kind, 0), *existing]) + 1
        self.counters[kind] = number
        return f"{prefix}{number:04d}"

    def scope_by_id(self, scope_id: str) -> ScopeEntry:
        for item in self.scope:
            if item.id == scope_id:
                return item
        raise ValidationError(f"unknown scope entry: {scope_id}")

    def target_by_id(self, target_id: str) -> Target:
        for target in self.targets:
            if target.id == target_id:
                return target
        raise ValidationError(f"unknown target: {target_id}")

    def add_scope(
        self,
        label: str,
        group: ScopeGroup,
        network: str,
        availability: ScopeAvailability = ScopeAvailability.READY,
        via_target_id: str = "",
        exclusions: list[str] | tuple[str, ...] = (),
    ) -> ScopeEntry:
        kind, stored_network, domain, normalized_exclusions = classify_scope(
            network, exclusions
        )
        normalized = stored_network or domain
        if via_target_id:
            self.target_by_id(via_target_id)
        if any(
            item.group == group and item.kind == kind and item.spec == normalized
            for item in self.scope
        ):
            raise ConflictError(f"scope already exists in {group.value}: {normalized}")
        item = ScopeEntry(
            id=self.next_id("scope", "S"),
            label=label.strip() or normalized,
            group=group,
            network=stored_network,
            availability=availability,
            via_target_id=via_target_id,
            kind=kind,
            domain=domain,
            exclusions=normalized_exclusions,
        )
        self.scope.append(item)
        self._validate_scope({target.id for target in self.targets})
        return item

    @property
    def domain_entries(self) -> list[ScopeEntry]:
        return [item for item in self.scope if item.kind == ScopeKind.DOMAIN]

    @property
    def network_entries(self) -> list[ScopeEntry]:
        return [item for item in self.scope if item.kind == ScopeKind.NETWORK]

    def hostname_scope(self, hostname: str) -> list[ScopeEntry]:
        return [item for item in self.domain_entries if item.matches_hostname(hostname)]

    def unscoped_hostnames(self, target: Target) -> list[str]:
        if not self.domain_entries:
            return []
        return [item for item in target.hostnames if not self.hostname_scope(item)]

    @property
    def outstanding_cleanup(self) -> list[CleanupItem]:
        return [item for item in self.cleanup if not item.removed_at]

    def strongest_access(self, target_id: str) -> AccessLevel | None:
        records = [item.level for item in self.access if item.target_id == target_id]
        return max(records, key=ACCESS_RANK.get) if records else None

    def confirmed_reference(self, ref_type: str, ref_id: str) -> bool:
        if ref_type == "access":
            return any(item.id == ref_id for item in self.access)
        if ref_type == "activity":
            return any(
                item.id == ref_id and item.result == ActivityResult.CONFIRMED
                for item in self.activities
            )
        if ref_type == "finding":
            return any(
                item.id == ref_id
                and item.state in {FindingState.CONFIRMED, FindingState.CLOSED}
                for item in self.findings
            )
        return False

    def target_references(self, target_id: str) -> list[str]:
        references: list[str] = []
        references.extend(
            f"scope {item.id}" for item in self.scope if item.via_target_id == target_id
        )
        references.extend(
            f"access {item.id}" for item in self.access if item.target_id == target_id
        )
        references.extend(
            f"activity {item.id}"
            for item in self.activities
            if item.target_id == target_id
        )
        references.extend(
            f"finding {item.id}"
            for item in self.findings
            if target_id in item.target_ids
        )
        references.extend(
            f"cleanup {item.id}" for item in self.cleanup if item.target_id == target_id
        )
        return references

    def normalize(self) -> None:
        for scope in self.scope:
            if scope.kind == ScopeKind.NETWORK:
                try:
                    scope.network = str(
                        ipaddress.ip_network(scope.network, strict=False)
                    )
                except ValueError as exc:
                    raise ValidationError(
                        f"invalid stored scope network: {scope.network}"
                    ) from exc
                scope.domain = ""
                try:
                    scope.exclusions = sorted(
                        {
                            str(ipaddress.ip_network(item, strict=False))
                            for item in scope.exclusions
                        }
                    )
                except ValueError as exc:
                    raise ValidationError(
                        f"invalid exclusion in scope {scope.id}"
                    ) from exc
            else:
                scope.domain = normalize_domain_pattern(scope.domain)
                scope.network = ""
                scope.exclusions = sorted(
                    {normalize_domain_pattern(item) for item in scope.exclusions}
                )
        for target in self.targets:
            for address in target.addresses:
                try:
                    address.value = str(ipaddress.ip_address(address.value))
                except ValueError as exc:
                    raise ValidationError(
                        f"invalid target address: {address.value}"
                    ) from exc
            target.hostnames = sorted(
                {normalize_hostname(item) for item in target.hostnames if item.strip()}
            )
            if target.primary_endpoint:
                try:
                    target.primary_endpoint = str(
                        ipaddress.ip_address(target.primary_endpoint)
                    )
                except ValueError:
                    target.primary_endpoint = normalize_hostname(target.primary_endpoint)
            target.services.sort(key=lambda item: (item.protocol, item.port))

    def validate(self) -> None:
        if self.schema != SCHEMA:
            raise ValidationError(f"manifest schema must be {SCHEMA}")
        if (
            not re.fullmatch(r"E-[0-9a-f]{12}", self.id)
            or not self.client.strip()
            or not self.name.strip()
        ):
            raise ValidationError(
                "engagement requires a stable ID, client/lab, and name"
            )
        start = (
            parse_utc(self.authorization.window_start)
            if self.authorization.window_start
            else None
        )
        end = (
            parse_utc(self.authorization.window_end)
            if self.authorization.window_end
            else None
        )
        if start is not None and end is not None and start > end:
            raise ValidationError("authorization window start must not be after its end")

        self._validate_identifiers()
        target_ids = {target.id for target in self.targets}
        scope_by_id = self._validate_scope(target_ids)
        self._validate_targets(scope_by_id)
        self._validate_records(target_ids)
        self._validate_attack_paths()

    def _validate_identifiers(self) -> None:
        collections = {
            "scope": (self.scope, r"S[0-9]{4,}"),
            "targets": (self.targets, r"T[0-9]{4,}"),
            "access": (self.access, r"AR[0-9]{4,}"),
            "activities": (self.activities, r"A[0-9]{4,}"),
            "findings": (self.findings, r"F[0-9]{4,}"),
            "attack paths": (self.attack_paths, r"P[0-9]{4,}"),
            "cleanup": (self.cleanup, r"C[0-9]{4,}"),
        }
        for label, (items, pattern) in collections.items():
            identifiers = [item.id for item in items]
            if len(identifiers) != len(set(identifiers)):
                raise ValidationError(f"duplicate ID in {label}")
            if any(not re.fullmatch(pattern, identifier) for identifier in identifiers):
                raise ValidationError(f"invalid ID in {label}")

    def _validate_scope(self, target_ids: set[str]) -> dict[str, ScopeEntry]:
        scope_by_id = {item.id: item for item in self.scope}
        for item in self.scope:
            if item.kind == ScopeKind.NETWORK:
                if item.domain:
                    raise ValidationError(f"network scope {item.id} has a domain value")
                try:
                    network = ipaddress.ip_network(item.network, strict=True)
                except ValueError as exc:
                    raise ValidationError(
                        f"invalid stored scope network: {item.network}"
                    ) from exc
                for exclusion in item.exclusions:
                    try:
                        excluded = ipaddress.ip_network(exclusion, strict=True)
                        inside = excluded.subnet_of(network)
                    except (TypeError, ValueError) as exc:
                        raise ValidationError(
                            f"invalid exclusion {exclusion} in scope {item.id}"
                        ) from exc
                    if not inside:
                        raise ValidationError(
                            f"exclusion {exclusion} is not inside scope {item.id} ({item.network})"
                        )
            else:
                if item.network:
                    raise ValidationError(f"domain scope {item.id} has a network value")
                normalize_domain_pattern(item.domain)
                for exclusion in item.exclusions:
                    normalize_domain_pattern(exclusion)
                    if not pattern_inside(exclusion, item.domain):
                        raise ValidationError(
                            f"exclusion {exclusion} is not inside scope {item.id} ({item.domain})"
                        )
            if item.via_target_id and item.via_target_id not in target_ids:
                raise ValidationError(f"scope {item.id} references missing target")
        return scope_by_id

    def _validate_targets(self, scope_by_id: dict[str, ScopeEntry]) -> None:
        used_addresses: set[tuple[str, str]] = set()
        used_directories: set[str] = set()
        for target in self.targets:
            if not target.display_name.strip() or not target.directory.strip():
                raise ValidationError(
                    f"target {target.id} requires a display name and directory"
                )
            if PurePosixPath(
                target.directory
            ).name != target.directory or target.directory in {".", ".."}:
                raise ValidationError(f"unsafe target directory: {target.directory}")
            if target.directory in used_directories:
                raise ValidationError(f"duplicate target directory: {target.directory}")
            used_directories.add(target.directory)
            values = self._validate_target_addresses(
                target, scope_by_id, used_addresses
            )
            if len(target.services) != len(
                {(item.port, item.protocol) for item in target.services}
            ):
                raise ValidationError(f"target {target.id} has duplicate services")
            for service in target.services:
                if not 1 <= service.port <= 65535:
                    raise ValidationError(f"invalid service port on target {target.id}")
                if service.protocol not in {"tcp", "udp", "sctp"}:
                    raise ValidationError(f"invalid service protocol on target {target.id}")
                if service.state not in {"open", "open|filtered"}:
                    raise ValidationError(f"invalid service state on target {target.id}")
                if not _safe_reference(service.source):
                    raise ValidationError(f"unsafe service source on target {target.id}")
            for hostname in target.hostnames:
                if normalize_hostname(hostname) != hostname:
                    raise ValidationError(f"target {target.id} hostname is not normalized")
            if target.primary_endpoint:
                endpoint_is_hostname = False
                try:
                    normalized_endpoint = str(ipaddress.ip_address(target.primary_endpoint))
                except ValueError:
                    endpoint_is_hostname = True
                    normalized_endpoint = normalize_hostname(target.primary_endpoint)
                if normalized_endpoint != target.primary_endpoint:
                    raise ValidationError(
                        f"target {target.id} primary endpoint is not normalized"
                    )
                if (
                    target.primary_endpoint not in values
                    and target.primary_endpoint not in target.hostnames
                ):
                    raise ValidationError(
                        f"target {target.id} primary endpoint is not one of its addresses or hostnames"
                    )
                if (
                    endpoint_is_hostname
                    and self.domain_entries
                    and not self.hostname_scope(normalized_endpoint)
                ):
                    raise ValidationError(
                        f"target {target.id} primary endpoint "
                        f"{normalized_endpoint} is not inside declared domain scope"
                    )

    @staticmethod
    def _validate_target_addresses(
        target: Target,
        scope_by_id: dict[str, ScopeEntry],
        used_addresses: set[tuple[str, str]],
    ) -> set[str]:
        values: set[str] = set()
        for address in target.addresses:
            if address.scope_id not in scope_by_id:
                raise ValidationError(
                    f"target {target.id} uses unknown scope {address.scope_id}"
                )
            scope = scope_by_id[address.scope_id]
            if scope.kind != ScopeKind.NETWORK:
                raise ValidationError(
                    f"target {target.id} address references domain scope {address.scope_id}"
                )
            try:
                normalized = str(ipaddress.ip_address(address.value))
            except ValueError as exc:
                raise ValidationError(
                    f"invalid target address: {address.value}"
                ) from exc
            if normalized != address.value:
                raise ValidationError(f"target {target.id} address is not normalized")
            parsed = ipaddress.ip_address(normalized)
            if parsed not in ipaddress.ip_network(scope.network):
                raise ValidationError(
                    f"address {normalized} is outside scope {address.scope_id}"
                )
            if not scope.contains(parsed):
                raise ValidationError(
                    f"address {normalized} is excluded from scope {address.scope_id}"
                )
            key = (address.scope_id, normalized)
            if key in used_addresses:
                raise ConflictError(
                    f"address {normalized} already belongs to another target in {address.scope_id}"
                )
            used_addresses.add(key)
            values.add(normalized)
        return values

    def _validate_records(self, target_ids: set[str]) -> None:
        for record in self.access:
            if record.target_id not in target_ids:
                raise ValidationError(f"access {record.id} references missing target")
            if not record.principal.strip() or not _safe_reference(record.evidence):
                raise ValidationError(f"invalid access record: {record.id}")
        for activity in self.activities:
            if activity.target_id and activity.target_id not in target_ids:
                raise ValidationError(
                    f"activity {activity.id} references missing target"
                )
            if not activity.summary.strip() or not _safe_reference(activity.evidence):
                raise ValidationError(f"invalid activity: {activity.id}")
        for finding in self.findings:
            if (
                not finding.title.strip()
                or not finding.target_ids
                or len(finding.target_ids) != len(set(finding.target_ids))
                or any(item not in target_ids for item in finding.target_ids)
            ):
                raise ValidationError(f"invalid finding: {finding.id}")
            if finding.document != f"findings/{finding.id}.md" or any(
                not _safe_reference(item) for item in finding.evidence
            ):
                raise ValidationError(f"unsafe finding path: {finding.id}")
            if finding.created_at:
                parse_utc(finding.created_at)
        for item in self.cleanup:
            if item.target_id not in target_ids or not item.location.strip():
                raise ValidationError(f"invalid cleanup item: {item.id}")
            if item.sha256 and not re.fullmatch(r"[0-9a-fA-F]{64}", item.sha256):
                raise ValidationError(f"invalid cleanup SHA-256: {item.id}")

    def _validate_attack_paths(self) -> None:
        for path in self.attack_paths:
            if not path.name.strip() or not path.steps:
                raise ValidationError(
                    f"attack path {path.id} requires a name and steps"
                )
            if path.created_at:
                parse_utc(path.created_at)
            for step in path.steps:
                if not self.confirmed_reference(step.ref_type, step.ref_id):
                    raise ValidationError(
                        f"attack path {path.id} contains unconfirmed reference {step.ref_type}:{step.ref_id}"
                    )
