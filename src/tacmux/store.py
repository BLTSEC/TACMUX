"""Private filesystem layout and atomic manifest persistence."""

from __future__ import annotations

from copy import deepcopy
from contextlib import contextmanager, suppress
from dataclasses import dataclass, fields
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import tempfile
from typing import Callable, Iterable, Iterator, TypeVar

from .config import Settings
from .errors import ConflictError, SafetyError, ValidationError
from .model import (
    AccessLevel,
    AccessRecord,
    Activity,
    ActivityResult,
    AssessmentType,
    AttackPath,
    AttackPathStep,
    Engagement,
    Finding,
    FindingState,
    ScopeEntry,
    ScopeAvailability,
    ScopeGroup,
    Severity,
    Target,
    TargetAddress,
)
from .render import render_activity_markdown, render_attack_path_markdown, render_sitrep


TARGET_PHASES = ("recon", "exploitation", "loot", "screenshots", "reports", "logs")
MANIFEST_RELATIVE = Path(".tacmux/engagement.json")
STATE_SCHEMA = "tacmux.state/v1"
MutationResult = TypeVar("MutationResult")


def restore_engagement_state(engagement: Engagement, snapshot: Engagement) -> None:
    for item in fields(Engagement):
        setattr(engagement, item.name, deepcopy(getattr(snapshot, item.name)))


def safe_filename(value: str, fallback: str = "item", limit: int = 48) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-._")
    return (normalized or fallback)[:limit]


def _private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def harden_private_tree(root: Path) -> None:
    """Apply owner-only modes to a copied or restored tree without following links."""

    root = root.resolve(strict=True)
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        os.chmod(current_path, 0o700)
        for name in directories:
            path = current_path / name
            if not path.is_symlink():
                os.chmod(path, 0o700)
        for name in files:
            path = current_path / name
            if path.is_symlink():
                continue
            executable = path.stat().st_mode & 0o111
            os.chmod(path, 0o700 if executable else 0o600)


def write_private_text(path: Path, text: str) -> None:
    _private_directory(path.parent)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        _fsync_directory(path.parent)
    except BaseException:
        with suppress(OSError):
            os.close(descriptor)
        with suppress(FileNotFoundError):
            os.unlink(temporary)
        raise


def write_private_json(path: Path, value: object) -> None:
    write_private_text(
        path, json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    )


def _contained(root: Path, path: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=True))
        return True
    except (OSError, ValueError):
        return False


@dataclass(slots=True, frozen=True)
class EngagementRecord:
    root: Path
    engagement: Engagement


class Workspace:
    def __init__(self, settings: Settings):
        self.settings = settings

    def initialize(self) -> None:
        os.umask(0o077)
        _private_directory(self.settings.workspace)
        _private_directory(self.settings.archive_dir)
        _private_directory(self.settings.log_dir)
        _private_directory(self.settings.config_file.parent)

    @contextmanager
    def lock(self, engagement_root: Path | None = None) -> Iterator[None]:
        root = engagement_root or self.settings.workspace
        _private_directory(root / ".tacmux")
        lock_path = root / ".tacmux/write.lock"
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def list_engagements(self) -> list[EngagementRecord]:
        if not self.settings.workspace.is_dir():
            return []
        records: list[EngagementRecord] = []
        for manifest in self.settings.workspace.glob("E-*/.tacmux/engagement.json"):
            try:
                engagement = self.load(manifest.parent.parent)
            except (OSError, ValidationError, ValueError, KeyError, TypeError):
                continue
            records.append(EngagementRecord(manifest.parent.parent, engagement))
        return sorted(
            records, key=lambda item: item.engagement.created_at, reverse=True
        )

    def invalid_engagements(self) -> list[tuple[Path, str]]:
        problems: list[tuple[Path, str]] = []
        if not self.settings.workspace.is_dir():
            return problems
        for manifest in self.settings.workspace.glob("E-*/.tacmux/engagement.json"):
            try:
                self.load(manifest.parent.parent)
            except (OSError, ValidationError, ValueError, KeyError, TypeError) as exc:
                problems.append((manifest, str(exc)))
        return problems

    def find(self, engagement_id: str) -> EngagementRecord:
        for record in self.list_engagements():
            if record.engagement.id == engagement_id:
                return record
        raise ValidationError(f"engagement not found: {engagement_id}")

    def delete_engagement(self, engagement_id: str) -> None:
        """Permanently remove one validated engagement from the live workspace."""

        workspace_root = self.settings.workspace.resolve(strict=True)
        staging: Path | None = None
        with self.lock():
            record = self.find(engagement_id)
            root = record.root
            if root.is_symlink():
                raise SafetyError(f"refusing to delete symlinked engagement: {root}")
            try:
                resolved_root = root.resolve(strict=True)
                resolved_parent = root.parent.resolve(strict=True)
            except OSError as exc:
                raise SafetyError(
                    f"cannot validate engagement path {root}: {exc}"
                ) from exc
            if (
                resolved_parent != workspace_root
                or resolved_root.parent != workspace_root
            ):
                raise SafetyError(
                    "engagement is not a direct child of the configured workspace: "
                    f"{root}"
                )
            if not root.name.startswith(f"{engagement_id}-"):
                raise SafetyError(
                    f"engagement directory does not match {engagement_id}: {root}"
                )
            if record.engagement.id != engagement_id:
                raise SafetyError(
                    f"engagement manifest identity does not match {engagement_id}"
                )

            deleting_root = workspace_root / ".tacmux" / "deleting"
            _private_directory(deleting_root)
            staging = deleting_root / (
                f"{engagement_id}-{os.getpid()}-{secrets.token_hex(4)}"
            )
            if staging.exists():
                raise ConflictError(f"delete staging path already exists: {staging}")
            root.rename(staging)
            try:
                _fsync_directory(workspace_root)
                if self.get_last_engagement() == engagement_id:
                    self.set_last_engagement("")
            except BaseException:
                try:
                    staging.rename(root)
                    _fsync_directory(workspace_root)
                except OSError as rollback_error:
                    raise SafetyError(
                        "engagement deletion could not be rolled back; data remains at "
                        f"{staging}"
                    ) from rollback_error
                raise

        assert staging is not None
        try:
            shutil.rmtree(staging)
            _fsync_directory(staging.parent)
        except OSError as exc:
            if staging.exists():
                raise SafetyError(
                    "engagement was removed from the picker, but filesystem cleanup "
                    f"is incomplete at {staging}: {exc}"
                ) from exc
            raise SafetyError(
                f"engagement was deleted, but final directory sync failed: {exc}"
            ) from exc

    def load(self, engagement_root: Path) -> Engagement:
        manifest = engagement_root / MANIFEST_RELATIVE
        try:
            with manifest.open(encoding="utf-8") as stream:
                value = json.load(stream)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValidationError(
                f"cannot read engagement manifest {manifest}: {exc}"
            ) from exc
        if not isinstance(value, dict):
            raise ValidationError(
                f"engagement manifest must contain a JSON object: {manifest}"
            )
        return Engagement.from_dict(value)

    def create_engagement(
        self,
        client: str,
        name: str,
        assessment_type: AssessmentType,
        *,
        logging_enabled: bool | None = None,
        initial_scope: Iterable[tuple[str, ScopeGroup, str, ScopeAvailability]] = (),
    ) -> EngagementRecord:
        self.initialize()
        engagement = Engagement.create(
            client,
            name,
            assessment_type,
            logging_enabled=self.settings.auto_log
            if logging_enabled is None
            else logging_enabled,
        )
        for label, group, network, availability in initial_scope:
            engagement.add_scope(label, group, network, availability)
        directory = f"{engagement.id}-{safe_filename(name, 'engagement')}"
        root = self.settings.workspace / directory
        if root.exists():
            raise ConflictError(f"engagement directory already exists: {root}")
        with self.lock():
            _private_directory(root)
            try:
                for relative in (
                    "notes",
                    "findings",
                    "targets",
                    ".tacmux/jobs",
                    ".tacmux/deleting",
                ):
                    _private_directory(root / relative)
                self._seed_editable_documents(root, engagement)
                self.save(root, engagement)
            except BaseException:
                shutil.rmtree(root, ignore_errors=True)
                raise
        self.set_last_engagement(engagement.id)
        return EngagementRecord(root, engagement)

    def _seed_editable_documents(self, root: Path, engagement: Engagement) -> None:
        overview = f"""# Engagement — {engagement.client}: {engagement.name}

> Confirm written authorization, scope, rules of engagement, and retention requirements before testing.

## Authorization

- Authorized by:
- Contract / SOW reference:
- Testing window (UTC):
- Emergency contact:

## Objectives

-

## Rules of Engagement

- Allowed techniques:
- Prohibited techniques:
- Testing hours:
- Evidence retention:

## Operator Notes

-

---
Created: {engagement.created_at}
"""
        write_private_text(root / "ENGAGEMENT.md", overview)
        write_private_text(
            root / "notes/payloads.md",
            "# Payload Log\n\n| UTC | Target | Path | SHA-256 | Cleanup |\n|---|---|---|---|---|\n",
        )
        write_private_text(
            root / "findings/README.md",
            "# Findings\n\nFinding narratives are created through TACMUX and edited with `$EDITOR`.\n",
        )

    def save(self, root: Path, engagement: Engagement) -> None:
        if not _contained(self.settings.workspace, root):
            raise SafetyError(f"engagement is outside configured workspace: {root}")
        engagement.validate()
        with self.lock(root):
            manifest = root / MANIFEST_RELATIVE
            if manifest.is_file():
                current = self.load(root)
                if current.revision != engagement.revision:
                    raise ConflictError(
                        "engagement changed in another TACMUX process; refresh and retry"
                    )
            previous_revision = engagement.revision
            engagement.revision += 1
            try:
                write_private_text(
                    root / "notes/activity.md", render_activity_markdown(engagement)
                )
                write_private_text(
                    root / "notes/attack-path.md",
                    render_attack_path_markdown(engagement),
                )
                write_private_text(
                    root / "SITREP.md",
                    render_sitrep(
                        engagement, include_mermaid=self.settings.include_mermaid
                    ),
                )
                # The manifest is the commit point. Generated documents are recoverable;
                # a manifest that references missing target files is not.
                write_private_json(manifest, engagement.to_dict())
            except BaseException:
                engagement.revision = previous_revision
                raise

    def _mutate_manifest(
        self,
        root: Path,
        engagement: Engagement,
        mutation: Callable[[], MutationResult],
    ) -> MutationResult:
        snapshot = deepcopy(engagement)
        try:
            result = mutation()
            self.save(root, engagement)
            return result
        except BaseException:
            restore_engagement_state(engagement, snapshot)
            raise

    def add_scope(
        self,
        root: Path,
        engagement: Engagement,
        label: str,
        group: ScopeGroup,
        network: str,
        availability: ScopeAvailability = ScopeAvailability.READY,
        via_target_id: str = "",
    ) -> ScopeEntry:
        return self._mutate_manifest(
            root,
            engagement,
            lambda: engagement.add_scope(
                label, group, network, availability, via_target_id
            ),
        )

    def update_scope(
        self,
        root: Path,
        engagement: Engagement,
        scope_id: str,
        *,
        label: str,
        group: ScopeGroup,
        network: str,
        availability: ScopeAvailability,
        via_target_id: str,
    ) -> ScopeEntry:
        def mutate() -> ScopeEntry:
            scope = engagement.scope_by_id(scope_id)
            scope.label = label
            scope.group = group
            scope.network = str(ipaddress.ip_network(network, strict=False))
            scope.availability = availability
            scope.via_target_id = via_target_id
            if any(
                item.id != scope.id
                and item.group == scope.group
                and item.network == scope.network
                for item in engagement.scope
            ):
                raise ValidationError(
                    f"scope already exists in {scope.group.value}: {scope.network}"
                )
            return scope

        return self._mutate_manifest(root, engagement, mutate)

    def add_target_address(
        self,
        root: Path,
        engagement: Engagement,
        target_id: str,
        address: str,
        scope_id: str,
        *,
        primary: bool = False,
    ) -> Target:
        def mutate() -> Target:
            target = engagement.target_by_id(target_id)
            target.addresses.append(TargetAddress(address, scope_id))
            if primary or not target.primary_endpoint:
                target.primary_endpoint = address
            return target

        return self._mutate_manifest(root, engagement, mutate)

    def remove_target_address(
        self,
        root: Path,
        engagement: Engagement,
        target_id: str,
        index: int,
    ) -> Target:
        def mutate() -> Target:
            target = engagement.target_by_id(target_id)
            if index < 0:
                raise ValidationError("target address selection is no longer valid")
            try:
                removed = target.addresses.pop(index)
            except IndexError as exc:
                raise ValidationError(
                    "target address selection is no longer valid"
                ) from exc
            if target.primary_endpoint == removed.value:
                target.primary_endpoint = (
                    target.hostnames[0]
                    if target.hostnames
                    else (target.addresses[0].value if target.addresses else "")
                )
            return target

        return self._mutate_manifest(root, engagement, mutate)

    def replace_target_hostnames(
        self,
        root: Path,
        engagement: Engagement,
        target_id: str,
        hostnames: Iterable[str],
    ) -> Target:
        def mutate() -> Target:
            target = engagement.target_by_id(target_id)
            previous = set(target.hostnames)
            target.hostnames = sorted(
                {item.strip() for item in hostnames if item.strip()}
            )
            if (
                target.primary_endpoint in previous
                and target.primary_endpoint not in target.hostnames
            ):
                target.primary_endpoint = (
                    target.hostnames[0]
                    if target.hostnames
                    else (target.addresses[0].value if target.addresses else "")
                )
            return target

        return self._mutate_manifest(root, engagement, mutate)

    def set_primary_endpoint(
        self,
        root: Path,
        engagement: Engagement,
        target_id: str,
        endpoint: str,
    ) -> Target:
        def mutate() -> Target:
            target = engagement.target_by_id(target_id)
            target.primary_endpoint = endpoint
            return target

        return self._mutate_manifest(root, engagement, mutate)

    def create_access(
        self,
        root: Path,
        engagement: Engagement,
        target_id: str,
        *,
        principal: str,
        authority: str,
        method: str,
        level: AccessLevel,
        evidence: str,
    ) -> AccessRecord:
        def mutate() -> AccessRecord:
            record = AccessRecord(
                id=engagement.next_id("access", "AR"),
                principal=principal,
                authority=authority,
                target_id=target_id,
                method=method,
                level=level,
                evidence=evidence,
            )
            engagement.access.append(record)
            return record

        return self._mutate_manifest(root, engagement, mutate)

    def create_activity(
        self,
        root: Path,
        engagement: Engagement,
        *,
        summary: str,
        result: ActivityResult,
        target_id: str,
        evidence: str,
    ) -> Activity:
        def mutate() -> Activity:
            activity = Activity(
                id=engagement.next_id("activity", "A"),
                summary=summary,
                result=result,
                target_id=target_id,
                evidence=evidence,
            )
            engagement.activities.append(activity)
            return activity

        return self._mutate_manifest(root, engagement, mutate)

    def create_attack_path(
        self,
        root: Path,
        engagement: Engagement,
        name: str,
        steps: Iterable[tuple[str, str, str]],
    ) -> AttackPath:
        def mutate() -> AttackPath:
            path = AttackPath(
                id=engagement.next_id("attack_path", "P"),
                name=name,
                steps=[AttackPathStep(*item) for item in steps],
            )
            engagement.attack_paths.append(path)
            return path

        return self._mutate_manifest(root, engagement, mutate)

    def update_record(
        self,
        root: Path,
        engagement: Engagement,
        kind: str,
        record_id: str,
        value: dict,
    ) -> AccessRecord | Activity | Finding | AttackPath:
        collections = {
            "access": engagement.access,
            "activity": engagement.activities,
            "finding": engagement.findings,
            "attack_path": engagement.attack_paths,
        }

        def mutate() -> AccessRecord | Activity | Finding | AttackPath:
            record = next(
                (item for item in collections.get(kind, []) if item.id == record_id),
                None,
            )
            if record is None:
                raise ValidationError(f"unknown {kind} record: {record_id}")
            names = {
                "access": ("principal", "authority", "method", "level", "evidence"),
                "activity": ("summary", "result", "target_id", "evidence"),
                "finding": ("title", "severity", "state", "target_ids", "evidence"),
            }
            if kind == "attack_path":
                record.name = value["name"]
                record.steps = [AttackPathStep(*item) for item in value["steps"]]
            else:
                for name in names[kind]:
                    setattr(record, name, value[name])
            return record

        return self._mutate_manifest(root, engagement, mutate)

    def refresh_sitrep(
        self,
        root: Path,
        engagement: Engagement,
        *,
        live_target_ids: set[str] | None = None,
        jobs: list[dict] | None = None,
    ) -> None:
        with self.lock(root):
            if self.load(root).revision != engagement.revision:
                raise ConflictError(
                    "engagement changed in another TACMUX process; refresh and retry"
                )
            write_private_text(
                root / "SITREP.md",
                render_sitrep(
                    engagement,
                    live_sessions=live_target_ids or set(),
                    jobs=jobs or [],
                    include_mermaid=self.settings.include_mermaid,
                ),
            )

    def create_target(
        self,
        root: Path,
        engagement: Engagement,
        display_name: str,
        *,
        addresses: list[TargetAddress] | None = None,
        hostnames: list[str] | None = None,
        primary_endpoint: str = "",
    ) -> Target:
        snapshot = deepcopy(engagement)
        target: Target | None = None
        try:
            target = self.stage_target(
                root,
                engagement,
                display_name,
                addresses=addresses,
                hostnames=hostnames,
                primary_endpoint=primary_endpoint,
            )
            self.save(root, engagement)
        except BaseException:
            restore_engagement_state(engagement, snapshot)
            if target is not None:
                shutil.rmtree(root / "targets" / target.directory, ignore_errors=True)
            raise
        assert target is not None
        return target

    def stage_target(
        self,
        root: Path,
        engagement: Engagement,
        display_name: str,
        *,
        addresses: list[TargetAddress] | None = None,
        hostnames: list[str] | None = None,
        primary_endpoint: str = "",
    ) -> Target:
        """Prepare one target for a caller that will commit the engagement once."""

        if not display_name.strip():
            raise ValidationError("target display name is required")
        target_id = engagement.next_id("target", "T")
        directory = f"{target_id}-{safe_filename(display_name, 'target')}"
        target = Target(
            id=target_id,
            display_name=display_name.strip(),
            directory=directory,
            addresses=list(addresses or []),
            hostnames=sorted(set(hostnames or [])),
            primary_endpoint=primary_endpoint.strip(),
        )
        target_root = root / "targets" / directory
        if not _contained(root, target_root) or target_root.exists():
            raise SafetyError(f"unsafe or existing target directory: {target_root}")
        _private_directory(target_root)
        try:
            for phase in TARGET_PHASES:
                _private_directory(target_root / phase)
            write_private_text(
                target_root / "NOTES.md",
                f"# {target.display_name}\n\n- Target ID: `{target.id}`\n- Created: {target.created_at}\n\n## Notes\n\n-\n",
            )
            engagement.targets.append(target)
            engagement.validate()
        except BaseException:
            engagement.targets = [
                item for item in engagement.targets if item.id != target.id
            ]
            shutil.rmtree(target_root, ignore_errors=True)
            raise
        return target

    def rename_target(
        self, root: Path, engagement: Engagement, target_id: str, name: str
    ) -> None:
        if not name.strip():
            raise ValidationError("target display name is required")

        def mutate() -> Target:
            target = engagement.target_by_id(target_id)
            target.display_name = name.strip()
            return target

        target = self._mutate_manifest(root, engagement, mutate)
        notes = root / "targets" / target.directory / "NOTES.md"
        try:
            content = notes.read_text(encoding="utf-8")
            _, separator, remainder = content.partition("\n")
            write_private_text(notes, f"# {target.display_name}{separator}{remainder}")
        except OSError:
            # Target identity is durable in the manifest; a missing editable note is
            # surfaced by the document browser and must not roll back the rename.
            pass

    def create_finding(
        self,
        root: Path,
        engagement: Engagement,
        *,
        title: str,
        severity: Severity,
        state: FindingState,
        target_ids: list[str],
        evidence: list[str] | None = None,
    ) -> Finding:
        snapshot = deepcopy(engagement)
        finding_id = engagement.next_id("finding", "F")
        document = f"findings/{finding_id}.md"
        finding = Finding(
            id=finding_id,
            title=title.strip(),
            severity=severity,
            state=state,
            target_ids=target_ids,
            evidence=list(evidence or []),
            document=document,
        )
        engagement.findings.append(finding)
        finding_path = root / document
        try:
            engagement.validate()
            write_private_text(
                finding_path,
                f"# {title.strip()}\n\n"
                f"- **ID:** `{finding_id}`\n"
                f"- **Severity:** {severity.value}\n"
                f"- **State:** {state.value}\n\n"
                "## Summary\n\n\n"
                "## Evidence\n\n\n"
                "## Impact\n\n\n"
                "## Recommendation\n\n\n",
            )
            self.save(root, engagement)
        except BaseException:
            restore_engagement_state(engagement, snapshot)
            finding_path.unlink(missing_ok=True)
            raise
        return finding

    def sync_finding_document(self, root: Path, finding: Finding) -> None:
        path = root / finding.document
        if not _contained(root, path) or not path.is_file():
            raise SafetyError(f"finding document is missing or unsafe: {path}")
        content = path.read_text(encoding="utf-8")
        marker = "## Summary"
        _, separator, narrative = content.partition(marker)
        if not separator:
            raise ValidationError(
                f"finding document is missing its Summary section: {finding.document}"
            )
        header = (
            f"# {finding.title}\n\n"
            f"- **ID:** `{finding.id}`\n"
            f"- **Severity:** {finding.severity.value}\n"
            f"- **State:** {finding.state.value}\n\n"
        )
        write_private_text(path, header + marker + narrative)

    def delete_target(self, root: Path, engagement: Engagement, target_id: str) -> None:
        target = engagement.target_by_id(target_id)
        references = engagement.target_references(target_id)
        if references:
            raise ConflictError(
                "target is referenced by "
                + ", ".join(references)
                + "; remove those records first"
            )
        target_root = root / "targets" / target.directory
        if not _contained(root / "targets", target_root) or not target_root.is_dir():
            raise SafetyError(
                f"refusing to delete unsafe or missing target path: {target_root}"
            )
        staging = root / ".tacmux/deleting" / f"{target.id}-{os.getpid()}"
        if staging.exists():
            raise ConflictError(f"delete staging path already exists: {staging}")
        target_root.rename(staging)
        original_targets = engagement.targets
        engagement.targets = [
            item for item in engagement.targets if item.id != target_id
        ]
        try:
            self.save(root, engagement)
        except BaseException:
            engagement.targets = original_targets
            staging.rename(target_root)
            raise
        shutil.rmtree(staging)

    def delete_scope(self, root: Path, engagement: Engagement, scope_id: str) -> None:
        scope = engagement.scope_by_id(scope_id)
        references = [
            target.id
            for target in engagement.targets
            if any(address.scope_id == scope_id for address in target.addresses)
        ]
        if references:
            raise ConflictError("scope is used by target " + ", ".join(references))

        def mutate() -> None:
            engagement.scope = [
                item for item in engagement.scope if item.id != scope.id
            ]

        self._mutate_manifest(root, engagement, mutate)

    def delete_record(
        self, root: Path, engagement: Engagement, kind: str, record_id: str
    ) -> None:
        collections = {
            "access": engagement.access,
            "activity": engagement.activities,
            "finding": engagement.findings,
            "attack_path": engagement.attack_paths,
        }
        if kind not in collections:
            raise ValidationError(f"unknown record type: {kind}")
        collection = collections[kind]
        record = next((item for item in collection if item.id == record_id), None)
        if record is None:
            raise ValidationError(f"unknown {kind} record: {record_id}")
        references = [
            path.id
            for path in engagement.attack_paths
            if kind != "attack_path"
            and any(
                step.ref_type == kind and step.ref_id == record_id
                for step in path.steps
            )
        ]
        if references:
            raise ConflictError(
                f"{kind} {record_id} is used by attack path " + ", ".join(references)
            )

        staged_document = (
            self._stage_finding_document(root, record) if kind == "finding" else None
        )
        original = list(collection)
        collection[:] = [item for item in collection if item.id != record_id]
        try:
            self.save(root, engagement)
        except BaseException:
            collection[:] = original
            if staged_document is not None:
                staged_document[1].rename(staged_document[0])
            raise
        if staged_document is not None:
            staged_document[1].unlink(missing_ok=True)

    @staticmethod
    def _stage_finding_document(
        root: Path, finding: Finding
    ) -> tuple[Path, Path] | None:
        document = root / finding.document
        if not document.is_file() or not _contained(root, document):
            return None
        staging = root / ".tacmux/deleting" / f"{finding.id}-{os.getpid()}.md"
        if staging.exists():
            raise ConflictError(f"delete staging path already exists: {staging}")
        document.rename(staging)
        return document, staging

    @contextmanager
    def _state_lock(self) -> Iterator[None]:
        _private_directory(self.settings.state_file.parent)
        lock_path = self.settings.state_file.with_suffix(".lock")
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _read_state(self) -> dict[str, object]:
        try:
            with self.settings.state_file.open(encoding="utf-8") as stream:
                value = json.load(stream)
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(value, dict) or value.get("schema") != STATE_SCHEMA:
            return {}
        return value

    def _update_state(self, **changes: object) -> None:
        with self._state_lock():
            value = self._read_state()
            value.update(changes)
            value["schema"] = STATE_SCHEMA
            write_private_json(self.settings.state_file, value)

    def set_last_engagement(self, engagement_id: str) -> None:
        self._update_state(last_engagement_id=engagement_id)

    def get_last_engagement(self) -> str:
        value = self._read_state()
        return str(value.get("last_engagement_id", ""))

    def set_theme(self, theme_name: str) -> None:
        if not theme_name.strip():
            raise ValidationError("theme name is required")
        self._update_state(selected_theme=theme_name.strip())

    def get_theme(self) -> str:
        value = self._read_state().get("selected_theme", "")
        return value if isinstance(value, str) else ""
