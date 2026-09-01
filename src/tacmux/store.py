"""Private filesystem layout and atomic manifest persistence."""

from __future__ import annotations

from copy import deepcopy
from contextlib import contextmanager, suppress
from dataclasses import dataclass, fields
import fcntl
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
    Authorization,
    AttackPath,
    AttackPathStep,
    CleanupItem,
    CleanupKind,
    Engagement,
    EngagementStatus,
    Finding,
    FindingState,
    ScopeEntry,
    ScopeAvailability,
    ScopeGroup,
    Service,
    Severity,
    Target,
    TargetAddress,
    classify_scope,
    utc_now,
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


def write_private_text_if_changed(path: Path, text: str) -> bool:
    """Write private UTF-8 text only when its bytes would change."""

    try:
        if (
            path.is_file()
            and not path.is_symlink()
            and (path.stat().st_mode & 0o777) == 0o600
            and path.read_text(encoding="utf-8") == text
        ):
            return False
    except (FileNotFoundError, UnicodeError):
        pass
    write_private_text(path, text)
    return True


def write_private_bytes(path: Path, data: bytes, *, replace: bool = True) -> None:
    """Atomically write private bytes, optionally refusing an existing destination."""

    _private_directory(path.parent)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            try:
                os.link(temporary, path)
            except FileExistsError as exc:
                raise ConflictError(f"destination already exists: {path}") from exc
            os.unlink(temporary)
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


def contained_path(root: Path, path: Path) -> bool:
    """Return whether *path* stays below *root* without traversing links."""

    try:
        root_resolved = root.resolve(strict=True)
        path_absolute = Path(os.path.abspath(path))
        root_absolute = Path(os.path.abspath(root))
        relative = path_absolute.relative_to(root_absolute)
        current = root_absolute
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                return False
        resolved = path_absolute.resolve(strict=False)
        resolved.relative_to(root_resolved)
        return True
    except (OSError, ValueError):
        return False


def contained_regular_file(root: Path, path: Path) -> bool:
    """Return whether *path* is a regular, non-linked file below *root*."""

    return contained_path(root, path) and path.is_file()


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

    def catalog_engagements(
        self,
    ) -> tuple[list[EngagementRecord], list[tuple[Path, str]]]:
        if not self.settings.workspace.is_dir():
            return [], []
        records: list[EngagementRecord] = []
        problems: list[tuple[Path, str]] = []
        for manifest in self.settings.workspace.glob("E-*/.tacmux/engagement.json"):
            try:
                engagement = self.load(manifest.parent.parent)
            except (OSError, ValidationError, ValueError, KeyError, TypeError) as exc:
                problems.append((manifest, str(exc)))
                continue
            records.append(EngagementRecord(manifest.parent.parent, engagement))
        return (
            sorted(records, key=lambda item: item.engagement.created_at, reverse=True),
            sorted(problems, key=lambda item: str(item[0])),
        )

    def list_engagements(self) -> list[EngagementRecord]:
        records, _ = self.catalog_engagements()
        return records

    def invalid_engagements(self) -> list[tuple[Path, str]]:
        _, problems = self.catalog_engagements()
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
        initial_scope: Iterable[
            tuple[str, ScopeGroup, str, ScopeAvailability]
            | tuple[str, ScopeGroup, str, ScopeAvailability, list[str]]
        ] = (),
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
        for values in initial_scope:
            label, group, scope_value, availability, *extra = values
            engagement.add_scope(
                label,
                group,
                scope_value,
                availability,
                exclusions=extra[0] if extra else (),
            )
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
                self.render_documents(root, engagement)
            except BaseException:
                shutil.rmtree(root, ignore_errors=True)
                raise
        self.set_last_engagement(engagement.id)
        return EngagementRecord(root, engagement)

    def _seed_editable_documents(self, root: Path, engagement: Engagement) -> None:
        overview = f"""# Engagement — {engagement.client}: {engagement.name}

> Confirm written authorization, scope, rules of engagement, and retention
> requirements before testing.

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
            root / "findings/README.md",
            "# Findings\n\nFinding narratives are created through TACMUX and "
            "edited with `$EDITOR`.\n",
        )

    def _assert_current_revision(self, root: Path, engagement: Engagement) -> None:
        manifest = root / MANIFEST_RELATIVE
        if manifest.is_file() and self.load(root).revision != engagement.revision:
            raise ConflictError(
                "engagement changed in another TACMUX process; refresh and retry"
            )

    @staticmethod
    def require_active(engagement: Engagement) -> None:
        if engagement.status == EngagementStatus.CLOSED:
            raise ConflictError(
                "engagement is closed; reopen it before making changes"
            )

    def save(
        self,
        root: Path,
        engagement: Engagement,
        _lock_held: bool = False,
    ) -> None:
        if not _contained(self.settings.workspace, root):
            raise SafetyError(f"engagement is outside configured workspace: {root}")
        if _lock_held:
            self._save_locked(root, engagement)
            return
        with self.lock(root):
            self._save_locked(root, engagement)

    def _save_locked(self, root: Path, engagement: Engagement) -> None:
        engagement.normalize()
        engagement.validate()
        self._assert_current_revision(root, engagement)
        manifest = root / MANIFEST_RELATIVE
        previous_revision = engagement.revision
        engagement.revision += 1
        try:
            write_private_json(manifest, engagement.to_dict())
        except BaseException:
            engagement.revision = previous_revision
            raise

    def _mutate_manifest(
        self,
        root: Path,
        engagement: Engagement,
        mutation: Callable[[], MutationResult],
        *,
        allow_closed: bool = False,
    ) -> MutationResult:
        snapshot = deepcopy(engagement)
        try:
            with self.lock(root):
                self._assert_current_revision(root, engagement)
                if not allow_closed:
                    self.require_active(engagement)
                result = mutation()
                self.save(root, engagement, True)
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
        exclusions: Iterable[str] = (),
    ) -> ScopeEntry:
        return self._mutate_manifest(
            root,
            engagement,
            lambda: engagement.add_scope(
                label,
                group,
                network,
                availability,
                via_target_id,
                list(exclusions),
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
        exclusions: Iterable[str] = (),
    ) -> ScopeEntry:
        def mutate() -> ScopeEntry:
            scope = engagement.scope_by_id(scope_id)
            kind, stored_network, domain, normalized_exclusions = classify_scope(
                network, list(exclusions)
            )
            scope.label = label.strip() or stored_network or domain
            scope.group = group
            scope.kind = kind
            scope.network = stored_network
            scope.domain = domain
            scope.exclusions = normalized_exclusions
            scope.availability = availability
            scope.via_target_id = via_target_id
            if any(
                item.id != scope.id
                and item.group == scope.group
                and item.kind == scope.kind
                and item.spec == scope.spec
                for item in engagement.scope
            ):
                raise ValidationError(
                    f"scope already exists in {scope.group.value}: {scope.spec}"
                )
            return scope

        return self._mutate_manifest(root, engagement, mutate)

    def update_engagement_details(
        self,
        root: Path,
        engagement: Engagement,
        *,
        client: str,
        name: str,
        assessment_type: AssessmentType,
        logging_enabled: bool,
        authorization: Authorization,
    ) -> Engagement:
        def mutate() -> Engagement:
            engagement.client = client.strip()
            engagement.name = name.strip()
            engagement.assessment_type = assessment_type
            engagement.logging_enabled = logging_enabled
            engagement.authorization = authorization
            return engagement

        return self._mutate_manifest(root, engagement, mutate)

    def set_status(
        self,
        root: Path,
        engagement: Engagement,
        status: EngagementStatus,
    ) -> Engagement:
        def mutate() -> Engagement:
            engagement.status = status
            return engagement

        return self._mutate_manifest(
            root, engagement, mutate, allow_closed=True
        )

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
                target.primary_endpoint = self._fallback_primary(
                    engagement, target
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
                target.primary_endpoint = self._fallback_primary(
                    engagement, target
                )
            return target

        return self._mutate_manifest(root, engagement, mutate)

    @staticmethod
    def _fallback_primary(engagement: Engagement, target: Target) -> str:
        if target.addresses:
            return target.addresses[0].value
        return next(
            (
                hostname
                for hostname in target.hostnames
                if not engagement.domain_entries
                or engagement.hostname_scope(hostname)
            ),
            "",
        )

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

    def create_cleanup_item(
        self,
        root: Path,
        engagement: Engagement,
        *,
        target_id: str,
        kind: CleanupKind,
        location: str,
        sha256: str = "",
        note: str = "",
    ) -> CleanupItem:
        def mutate() -> CleanupItem:
            item = CleanupItem(
                id=engagement.next_id("cleanup", "C"),
                target_id=target_id,
                kind=kind,
                location=location.strip(),
                sha256=sha256.strip().casefold(),
                note=note.strip(),
            )
            engagement.cleanup.append(item)
            return item

        return self._mutate_manifest(root, engagement, mutate)

    def mark_cleanup_removed(
        self,
        root: Path,
        engagement: Engagement,
        item_id: str,
    ) -> CleanupItem:
        def mutate() -> CleanupItem:
            item = next(
                (value for value in engagement.cleanup if value.id == item_id), None
            )
            if item is None:
                raise ValidationError(f"unknown cleanup item: {item_id}")
            if not item.removed_at:
                item.removed_at = utc_now()
            return item

        return self._mutate_manifest(root, engagement, mutate)

    def clear_services(
        self,
        root: Path,
        engagement: Engagement,
        target_id: str,
    ) -> Target:
        def mutate() -> Target:
            target = engagement.target_by_id(target_id)
            target.services.clear()
            return target

        return self._mutate_manifest(root, engagement, mutate)

    def append_note(
        self,
        record: EngagementRecord,
        target: Target | None,
        text: str,
    ) -> Path:
        if not text.strip():
            raise ValidationError("note text is required")
        with self.lock(record.root):
            current = self.load(record.root)
            self.require_active(current)
            self._assert_current_revision(record.root, record.engagement)
            if target is None:
                path = record.root / "ENGAGEMENT.md"
                heading = "## Operator Notes"
            else:
                current_target = current.target_by_id(target.id)
                path = (
                    record.root
                    / "targets"
                    / current_target.directory
                    / "NOTES.md"
                )
                heading = "## Notes"
            if not _contained(record.root, path):
                raise SafetyError(f"unsafe note path: {path}")
            content = path.read_text(encoding="utf-8")
            if heading not in content:
                raise ValidationError(f"note file is missing {heading}: {path}")
            line = f"- {utc_now()} — {text.strip()}\n"
            prefix, marker, remainder = content.partition(heading)
            boundary = len(remainder)
            for token in ("\n## ", "\n---"):
                index = remainder.find(token)
                if index >= 0:
                    boundary = min(boundary, index)
            notes, suffix = remainder[:boundary], remainder[boundary:]
            notes = notes.rstrip() + "\n" if notes.strip() else "\n"
            write_private_text(path, prefix + marker + notes + line + suffix)
        return path

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
    ) -> AccessRecord | Activity | Finding | AttackPath | CleanupItem:
        collections = {
            "access": engagement.access,
            "activity": engagement.activities,
            "finding": engagement.findings,
            "attack_path": engagement.attack_paths,
            "cleanup": engagement.cleanup,
        }

        def mutate() -> AccessRecord | Activity | Finding | AttackPath | CleanupItem:
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
                "cleanup": ("target_id", "kind", "location", "sha256", "note", "removed_at"),
            }
            if kind == "attack_path":
                record.name = value["name"]
                record.steps = [AttackPathStep(*item) for item in value["steps"]]
            else:
                for name in names[kind]:
                    setattr(record, name, value[name])
            return record

        return self._mutate_manifest(root, engagement, mutate)

    def render_documents(
        self,
        root: Path,
        engagement: Engagement,
        *,
        live_target_ids: set[str] | None = None,
        jobs: list[dict] | None = None,
    ) -> int:
        with self.lock(root):
            self._assert_current_revision(root, engagement)
            write_private_text_if_changed(
                root / "notes/activity.md", render_activity_markdown(engagement)
            )
            write_private_text_if_changed(
                root / "notes/attack-path.md",
                render_attack_path_markdown(engagement),
            )
            write_private_text_if_changed(
                root / "SITREP.md",
                render_sitrep(
                    engagement,
                    live_sessions=live_target_ids or set(),
                    jobs=jobs or [],
                    include_mermaid=self.settings.include_mermaid,
                    warnings=self.missing_evidence(root, engagement),
                ),
            )
            return (root / MANIFEST_RELATIVE).stat().st_mtime_ns

    def missing_evidence(self, root: Path, engagement: Engagement) -> list[str]:
        references: list[tuple[str, str, str]] = []
        references.extend(
            ("access", item.id, item.evidence)
            for item in engagement.access
            if item.evidence
        )
        references.extend(
            ("activity", item.id, item.evidence)
            for item in engagement.activities
            if item.evidence
        )
        references.extend(
            ("finding", item.id, reference)
            for item in engagement.findings
            for reference in item.evidence
        )
        references.extend(
            ("service", target.id, service.source)
            for target in engagement.targets
            for service in target.services
            if service.source
        )
        return [
            f"{kind} {item_id} references missing evidence: {reference}"
            for kind, item_id, reference in references
            if not contained_regular_file(root, root / reference)
        ]

    def create_target(
        self,
        root: Path,
        engagement: Engagement,
        display_name: str,
        *,
        addresses: list[TargetAddress] | None = None,
        hostnames: list[str] | None = None,
        primary_endpoint: str = "",
        services: list[Service] | None = None,
    ) -> Target:
        self.require_active(engagement)
        snapshot = deepcopy(engagement)
        target: Target | None = None
        try:
            with self.lock(root):
                self._assert_current_revision(root, engagement)
                target = self.stage_target(
                    root,
                    engagement,
                    display_name,
                    addresses=addresses,
                    hostnames=hostnames,
                    primary_endpoint=primary_endpoint,
                    services=services,
                )
                self.save(root, engagement, True)
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
        services: list[Service] | None = None,
    ) -> Target:
        """Prepare one target for a caller that will commit the engagement once."""

        self.require_active(engagement)
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
            services=list(services or []),
        )
        target_root = root / "targets" / directory
        if not _contained(root, target_root) or target_root.exists():
            raise SafetyError(f"unsafe or existing target directory: {target_root}")
        _private_directory(target_root)
        try:
            for phase in TARGET_PHASES:
                _private_directory(target_root / phase)
            note_text = (
                f"# {target.display_name}\n\n"
                f"- Target ID: `{target.id}`\n"
                f"- Created: {target.created_at}\n\n"
                "## Notes\n\n-\n"
            )
            write_private_text(target_root / "NOTES.md", note_text)
            engagement.targets.append(target)
            engagement.normalize()
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
    ) -> str:
        self.require_active(engagement)
        if not name.strip():
            raise ValidationError("target display name is required")
        snapshot = deepcopy(engagement)
        try:
            with self.lock(root):
                self._assert_current_revision(root, engagement)
                target = engagement.target_by_id(target_id)
                target.display_name = name.strip()
                self.save(root, engagement, True)
                notes = root / "targets" / target.directory / "NOTES.md"
                try:
                    content = notes.read_text(encoding="utf-8")
                    _, separator, remainder = content.partition("\n")
                    write_private_text(
                        notes, f"# {target.display_name}{separator}{remainder}"
                    )
                except (OSError, UnicodeError) as exc:
                    return (
                        "Target renamed, but its NOTES.md heading could not be "
                        f"updated: {exc}"
                    )
        except BaseException:
            restore_engagement_state(engagement, snapshot)
            raise
        return ""

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
        self.require_active(engagement)
        snapshot = deepcopy(engagement)
        finding: Finding | None = None
        finding_path: Path | None = None
        document_created = False
        try:
            with self.lock(root):
                self._assert_current_revision(root, engagement)
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
                engagement.validate()
                if finding_path.exists():
                    raise ConflictError(
                        f"finding document already exists: {finding_path}"
                    )
                write_private_text(
                    finding_path,
                    f"# {title.strip()}\n\n"
                    f"- **ID:** `{finding_id}`\n"
                    f"- **Severity:** {severity.value}\n"
                    f"- **State:** {state.value}\n"
                    f"- **Created UTC:** {finding.created_at}\n\n"
                    "## Summary\n\n\n"
                    "## Evidence\n\n\n"
                    "## Impact\n\n\n"
                    "## Recommendation\n\n\n",
                )
                document_created = True
                self.save(root, engagement, True)
        except BaseException:
            restore_engagement_state(engagement, snapshot)
            if finding_path is not None and document_created:
                finding_path.unlink(missing_ok=True)
            raise
        assert finding is not None
        return finding

    def sync_finding_document(self, root: Path, finding: Finding) -> None:
        self.require_active(self.load(root))
        path = root / finding.document
        if not _contained(root, path) or not path.is_file():
            raise SafetyError(f"finding document is missing or unsafe: {path}")
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeError as exc:
            raise ValidationError(
                f"finding document is not valid UTF-8: {finding.document}"
            ) from exc
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
            f"- **State:** {finding.state.value}\n"
            f"- **Created UTC:** {finding.created_at or '—'}\n\n"
        )
        write_private_text(path, header + marker + narrative)

    def delete_target(self, root: Path, engagement: Engagement, target_id: str) -> None:
        self.require_active(engagement)
        staging: Path | None = None
        target_root: Path | None = None
        snapshot = deepcopy(engagement)
        with self.lock(root):
            self._assert_current_revision(root, engagement)
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
            staging = root / ".tacmux/deleting" / (
                f"{target.id}-{os.getpid()}-{secrets.token_hex(4)}"
            )
            if staging.exists():
                raise ConflictError(f"delete staging path already exists: {staging}")
            target_root.rename(staging)
            engagement.targets = [
                item for item in engagement.targets if item.id != target_id
            ]
            try:
                self.save(root, engagement, True)
            except BaseException:
                restore_engagement_state(engagement, snapshot)
                staging.rename(target_root)
                raise
        assert staging is not None
        try:
            shutil.rmtree(staging)
            _fsync_directory(staging.parent)
        except OSError as exc:
            if staging.exists():
                raise SafetyError(
                    "target was removed from the engagement, but filesystem cleanup "
                    f"is incomplete at {staging}: {exc}"
                ) from exc
            raise SafetyError(
                f"target was deleted, but final directory sync failed: {exc}"
            ) from exc

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
        self.require_active(engagement)
        snapshot = deepcopy(engagement)
        staged_document: tuple[Path, Path] | None = None
        try:
            with self.lock(root):
                self._assert_current_revision(root, engagement)
                collections = {
                    "access": engagement.access,
                    "activity": engagement.activities,
                    "finding": engagement.findings,
                    "attack_path": engagement.attack_paths,
                    "cleanup": engagement.cleanup,
                }
                if kind not in collections:
                    raise ValidationError(f"unknown record type: {kind}")
                collection = collections[kind]
                record = next(
                    (item for item in collection if item.id == record_id), None
                )
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
                        f"{kind} {record_id} is used by attack path "
                        + ", ".join(references)
                    )
                staged_document = (
                    self._stage_finding_document(root, record)
                    if kind == "finding"
                    else None
                )
                collection[:] = [item for item in collection if item.id != record_id]
                self.save(root, engagement, True)
        except BaseException:
            restore_engagement_state(engagement, snapshot)
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
        staging = root / ".tacmux/deleting" / (
            f"{finding.id}-{os.getpid()}-{secrets.token_hex(4)}.md"
        )
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
