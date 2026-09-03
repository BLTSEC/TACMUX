"""Filesystem-backed engagement operations with SITREP as the source of truth."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Callable, Iterator, Sequence

from .config import Settings
from .errors import ConflictError, ExternalToolError, SafetyError, ValidationError
from . import sitrep


TARGET_DIRECTORIES = ("scans", "payloads", "loot", "screenshots", "working")
OUTCOMES = ("info", "success", "partial", "failed")
TARGET_STATUSES = ("new", "active", "blocked", "complete")
ACCESS_LEVELS = ("none", "authenticated", "user", "admin", "system", "domain")
IMAGE_LIMIT = 25 * 1024 * 1024
IMAGE_SUFFIXES = {".gif", ".jpeg", ".jpg", ".png", ".webp"}


@dataclass(slots=True, frozen=True)
class CaptureRecord:
    identifier: str
    status: str
    tool: str
    path: str
    command: str


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def validate_name(value: str, kind: str = "name") -> str:
    result = value.strip()
    if not result:
        raise ValidationError(f"{kind} cannot be empty")
    if result in {".", ".."} or "/" in result or "\0" in result:
        raise ValidationError(f"{kind} cannot contain path separators")
    if any(ord(character) < 32 or ord(character) == 127 for character in result):
        raise ValidationError(f"{kind} cannot contain control characters")
    if len(result) > 80:
        raise ValidationError(f"{kind} cannot exceed 80 characters")
    return result


def validate_value(value: str, field: str, *, required: bool = True) -> str:
    result = value.strip()
    if required and not result:
        raise ValidationError(f"{field} cannot be empty")
    if "\0" in result or "\n" in result or "\r" in result:
        raise ValidationError(f"{field} must be a single line")
    return result


def validate_confirmation_component(value: str, field: str) -> str:
    result = validate_value(value, field)
    if ";" in result or "·" in result:
        raise ValidationError(f"{field} cannot contain ';' or '·'")
    return result


def validate_target_name(value: str) -> str:
    return validate_confirmation_component(
        validate_name(value, "target name"), "target name"
    )


def _private_directory(path: Path) -> None:
    if path.exists() and path.is_symlink():
        raise SafetyError(f"refusing linked directory: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)


def _atomic_write(path: Path, text: str) -> None:
    _private_directory(path.parent)
    if path.exists() and path.is_symlink():
        raise SafetyError(f"refusing linked file: {path}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


class Workspace:
    def __init__(self, settings: Settings):
        self.settings = settings

    def initialize(self) -> None:
        _private_directory(self.settings.workspace)

    def _configured_sitrep(self, root: Path) -> Path:
        if self.settings.sitrep_root is None:
            raise SafetyError("external SITREP requires paths.sitrep_root")
        notes_root = self.settings.sitrep_root
        if not notes_root.is_dir() or notes_root.is_symlink():
            raise SafetyError(
                f"configured SITREP root is missing or linked: {notes_root}"
            )
        expected = notes_root / root.name / "SITREP.md"
        try:
            expected.resolve(strict=False).relative_to(notes_root.resolve(strict=True))
        except (OSError, ValueError) as exc:
            raise SafetyError(
                f"external SITREP escapes configured root: {expected}"
            ) from exc
        return expected

    def _resolve_sitrep(self, root: Path, *, require_exists: bool = True) -> Path:
        link = root / "SITREP.md"
        if link.is_symlink():
            expected = self._configured_sitrep(root)
            try:
                actual = link.resolve(strict=require_exists)
            except OSError as exc:
                raise SafetyError(f"cannot resolve linked SITREP: {link}") from exc
            if actual != expected.resolve(strict=require_exists):
                raise SafetyError(
                    f"linked SITREP has an unexpected destination: {link}"
                )
            if expected.is_symlink():
                raise SafetyError(f"refusing linked external SITREP: {expected}")
            path = expected
        else:
            path = self._contained(root, "SITREP.md")
        if require_exists and (not path.is_file() or path.is_symlink()):
            raise ValidationError(f"SITREP is missing or unsafe: {path}")
        return path

    def _contained(self, root: Path, *parts: str) -> Path:
        base = root.resolve(strict=True)
        candidate = root.joinpath(*parts)
        current = root
        for part in parts:
            current /= part
            if current.exists() and current.is_symlink():
                raise SafetyError(f"refusing linked TACMUX path: {current}")
        try:
            candidate.resolve(strict=False).relative_to(base)
        except (OSError, ValueError) as exc:
            raise SafetyError(f"path escapes engagement: {candidate}") from exc
        return candidate

    def is_engagement(self, root: Path) -> bool:
        if not (
            root.is_dir()
            and not root.is_symlink()
            and (root / ".tacmux/version").is_file()
            and (root / "SITREP.md").is_file()
        ):
            return False
        try:
            self._resolve_sitrep(root)
        except (SafetyError, ValidationError, OSError):
            return False
        return True

    def engagements(self) -> list[Path]:
        self.initialize()
        return sorted(
            (
                child
                for child in self.settings.workspace.iterdir()
                if self.is_engagement(child)
            ),
            key=lambda path: path.name.casefold(),
        )

    def create_engagement(self, name: str) -> Path:
        name = validate_name(name, "engagement name")
        self.initialize()
        root = self._contained(self.settings.workspace, name)
        if root.exists():
            if self.is_engagement(root):
                return root
            raise ConflictError(
                f"directory exists but is not a TACMUX engagement: {root}"
            )
        root.mkdir(mode=0o700)
        external_directory: Path | None = None
        external_created = False
        try:
            for relative in (
                ".tacmux",
                "credentials",
                "credentials/keys",
                "captures",
                "captures/.nocap",
                "captures/ops",
                "logs",
                "targets",
            ):
                _private_directory(root / relative)
            _atomic_write(root / ".tacmux/version", "3\n")
            document = sitrep.initial_document(name)
            if self.settings.sitrep_root is None:
                _atomic_write(root / "SITREP.md", document)
            else:
                destination = self._configured_sitrep(root)
                external_directory = destination.parent
                if external_directory.exists():
                    raise ConflictError(
                        f"external engagement notes already exist: {external_directory}"
                    )
                external_directory.mkdir(mode=0o700)
                external_created = True
                _atomic_write(destination, document)
                os.symlink(destination, root / "SITREP.md")
            self._sync_credentials(root, document)
        except BaseException:
            shutil.rmtree(root, ignore_errors=True)
            if external_directory is not None and external_created:
                shutil.rmtree(external_directory, ignore_errors=True)
            raise
        return root

    def find_root(self, path: Path) -> Path | None:
        candidate = path.resolve(strict=False)
        for parent in (candidate, *candidate.parents):
            if self.is_engagement(parent):
                return parent
        return None

    def targets(self, root: Path) -> list[str]:
        self.require_engagement(root)
        target_root = self._contained(root, "targets")
        return sorted(
            (
                child.name
                for child in target_root.iterdir()
                if child.is_dir() and not child.is_symlink()
            ),
            key=str.casefold,
        )

    def require_engagement(self, root: Path) -> None:
        if not self.is_engagement(root):
            raise ValidationError(f"not a TACMUX v3 engagement: {root}")
        _private_directory(self._contained(root, "credentials", "keys"))

    def sitrep_path(self, root: Path) -> Path:
        self.require_engagement(root)
        return self._resolve_sitrep(root)

    def read(self, root: Path) -> str:
        path = self.sitrep_path(root)
        try:
            return path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ValidationError(f"cannot read {path}: {exc}") from exc

    @contextmanager
    def locked(self, root: Path) -> Iterator[None]:
        self.require_engagement(root)
        lock_path = self._contained(root, ".tacmux", "lock")
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def mutate(self, root: Path, operation: Callable[[str], str]) -> str:
        with self.locked(root):
            previous = self.read(root)
            updated = operation(previous)
            return self._commit(root, previous, updated)

    def _commit(
        self,
        root: Path,
        previous: str,
        updated: str,
        *,
        allow_reference_problems: bool = False,
    ) -> str:
        if not updated.endswith("\n"):
            updated += "\n"
        updated = sitrep.normalize_document(updated)
        problems = self.validate(root, updated)
        if problems and not allow_reference_problems:
            raise ValidationError("; ".join(problems))
        path = self.sitrep_path(root)
        try:
            current = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ValidationError(f"cannot re-read {path}: {exc}") from exc
        if current != previous:
            raise ConflictError("SITREP changed in another editor; retry the command")
        if updated != previous:
            _atomic_write(path, updated)
        os.chmod(path, 0o600)
        self._sync_credentials(root, updated)
        return updated

    def _target_path(self, root: Path, target: str) -> Path:
        target = validate_target_name(target)
        return self._contained(root, "targets", target)

    def target_exists(self, root: Path, target: str) -> bool:
        return target.casefold() in {name.casefold() for name in self.targets(root)}

    def canonical_target(self, root: Path, target: str) -> str:
        matches = [
            name for name in self.targets(root) if name.casefold() == target.casefold()
        ]
        if not matches:
            raise ValidationError(f"unknown target: {target}")
        return matches[0]

    def add_target(self, root: Path, name: str, endpoint: str) -> str:
        name = validate_target_name(name)
        if name.casefold() in {"engagement", "ops"}:
            raise ValidationError(f"reserved target name: {name}")
        endpoint = validate_value(endpoint, "endpoint")
        with self.locked(root):
            existing = self.targets(root)
            if name.casefold() in {value.casefold() for value in existing}:
                raise ConflictError(f"target already exists: {name}")
            path = self._target_path(root, name)
            path.mkdir(mode=0o700)
            try:
                for directory in TARGET_DIRECTORIES:
                    _private_directory(path / directory)
                previous = self.read(root)
                updated = sitrep.add_target(previous, name, endpoint)
                self._commit(root, previous, updated)
            except BaseException:
                shutil.rmtree(path, ignore_errors=True)
                raise
        return name

    def target_details(self, root: Path, target: str) -> dict[str, tuple[str, str]]:
        target = self.canonical_target(root, target)
        return sitrep.details_map(self.read(root), target)

    def write_target_list(
        self, root: Path, selected: Sequence[str]
    ) -> tuple[Path, int]:
        with self.locked(root):
            available = {name.casefold(): name for name in self.targets(root)}
            targets: list[str] = []
            for value in selected:
                target = available.get(value.casefold())
                if target is None:
                    raise ValidationError(f"unknown target: {value}")
                if target not in targets:
                    targets.append(target)
            document = self.read(root)
            endpoints = list(
                dict.fromkeys(
                    sitrep.details_map(document, target)["Endpoint"][0]
                    for target in targets
                )
            )
            path = self._contained(root, "targets.txt")
            _atomic_write(path, "".join(f"{endpoint}\n" for endpoint in endpoints))
            return path, len(endpoints)

    def set_target_detail(
        self, root: Path, target: str, field: str, value: str, notes: str | None = None
    ) -> None:
        target = self.canonical_target(root, target)
        value = validate_value(value, field, required=False)
        if field == "Status" and value not in TARGET_STATUSES:
            raise ValidationError("status must be new, active, blocked, or complete")
        self.mutate(
            root, lambda text: sitrep.set_detail(text, target, field, value, notes)
        )

    def rename_target(self, root: Path, old: str, new: str) -> str:
        old = self.canonical_target(root, old)
        new = validate_target_name(new)
        if new.casefold() in {"engagement", "ops"}:
            raise ValidationError(f"reserved target name: {new}")
        if new.casefold() in {
            name.casefold()
            for name in self.targets(root)
            if name.casefold() != old.casefold()
        }:
            raise ConflictError(f"target already exists: {new}")
        with self.locked(root):
            old_path = self._target_path(root, old)
            new_path = self._target_path(root, new)
            text = self.read(root)
            details = sitrep.details_map(text, old)
            route = details["Capture Route"][0]
            capture_path = self._contained(root, "captures", route) if route else None
            route_has_files = bool(
                capture_path
                and capture_path.exists()
                and any(path.is_file() for path in capture_path.rglob("*"))
            )
            capture_renamed = False
            old_capture: Path | None = None
            new_capture: Path | None = None
            old_path.rename(new_path)
            try:
                updated = sitrep.rename_target(text, old, new)
                if not route_has_files and route == old:
                    updated = sitrep.set_detail(updated, new, "Capture Route", new)
                    old_capture = self._contained(root, "captures", old)
                    new_capture = self._contained(root, "captures", new)
                    if old_capture.exists():
                        if new_capture.exists():
                            raise ConflictError(
                                "capture route already exists for renamed target: "
                                f"{new_capture}"
                            )
                        old_capture.rename(new_capture)
                        capture_renamed = True
                self._commit(root, text, updated)
            except BaseException:
                if capture_renamed and old_capture and new_capture:
                    new_capture.rename(old_capture)
                new_path.rename(old_path)
                raise
        return new

    def deletion_references(self, root: Path, target: str) -> list[str]:
        target = self.canonical_target(root, target)
        text = self.read(root)
        references: list[str] = []
        if any(event.target == target for event in sitrep.read_events(text)):
            references.append("operations log events")
        if any(task.target == target for task in sitrep.read_tasks(text, "TODO")):
            references.append("TODO items")
        if any(task.target == target for task in sitrep.read_tasks(text, "CLEANUP")):
            references.append("cleanup items")
        if any(
            confirmation_target == target
            for row in sitrep.read_global(text, "CREDENTIALS")
            for confirmation_target, _service, _access in sitrep.parse_confirmed_access(
                row[5]
            )
        ):
            references.append("confirmed credentials")
        if sitrep.read_target(text, target, "PORTS"):
            references.append("port records")
        route = sitrep.details_map(text, target)["Capture Route"][0]
        if route:
            capture = self._contained(root, "captures", route)
            if capture.exists() and any(path.is_file() for path in capture.rglob("*")):
                references.append("NOCAP captures")
        return references

    def delete_target(self, root: Path, target: str) -> None:
        target = self.canonical_target(root, target)
        with self.locked(root):
            references = self.deletion_references(root, target)
            if references:
                raise ConflictError(
                    f"cannot delete {target}; clear its " + ", ".join(references)
                )
            path = self._target_path(root, target)
            deleting = self._contained(root, ".tacmux", "deleting")
            _private_directory(deleting)
            staged = deleting / f"{target}-{os.getpid()}"
            path.rename(staged)
            try:
                previous = self.read(root)
                updated = sitrep.remove_target(previous, target)
                self._commit(root, previous, updated)
            except BaseException:
                staged.rename(path)
                raise
            try:
                shutil.rmtree(staged)
            except OSError as exc:
                raise SafetyError(
                    f"target was removed but staged data remains at {staged}: {exc}"
                ) from exc

    def add_event(
        self,
        root: Path,
        target: str,
        outcome: str,
        summary: str,
        notes: str = "",
        *,
        capture: CaptureRecord | None = None,
        images: Sequence[Path] = (),
    ) -> str:
        if target != "ENGAGEMENT":
            target = self.canonical_target(root, target)
        if outcome not in OUTCOMES:
            raise ValidationError("outcome must be info, success, partial, or failed")
        summary = validate_value(summary, "summary")
        notes = validate_value(notes, "notes", required=False)
        image_sources = [self._validate_image(path) for path in images]
        created_images: list[Path] = []
        identifier = ""
        with self.locked(root):
            previous = self.read(root)
            events = sitrep.read_events(previous)
            if capture and any(
                event.capture_id == capture.identifier for event in events
            ):
                raise ConflictError(
                    f"capture is already attached: {capture.identifier}"
                )
            identifier = sitrep.next_event_id(events)
            try:
                image_links = [
                    self._copy_event_image(root, source, created_images)
                    for source in image_sources
                ]
                body = self._event_body(summary, notes, capture, image_links)
                event = sitrep.Event(
                    identifier,
                    utc_now(),
                    target,
                    outcome,
                    summary,
                    capture.identifier if capture else "",
                    body,
                )
                self._commit(root, previous, sitrep.append_event(previous, event))
            except BaseException:
                for path in created_images:
                    path.unlink(missing_ok=True)
                raise
        return identifier

    @staticmethod
    def _validate_image(path: Path) -> Path:
        source = path.expanduser()
        if source.is_symlink() or not source.is_file():
            raise ValidationError(f"image is missing or unsafe: {source}")
        if re.search(r'[\x00-\x1f\x7f\\<>#?%]', source.name):
            raise ValidationError(
                "image filename cannot contain control characters, \\, <, >, #, ?, or %"
            )
        size = source.stat().st_size
        if not 0 < size <= IMAGE_LIMIT:
            raise ValidationError(
                f"image must be between 1 byte and {IMAGE_LIMIT} bytes"
            )
        if source.suffix.casefold() not in IMAGE_SUFFIXES:
            raise ValidationError(f"unsupported image type: {source.suffix or '-'}")
        try:
            with source.open("rb") as stream:
                header = stream.read(12)
        except OSError as exc:
            raise ValidationError(f"cannot read image {source}: {exc}") from exc
        valid = (
            header.startswith(b"\x89PNG\r\n\x1a\n")
            or header.startswith(b"\xff\xd8\xff")
            or header.startswith((b"GIF87a", b"GIF89a"))
            or (header.startswith(b"RIFF") and header[8:12] == b"WEBP")
        )
        if not valid:
            raise ValidationError(
                f"file does not match a supported image format: {source}"
            )
        return source

    def _copy_event_image(
        self, root: Path, source: Path, created: list[Path]
    ) -> str:
        directory = self.sitrep_path(root).parent / "images"
        _private_directory(directory)
        destination = directory / source.name
        counter = 2
        while destination.exists() or destination.is_symlink():
            destination = directory / f"{source.stem}-{counter}{source.suffix.lower()}"
            counter += 1
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", dir=directory
        )
        temporary = Path(temporary_name)
        try:
            os.close(descriptor)
            shutil.copyfile(source, temporary)
            os.chmod(temporary, 0o600)
            with temporary.open("rb") as stream:
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
            directory_descriptor = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
            created.append(destination)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        return f"images/{destination.name}"

    @staticmethod
    def _fenced_command(command: str) -> str:
        longest = max((len(run) for run in re.findall(r"`+", command)), default=0)
        fence = "`" * max(3, longest + 1)
        return f"{fence}bash\n{command}\n{fence}"

    def _event_body(
        self,
        summary: str,
        notes: str,
        capture: CaptureRecord | None,
        images: Sequence[str],
    ) -> str:
        sections: list[str] = []
        if capture:
            sections.append(
                "#### Evidence\n\n"
                f"- **Status:** {capture.status}\n"
                f"- **Tool:** {capture.tool}\n"
                f"- **Path:** captures/{capture.path}\n\n"
                "#### Command\n\n"
                f"{self._fenced_command(capture.command)}"
            )
        if capture or images:
            if images:
                alt = summary.replace("\\", "\\\\").replace("]", "\\]")
                rendered = "\n\n".join(
                    f"![{alt}](<{path}>)\n\n**Caption:** {summary}"
                    for path in images
                )
            else:
                rendered = (
                    "**Image:** _Not attached._\n\n"
                    f"**Caption:** _Evidence supporting: {summary}._"
                )
            sections.append(f"#### Screenshots\n\n{rendered}")
            sections.append("#### Draft findings\n\n_None recorded._")
        if notes or capture or images:
            sections.append(
                "#### Notes\n\n"
                + (notes if notes else "_Add supporting context here._")
            )
        return "\n\n".join(sections)

    def inspect_capture(self, root: Path, target: str) -> CaptureRecord:
        binary = shutil.which("cap")
        if binary is None:
            raise ExternalToolError("cap is required for --capture")
        route = "ops"
        if target != "ENGAGEMENT":
            target = self.canonical_target(root, target)
            route = self.target_details(root, target)["Capture Route"][0]
        environment = os.environ | {
            "NOCAP_WORKSPACE": str(root),
            "TACMUX_TARGET": "captures",
            "NOCAP_ROUTE_PREFIX": route,
        }
        try:
            result = subprocess.run(
                [binary, "inspect", "--json"],
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ExternalToolError(
                f"cannot inspect latest NOCAP capture: {exc}"
            ) from exc
        if result.returncode:
            raise ExternalToolError(
                (result.stderr or "NOCAP has no retained capture").strip()
            )
        try:
            value = json.loads(result.stdout)["capture"]
            record = CaptureRecord(
                validate_value(value["id"], "capture ID"),
                validate_value(value["status"], "capture status"),
                validate_value(value.get("effective_tool", "unknown"), "capture tool"),
                validate_value(value["path"], "capture path"),
                validate_value(
                    value.get("command", ""),
                    "capture command",
                    required=False,
                ),
            )
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ExternalToolError("cap inspect returned invalid JSON") from exc
        if record.status in {"deleted", "deleting", "running"}:
            raise ValidationError(
                f"capture is not retained and finished: {record.status}"
            )
        relative = Path(record.path)
        if relative.is_absolute() or ".." in relative.parts:
            raise SafetyError(f"capture path is unsafe: {record.path}")
        evidence = self._contained(root, "captures", *relative.parts)
        if evidence.is_symlink() or not evidence.is_file():
            raise ValidationError(f"capture evidence is missing: {record.path}")
        expected = route.rstrip("/") + "/"
        if not record.path.startswith(expected):
            raise ValidationError(
                f"latest capture belongs to another route: {record.path}"
            )
        return record

    def add_credential(
        self,
        root: Path,
        principal: str,
        secret: str,
        secret_type: str,
        source: str = "",
        notes: str = "",
    ) -> str:
        principal = validate_value(principal, "principal")
        secret = validate_value(secret, "secret")
        secret_type = secret_type.casefold()
        if secret_type not in {"password", "hash"}:
            raise ValidationError("credential type must be password or hash")

        created: list[str] = []

        def operation(text: str) -> str:
            rows = sitrep.read_global(text, "CREDENTIALS")
            for row in rows:
                if row[1] == principal and row[2] == secret_type and row[3] == secret:
                    raise ConflictError(f"credential already exists: {row[0]}")
            identifier = sitrep.next_id(rows, "C")
            created.append(identifier)
            rows.append(
                [
                    identifier,
                    principal,
                    secret_type,
                    secret,
                    source,
                    "",
                    utc_now(),
                    "",
                    notes,
                ]
            )
            return sitrep.write_global(text, "CREDENTIALS", rows)

        self.mutate(root, operation)
        return created[0]

    def confirm_credential(
        self,
        root: Path,
        credential: str,
        target: str,
        access: str,
        service: str,
        notes: str = "",
    ) -> None:
        target = self.canonical_target(root, target)
        validate_confirmation_component(target, "target name")
        access = access.casefold()
        if access not in ACCESS_LEVELS or access == "none":
            raise ValidationError(
                "confirmed access must be authenticated, user, admin, system, or domain"
            )
        service = validate_confirmation_component(service, "service")
        notes = validate_value(notes, "notes", required=False)

        def operation(text: str) -> str:
            credentials = sitrep.read_global(text, "CREDENTIALS")
            match = next((row for row in credentials if row[0] == credential), None)
            if match is None:
                raise ValidationError(f"unknown credential: {credential}")
            entries = sitrep.parse_confirmed_access(match[5])
            key = (target.casefold(), service.casefold())
            replacement = (target, service, access)
            for index, entry in enumerate(entries):
                if (entry[0].casefold(), entry[1].casefold()) == key:
                    entries[index] = replacement
                    break
            else:
                entries.append(replacement)
            match[5] = sitrep.render_confirmed_access(entries)
            match[7] = utc_now()
            if notes:
                tagged = f"[{target} / {service}] {notes}"
                match[8] = f"{match[8]}; {tagged}" if match[8] else tagged
            updated = sitrep.write_global(text, "CREDENTIALS", credentials)
            current_access = sitrep.details_map(updated, target)["Access"][0]
            if ACCESS_LEVELS.index(access) > ACCESS_LEVELS.index(current_access):
                updated = sitrep.set_detail(updated, target, "Access", access)
                updated = sitrep.set_detail(updated, target, "Principal", match[1])
                updated = sitrep.set_detail(
                    updated,
                    target,
                    "Method/Path",
                    f"Credential {credential} via {service}",
                )
            return updated

        self.mutate(root, operation)

    def add_task(self, root: Path, target: str, task: str, notes: str = "") -> str:
        if target != "ENGAGEMENT":
            target = self.canonical_target(root, target)
        task = validate_value(task, "task")
        created: list[str] = []

        def operation(text: str) -> str:
            tasks = sitrep.read_tasks(text, "TODO")
            identifier = sitrep.next_id(
                [[value.identifier] for value in tasks], "T"
            )
            created.append(identifier)
            tasks.append(sitrep.Task(identifier, target, task, utc_now(), notes=notes))
            return sitrep.write_tasks(text, "TODO", tasks)

        self.mutate(root, operation)
        return created[0]

    def complete_task(self, root: Path, identifier: str) -> None:
        self._set_task_completion(root, "TODO", identifier, complete=True)

    def reopen_task(self, root: Path, identifier: str) -> None:
        self._set_task_completion(root, "TODO", identifier, complete=False)

    def add_cleanup(self, root: Path, target: str, item: str, notes: str = "") -> str:
        if target != "ENGAGEMENT":
            target = self.canonical_target(root, target)
        item = validate_value(item, "cleanup item")
        created: list[str] = []

        def operation(text: str) -> str:
            tasks = sitrep.read_tasks(text, "CLEANUP")
            identifier = sitrep.next_id(
                [[value.identifier] for value in tasks], "X"
            )
            created.append(identifier)
            tasks.append(sitrep.Task(identifier, target, item, utc_now(), notes=notes))
            return sitrep.write_tasks(text, "CLEANUP", tasks)

        self.mutate(root, operation)
        return created[0]

    def complete_cleanup(self, root: Path, identifier: str) -> None:
        self._set_task_completion(root, "CLEANUP", identifier, complete=True)

    def reopen_cleanup(self, root: Path, identifier: str) -> None:
        self._set_task_completion(root, "CLEANUP", identifier, complete=False)

    def _set_task_completion(
        self, root: Path, name: str, identifier: str, *, complete: bool
    ) -> None:
        def operation(text: str) -> str:
            tasks = sitrep.read_tasks(text, name)
            index = next(
                (
                    position
                    for position, value in enumerate(tasks)
                    if value.identifier == identifier
                ),
                None,
            )
            if index is None:
                raise ValidationError(f"unknown {name.lower()} item: {identifier}")
            task = tasks[index]
            if task.complete == complete:
                state = "completed" if complete else "open"
                raise ConflictError(f"{identifier} is already {state}")
            tasks[index] = replace(
                task,
                complete=complete,
                completed_at=utc_now() if complete else "",
            )
            return sitrep.write_tasks(text, name, tasks)

        self.mutate(root, operation)

    def merge_ports(
        self, root: Path, target: str, ports: Sequence[Sequence[str]]
    ) -> int:
        target = self.canonical_target(root, target)
        if not ports:
            raise ValidationError("input contained no Nmap port rows")

        def operation(text: str) -> str:
            existing = sitrep.read_target(text, target, "PORTS")
            indexed = {(row[0], row[1]): row for row in existing}
            for port, protocol, state, service, version in ports:
                key = (port, protocol)
                notes = indexed.get(key, ["", "", "", "", "", "", ""])[6]
                indexed[key] = [
                    port,
                    protocol,
                    state,
                    service,
                    version,
                    utc_now(),
                    notes,
                ]
            rows = sorted(
                indexed.values(),
                key=lambda row: (int(row[0]) if row[0].isdigit() else 65536, row[1]),
            )
            return sitrep.write_target(text, target, "PORTS", rows)

        self.mutate(root, operation)
        return len(ports)

    def store_scan(
        self, root: Path, target: str, content: str, label: str = "nmap"
    ) -> Path:
        target = self.canonical_target(root, target)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        directory = self._target_path(root, target) / "scans"
        _private_directory(directory)
        path = directory / f"{label}-{stamp}.txt"
        counter = 1
        while path.exists():
            path = directory / f"{label}-{stamp}-{counter}.txt"
            counter += 1
        _atomic_write(path, content if content.endswith("\n") else content + "\n")
        return path

    def _sync_credentials(self, root: Path, text: str) -> None:
        rows = sitrep.read_global(text, "CREDENTIALS")
        directory = self._contained(root, "credentials")
        _private_directory(directory)
        pairs = [f"{row[1]}:{row[3]}" for row in rows]
        users = list(dict.fromkeys(row[1] for row in rows))
        passwords = list(dict.fromkeys(row[3] for row in rows if row[2] == "password"))
        hashes = list(dict.fromkeys(row[3] for row in rows if row[2] == "hash"))
        for name, values in (
            ("creds.txt", pairs),
            ("users.txt", users),
            ("passwords.txt", passwords),
            ("hashes.txt", hashes),
        ):
            _atomic_write(directory / name, "".join(f"{value}\n" for value in values))

    def validate(self, root: Path, text: str | None = None) -> list[str]:
        self.require_engagement(root)
        document = self.read(root) if text is None else text
        if sitrep.uses_legacy_format(document):
            raise ValidationError("legacy SITREP format; run tacmux sitrep sync")
        sitrep.read_global(document, "CREDENTIALS")
        sections = sitrep.target_sections(document)
        section_names = {section.name for section in sections}
        directory_names = set(self.targets(root))
        problems: list[str] = []
        endpoints: dict[str, str] = {}
        routes: dict[str, str] = {}
        for target in sorted(section_names):
            validate_target_name(target)
            details = sitrep.details_map(document, target)
            endpoint = details["Endpoint"][0]
            if not endpoint:
                raise ValidationError(f"{target} Endpoint cannot be empty")
            if endpoint in endpoints:
                raise ValidationError(
                    f"targets {endpoints[endpoint]} and {target} "
                    f"share Endpoint {endpoint}"
                )
            endpoints[endpoint] = target
            if details["Status"][0] not in TARGET_STATUSES:
                raise ValidationError(f"{target} has an invalid Status")
            if details["Access"][0] not in ACCESS_LEVELS:
                raise ValidationError(f"{target} has an invalid Access level")
            route = validate_name(details["Capture Route"][0], "capture route")
            if route.casefold() == "ops":
                raise ValidationError(f"{target} uses the reserved capture route: ops")
            if route.casefold() in routes:
                raise ValidationError(
                    f"targets {routes[route.casefold()]} and {target} "
                    f"share Capture Route {route}"
                )
            routes[route.casefold()] = target
            for row in sitrep.read_target(document, target, "PORTS"):
                if not row[0].isdigit() or not 1 <= int(row[0]) <= 65535:
                    raise ValidationError(f"{target} has an invalid port: {row[0]}")
                if row[1] not in {"tcp", "udp", "sctp"}:
                    raise ValidationError(f"{target} has an invalid protocol: {row[1]}")
            if target not in directory_names:
                problems.append(f"orphan SITREP target: {target}")
        capture_root = self._contained(root, "captures")
        for child in capture_root.iterdir():
            if child.is_symlink():
                problems.append(f"linked capture route: {child.name}")
                continue
            if (
                child.is_dir()
                and child.name.casefold() not in {".nocap", "ops", *routes}
                and any(path.is_file() for path in child.rglob("*"))
            ):
                problems.append(f"unassigned capture route with files: {child.name}")
        for target in sorted(directory_names - section_names):
            problems.append(f"target directory missing from SITREP: {target}")
        credential_rows = sitrep.read_global(document, "CREDENTIALS")
        credential_ids = [row[0] for row in credential_rows]
        if len(credential_ids) != len(set(credential_ids)):
            raise ValidationError("duplicate credential IDs")
        for row in credential_rows:
            if not re.fullmatch(r"C\d{3,}", row[0]):
                raise ValidationError(f"invalid credential ID: {row[0]}")
            if row[2] not in {"password", "hash"}:
                raise ValidationError(f"invalid credential type: {row[2]}")
            confirmations = sitrep.parse_confirmed_access(row[5])
            confirmation_keys: set[tuple[str, str]] = set()
            for target, service, access in confirmations:
                validate_confirmation_component(target, "confirmed target")
                validate_confirmation_component(service, "confirmed service")
                key = (target.casefold(), service.casefold())
                if key in confirmation_keys:
                    raise ValidationError(
                        f"duplicate confirmed target/service on credential {row[0]}"
                    )
                confirmation_keys.add(key)
                if target not in directory_names:
                    problems.append(
                        f"credential {row[0]} references missing target: {target}"
                    )
                if access not in ACCESS_LEVELS or access == "none":
                    raise ValidationError(
                        f"invalid confirmed access on credential {row[0]}: {access}"
                    )
            if bool(confirmations) != bool(row[7]):
                raise ValidationError(
                    f"credential {row[0]} confirmation timestamp is inconsistent"
                )
        targets = directory_names | {"ENGAGEMENT"}
        for name, prefix in (("TODO", "T"), ("CLEANUP", "X")):
            tasks = sitrep.read_tasks(document, name)
            identifiers = [task.identifier for task in tasks]
            if len(identifiers) != len(set(identifiers)):
                raise ValidationError(f"duplicate IDs in {name.lower()}")
            for task in tasks:
                if not re.fullmatch(rf"{prefix}\d{{3,}}", task.identifier):
                    raise ValidationError(
                        f"invalid ID in {name.lower()}: {task.identifier}"
                    )
                if task.target not in targets:
                    problems.append(
                        f"{name.lower()} references missing target: {task.target}"
                    )
        events = sitrep.read_events(document)
        event_ids = [event.identifier for event in events]
        if len(event_ids) != len(set(event_ids)):
            raise ValidationError("duplicate Operations Log event IDs")
        captures = [event.capture_id for event in events if event.capture_id]
        if len(captures) != len(set(captures)):
            raise ValidationError("duplicate NOCAP capture IDs in Operations Log")
        for event in events:
            if event.target not in targets:
                problems.append(
                    f"operations log references missing target: {event.target}"
                )
            if event.outcome not in OUTCOMES:
                raise ValidationError(
                    f"invalid Operations Log outcome: {event.outcome}"
                )
        return problems

    def repair_scaffolding(self, root: Path, endpoints: dict[str, str]) -> list[str]:
        """Add missing target sections. Existing malformed tables are never replaced."""
        with self.locked(root):
            previous = self.read(root)
            text = sitrep.ensure_scaffolding(previous)
            sections = {item.name for item in sitrep.target_sections(text)}
            for target in self.targets(root):
                if target not in sections:
                    endpoint = validate_value(
                        endpoints.get(target, ""), f"endpoint for {target}"
                    )
                    text = sitrep.add_target(text, target, endpoint)
            problems = self.validate(root, text)
            self._commit(
                root,
                previous,
                text,
                allow_reference_problems=True,
            )
            return problems

    def upgrade_sitrep(self, root: Path) -> Path | None:
        with self.locked(root):
            previous = self.read(root)
            if not sitrep.uses_legacy_format(previous):
                return None
            backup_directory = self._contained(root, ".tacmux", "backups")
            _private_directory(backup_directory)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            backup = backup_directory / f"SITREP-before-operations-log-{stamp}.md"
            counter = 2
            while backup.exists():
                backup = backup_directory / (
                    f"SITREP-before-operations-log-{stamp}-{counter}.md"
                )
                counter += 1
            _atomic_write(backup, previous)
            self._commit(root, previous, sitrep.upgrade_legacy(previous))
            return backup


NMAP_PORT = re.compile(
    r"^\s*(\d{1,5})/(tcp|udp|sctp)\s+(\S+)\s+(\S+)(?:\s+(.*?))?\s*$",
    re.IGNORECASE,
)


def parse_nmap_ports(content: str) -> list[list[str]]:
    ports: dict[tuple[str, str], list[str]] = {}
    for line in content.splitlines():
        match = NMAP_PORT.match(line)
        if not match:
            continue
        port, protocol, state, service, version = match.groups()
        number = int(port)
        if number < 1 or number > 65535:
            continue
        row = [port, protocol.lower(), state, service, (version or "").strip()]
        ports[(port, protocol.lower())] = row
    return list(ports.values())


def parse_host_candidates(content: str, kind: str = "hosts") -> list[tuple[str, str]]:
    candidates: dict[str, tuple[str, str]] = {}
    for line in content.splitlines():
        stripped = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", line).strip()
        if not stripped or stripped.startswith("#"):
            continue
        ip = ""
        name = ""
        grepable = re.search(
            r"\bHost:\s+([^ ]+)\s+\(([^)]*)\).*\bStatus:\s+Up", stripped
        )
        normal = re.search(
            r"^Nmap scan report for (?:(.*?) \()?([^ ()]+)\)?$", stripped
        )
        if grepable:
            ip, name = grepable.group(1), grepable.group(2)
        elif stripped.startswith("Host:"):
            continue
        elif normal:
            possible_name, possible_ip = normal.groups()
            ip, name = possible_ip, possible_name or ""
        elif kind == "netexec":
            match = re.search(r"\b((?:\d{1,3}\.){3}\d{1,3})\b", stripped)
            if match:
                ip = match.group(1)
                remainder = stripped[match.end() :].split()
                if remainder and remainder[0].isdigit():
                    remainder = remainder[1:]
                if remainder and re.fullmatch(r"[A-Za-z0-9_.-]+", remainder[0]):
                    name = remainder[0]
        else:
            fields = stripped.split()
            for field in fields:
                try:
                    ipaddress.ip_address(field.strip("[](),"))
                except ValueError:
                    continue
                ip = field.strip("[](),")
                other = next((value for value in fields if value != field), "")
                name = other
                break
        try:
            endpoint = str(ipaddress.ip_address(ip))
        except ValueError:
            continue
        candidate_name = validate_name(name or endpoint, "candidate name")
        candidates[endpoint] = (candidate_name, endpoint)
    return list(candidates.values())
