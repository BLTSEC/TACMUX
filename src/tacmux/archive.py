"""Verified private archives with safe restore semantics."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile
from typing import Any

from . import __version__
from .errors import ConflictError, SafetyError, ValidationError
from .model import Engagement, Target
from .store import (
    Workspace,
    _private_directory,
    harden_private_tree,
    restore_engagement_state,
    write_private_json,
)


ARCHIVE_SCHEMA = "tacmux.archive/v2"
CHUNK_SIZE = 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def _tar_filter(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
    parts = PurePosixPath(info.name).parts
    if "__MACOSX" in parts or any(
        part.startswith("._") or part == ".DS_Store" for part in parts
    ):
        return None
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    return info


def _contents(path: Path) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    links: list[dict[str, Any]] = []
    directories = 0
    with tarfile.open(path, "r:gz") as archive:
        for member in sorted(archive.getmembers(), key=lambda item: item.name):
            if member.isfile():
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValidationError(f"cannot read archived member: {member.name}")
                digest = hashlib.sha256()
                with stream:
                    while chunk := stream.read(CHUNK_SIZE):
                        digest.update(chunk)
                files.append(
                    {
                        "path": member.name,
                        "size_bytes": member.size,
                        "sha256": digest.hexdigest(),
                    }
                )
            elif member.isdir():
                directories += 1
            elif member.issym() or member.islnk():
                links.append(
                    {
                        "path": member.name,
                        "target": member.linkname,
                        "type": "symlink" if member.issym() else "hardlink",
                    }
                )
            else:
                raise SafetyError(
                    f"archive contains unsupported special entry: {member.name}"
                )
    return {
        "file_count": len(files),
        "directory_count": directories,
        "link_count": len(links),
        "total_file_bytes": sum(item["size_bytes"] for item in files),
        "files": files,
        "links": links,
    }


def create_archive(
    source: Path,
    archive_dir: Path,
    *,
    kind: str,
    engagement_id: str,
    object_id: str,
    object_metadata: dict[str, Any] | None = None,
) -> tuple[Path, Path]:
    if kind not in {"engagements", "targets"}:
        raise ValidationError(f"unsupported archive kind: {kind}")
    if kind == "targets" and not isinstance(object_metadata, dict):
        raise ValidationError("target archives require target metadata")
    source = source.resolve(strict=True)
    if not source.is_dir():
        raise ValidationError(f"archive source is not a directory: {source}")
    destination = archive_dir / engagement_id / kind
    _private_directory(destination)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    stem = f"{object_id}-{stamp}"
    final_archive = destination / f"{stem}.tar.gz"
    final_manifest = destination / f"{stem}.manifest.json"
    if final_archive.exists() or final_manifest.exists():
        raise ConflictError(f"archive destination already exists: {stem}")
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{stem}.", suffix=".tar.gz", dir=destination
    )
    os.close(descriptor)
    temporary_path = Path(temporary)
    try:
        with tarfile.open(temporary_path, "w:gz") as archive:
            archive.add(source, arcname=source.name, recursive=True, filter=_tar_filter)
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, final_archive)
        document = {
            "schema": ARCHIVE_SCHEMA,
            "created_utc": datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "tacmux_version": __version__,
            "context": {
                "kind": kind,
                "engagement_id": engagement_id,
                "object_id": object_id,
                "source_name": source.name,
                "object_metadata": object_metadata,
            },
            "archive": {
                "filename": final_archive.name,
                "size_bytes": final_archive.stat().st_size,
                "sha256": sha256_file(final_archive),
            },
            "contents": _contents(final_archive),
        }
        write_private_json(final_manifest, document)
        verify_archive(final_archive, final_manifest)
        return final_archive, final_manifest
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        final_archive.unlink(missing_ok=True)
        final_manifest.unlink(missing_ok=True)
        raise


def _manifest_path(archive: Path) -> Path:
    name = archive.name
    if not name.endswith(".tar.gz"):
        raise ValidationError("archive filename must end in .tar.gz")
    return archive.with_name(name[: -len(".tar.gz")] + ".manifest.json")


def _validate_manifest_shape(document: object) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(document, dict):
        raise ValidationError("archive manifest must contain a JSON object")
    if document.get("schema") != ARCHIVE_SCHEMA:
        raise ValidationError(f"unsupported archive schema: {document.get('schema')}")
    metadata = document.get("archive")
    context = document.get("context")
    contents = document.get("contents")
    if not all(isinstance(item, dict) for item in (metadata, context, contents)):
        raise ValidationError("archive manifest sections must be JSON objects")
    if context.get("kind") not in {"engagements", "targets"}:
        raise ValidationError(f"unsupported archive kind: {context.get('kind')}")
    for key in ("engagement_id", "object_id", "source_name"):
        if not isinstance(context.get(key), str) or not context[key]:
            raise ValidationError(f"archive context {key} must be a non-empty string")
    if (
        context["kind"] == "engagements"
        and context["object_id"] != context["engagement_id"]
    ):
        raise ValidationError("engagement archive IDs do not match")
    object_metadata = context.get("object_metadata")
    if object_metadata is not None and not isinstance(object_metadata, dict):
        raise ValidationError("archive object_metadata must be an object or null")
    if not isinstance(metadata.get("filename"), str):
        raise ValidationError("archive filename metadata must be a string")
    if (
        isinstance(metadata.get("size_bytes"), bool)
        or not isinstance(metadata.get("size_bytes"), int)
        or metadata["size_bytes"] < 0
    ):
        raise ValidationError("archive size metadata must be a non-negative integer")
    digest = metadata.get("sha256")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ValidationError("archive SHA-256 metadata is invalid")
    return metadata, context


def verify_archive(archive: Path, manifest: Path | None = None) -> dict[str, Any]:
    archive = archive.resolve(strict=True)
    manifest = (manifest or _manifest_path(archive)).resolve(strict=True)
    try:
        with manifest.open(encoding="utf-8") as stream:
            document = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"cannot read archive manifest: {exc}") from exc
    metadata, context = _validate_manifest_shape(document)
    if metadata.get("filename") != archive.name:
        raise ValidationError("archive filename does not match manifest")
    if metadata.get("size_bytes") != archive.stat().st_size:
        raise ValidationError("archive size does not match manifest")
    if metadata.get("sha256") != sha256_file(archive):
        raise ValidationError("archive SHA-256 does not match manifest")
    try:
        current = _contents(archive)
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise ValidationError(f"cannot read archive contents: {exc}") from exc
    if document.get("contents") != current:
        raise ValidationError("archived members do not match manifest")
    source_name = context["source_name"]
    source_path = PurePosixPath(source_name)
    if (
        not source_name
        or source_path.is_absolute()
        or len(source_path.parts) != 1
        or source_name in {".", ".."}
    ):
        raise SafetyError(f"unsafe archive source name: {source_name}")
    try:
        with tarfile.open(archive, "r:gz") as bundle:
            members = bundle.getmembers()
            roots = [member for member in members if member.name == source_name]
            if len(roots) != 1 or not roots[0].isdir():
                raise SafetyError("archive source root must be exactly one directory")
            for member in members:
                _validate_member(member, archive.parent)
                parts = PurePosixPath(member.name).parts
                if not parts or parts[0] != source_name:
                    raise SafetyError(
                        f"archive member is outside source root: {member.name}"
                    )
                if member.islnk():
                    link_parts = PurePosixPath(member.linkname).parts
                    if not link_parts or link_parts[0] != source_name:
                        raise SafetyError(
                            f"archive hardlink is outside source root: "
                            f"{member.name} -> {member.linkname}"
                        )
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise ValidationError(f"cannot validate archive members: {exc}") from exc
    return document


def restore_engagement_archive(
    archive: Path, workspace: Workspace, context: dict[str, Any]
) -> Path:
    restored = restore_archive(archive, workspace.settings.workspace)
    try:
        engagement = workspace.load(restored)
        if (
            engagement.id != context["engagement_id"]
            or engagement.id != context["object_id"]
            or not restored.name.startswith(f"{engagement.id}-")
        ):
            raise ValidationError(
                "restored engagement manifest does not match archive context"
            )
    except BaseException:
        shutil.rmtree(restored, ignore_errors=True)
        raise
    return restored


def restore_target_archive(
    archive: Path,
    workspace: Workspace,
    engagement_root: Path,
    engagement: Engagement,
    context: dict[str, Any],
) -> Path:
    if context["engagement_id"] != engagement.id:
        raise ValidationError("target archive belongs to a different engagement")
    metadata = context.get("object_metadata")
    if not isinstance(metadata, dict):
        raise ValidationError(
            "target archive does not contain restorable target metadata"
        )
    archived_target = Target.from_dict(metadata)
    if (
        archived_target.id != context["object_id"]
        or archived_target.directory != context["source_name"]
    ):
        raise ValidationError("target archive metadata does not match archive context")
    existing_target = next(
        (item for item in engagement.targets if item.id == archived_target.id), None
    )
    if existing_target is not None and existing_target != archived_target:
        raise ValidationError(
            "target archive metadata does not match the existing target"
        )
    if existing_target is None:
        snapshot = deepcopy(engagement)
        engagement.targets.append(archived_target)
        try:
            engagement.validate()
        finally:
            restore_engagement_state(engagement, snapshot)

    restored = restore_archive(archive, engagement_root / "targets")
    if existing_target is None:
        snapshot = deepcopy(engagement)
        engagement.targets.append(archived_target)
        try:
            workspace.save(engagement_root, engagement)
        except BaseException:
            restore_engagement_state(engagement, snapshot)
            shutil.rmtree(restored, ignore_errors=True)
            raise
    return restored


def _validate_member(member: tarfile.TarInfo, destination: Path) -> None:
    path = PurePosixPath(member.name)
    if path.is_absolute() or ".." in path.parts:
        raise SafetyError(f"unsafe archive member path: {member.name}")
    candidate = (destination / Path(*path.parts)).resolve(strict=False)
    try:
        candidate.relative_to(destination.resolve(strict=False))
    except ValueError as exc:
        raise SafetyError(f"archive member escapes destination: {member.name}") from exc
    if member.issym() or member.islnk():
        link = PurePosixPath(member.linkname)
        if link.is_absolute() or ".." in link.parts:
            raise SafetyError(
                f"unsafe archive link: {member.name} -> {member.linkname}"
            )
    if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
        raise SafetyError(f"archive contains unsupported special entry: {member.name}")


def restore_archive(archive: Path, destination: Path) -> Path:
    document = verify_archive(archive)
    destination = destination.resolve(strict=False)
    _private_directory(destination)
    source_name = str(document["context"]["source_name"])
    restored_root = destination / source_name
    if os.path.lexists(restored_root):
        raise ConflictError(f"restore destination already exists: {restored_root}")
    staging = Path(tempfile.mkdtemp(prefix=".tacmux-restore-", dir=destination))
    try:
        with tarfile.open(archive, "r:gz") as bundle:
            members = bundle.getmembers()
            for member in members:
                _validate_member(member, staging)
            bundle.extractall(staging, members=members, filter="data")
        staged_root = staging / source_name
        harden_private_tree(staged_root)
        if os.path.lexists(restored_root):
            raise ConflictError(f"restore destination already exists: {restored_root}")
        staged_root.rename(restored_root)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return restored_root
