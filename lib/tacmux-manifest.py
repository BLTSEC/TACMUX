#!/usr/bin/env python3
"""Create a deterministic sidecar manifest for a TACMUX tar archive."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import tarfile
import tempfile
from pathlib import Path


CHUNK_SIZE = 1024 * 1024


def sha256_stream(stream) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(CHUNK_SIZE):
        digest.update(chunk)
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return sha256_stream(stream)


def utc_timestamp(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")


def archive_contents(path: Path) -> dict:
    files = []
    links = []
    directory_count = 0
    special_entry_count = 0

    with tarfile.open(path, "r:gz") as archive:
        for member in sorted(archive.getmembers(), key=lambda item: item.name):
            if member.isfile():
                stream = archive.extractfile(member)
                if stream is None:
                    raise RuntimeError(f"unable to read archived file: {member.name}")
                with stream:
                    digest = sha256_stream(stream)
                files.append(
                    {
                        "path": member.name,
                        "size_bytes": member.size,
                        "modified_utc": utc_timestamp(member.mtime),
                        "sha256": digest,
                    }
                )
            elif member.isdir():
                directory_count += 1
            elif member.issym() or member.islnk():
                links.append(
                    {
                        "path": member.name,
                        "target": member.linkname,
                        "type": "symlink" if member.issym() else "hardlink",
                        "modified_utc": utc_timestamp(member.mtime),
                    }
                )
            else:
                special_entry_count += 1

    return {
        "entry_count": len(files) + len(links) + directory_count + special_entry_count,
        "file_count": len(files),
        "directory_count": directory_count,
        "link_count": len(links),
        "special_entry_count": special_entry_count,
        "total_file_bytes": sum(item["size_bytes"] for item in files),
        "files": files,
        "links": links,
    }


def write_private_json(path: Path, document: dict, file_mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    try:
        os.fchmod(descriptor, file_mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(document, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        os.replace(temporary_name, path)
        os.chmod(path, file_mode)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--file-mode", required=True)
    parser.add_argument("--created-utc", required=True)
    parser.add_argument("--tacmux-version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--workspace-relative-path", required=True)
    parser.add_argument("--session", required=True)
    parser.add_argument("--engagement", default="")
    args = parser.parse_args()

    try:
        file_mode = int(args.file_mode, 8)
    except ValueError:
        parser.error(f"invalid file mode: {args.file_mode}")
    if not 0 <= file_mode <= 0o666:
        parser.error(f"invalid file mode: {args.file_mode}")

    archive = args.archive.resolve()
    if not archive.is_file():
        parser.error(f"archive does not exist: {archive}")

    document = {
        "schema": "tacmux.archive-manifest/v1",
        "created_utc": args.created_utc,
        "tacmux_version": args.tacmux_version,
        "context": {
            "engagement": args.engagement or None,
            "target": args.target,
            "workspace_relative_path": args.workspace_relative_path,
            "tmux_session": args.session,
        },
        "archive": {
            "filename": archive.name,
            "size_bytes": archive.stat().st_size,
            "sha256": sha256_file(archive),
        },
        "contents": archive_contents(archive),
    }
    write_private_json(args.output, document, file_mode)
    print(f"Archived files: {document['contents']['file_count']}")
    print(f"Archive SHA-256: {document['archive']['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
