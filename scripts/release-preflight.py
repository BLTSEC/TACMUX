#!/usr/bin/env python3
"""Validate that a TACMUX release is complete before tagging it."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path


VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
INIT_VERSION_RE = re.compile(r'^__version__\s*=\s*"([^"]+)"\s*$', re.MULTILINE)
CHANGELOG_HEADING_RE = re.compile(r"^## ([0-9]+\.[0-9]+\.[0-9]+)(?:\s|$)", re.MULTILINE)

REQUIRED_FILES = (
    "assets/tacmux-v2-tour.gif",
    "assets/tacmux-v2-targets.png",
    "scripts/demo/setup-tacmux-demo.py",
    "scripts/demo/tacmux-v2.tape",
    "scripts/render-demo.sh",
)


def load_toml(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def changelog_notes(changelog: str, version: str) -> str | None:
    matches = list(CHANGELOG_HEADING_RE.finditer(changelog))
    for index, match in enumerate(matches):
        if match.group(1) != version:
            continue
        start = changelog.find("\n", match.start()) + 1
        end = matches[index + 1].start() if index + 1 < len(matches) else len(changelog)
        notes = changelog[start:end].strip()
        return notes or None
    return None


def git_output(root: Path, *args: str) -> str:
    result = subprocess.run(
        ("git", *args),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def validate(root: Path, version: str, require_head_main: bool) -> tuple[list[str], str | None]:
    failures: list[str] = []

    if not VERSION_RE.fullmatch(version):
        return ([f"version must be a stable X.Y.Z value, got {version!r}"], None)

    pyproject = load_toml(root / "pyproject.toml")
    project_version = pyproject.get("project", {}).get("version")
    if project_version != version:
        failures.append(f"pyproject.toml has {project_version!r}, expected {version!r}")

    init_text = (root / "src/tacmux/__init__.py").read_text()
    init_match = INIT_VERSION_RE.search(init_text)
    init_version = init_match.group(1) if init_match else None
    if init_version != version:
        failures.append(f"src/tacmux/__init__.py has {init_version!r}, expected {version!r}")

    lock = load_toml(root / "uv.lock")
    lock_versions = [
        package.get("version")
        for package in lock.get("package", [])
        if package.get("name") == "tacmux"
    ]
    if lock_versions != [version]:
        failures.append(f"uv.lock has TACMUX versions {lock_versions!r}, expected [{version!r}]")

    changelog = (root / "CHANGELOG.md").read_text()
    notes = changelog_notes(changelog, version)
    if not notes:
        failures.append(f"CHANGELOG.md has no non-empty {version} release section")

    for relative_path in REQUIRED_FILES:
        if not (root / relative_path).is_file():
            failures.append(f"required release artifact is missing: {relative_path}")

    readme = (root / "README.md").read_text()
    if "assets/tacmux-v2-tour.gif" not in readme:
        failures.append("README.md does not reference assets/tacmux-v2-tour.gif")

    usage = (root / "docs/USAGE.md").read_text()
    if "../assets/tacmux-v2-targets.png" not in usage:
        failures.append("docs/USAGE.md does not reference ../assets/tacmux-v2-targets.png")

    if require_head_main:
        try:
            head = git_output(root, "rev-parse", "HEAD")
            main = git_output(root, "rev-parse", "refs/remotes/origin/main")
        except (OSError, subprocess.CalledProcessError) as exc:
            failures.append(f"could not compare HEAD with origin/main: {exc}")
        else:
            if head != main:
                failures.append(f"HEAD {head} does not match origin/main {main}")

    return failures, notes


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="stable release version without a v prefix")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--require-head-main",
        action="store_true",
        help="require HEAD to equal refs/remotes/origin/main",
    )
    parser.add_argument("--notes-output", type=Path, help="write the CHANGELOG section here")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()

    try:
        failures, notes = validate(root, args.version, args.require_head_main)
    except (OSError, KeyError, tomllib.TOMLDecodeError) as exc:
        failures, notes = [f"could not read release metadata: {exc}"], None

    if failures:
        for failure in failures:
            print(f"[FAIL] {failure}", file=sys.stderr)
        return 1

    if args.notes_output:
        args.notes_output.write_text(f"{notes}\n")

    print(f"[ok] TACMUX {args.version} release tree is complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
