#!/usr/bin/env python3
"""Build an isolated TACMUX workspace from the public synthetic fixture."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = REPO_ROOT / "tests/fixtures/external_internal_example.json"
TARGET_PHASES = ("recon", "exploitation", "loot", "screenshots", "reports", "logs")


def private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)


def private_text(path: Path, content: str) -> None:
    private_directory(path.parent)
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="create an isolated TACMUX demo from the checked-in fixture"
    )
    parser.add_argument(
        "root",
        type=Path,
        help="an existing, empty temporary directory owned by the current user",
    )
    return parser.parse_args()


def require_empty_private_root(path: Path) -> Path:
    root = path.resolve(strict=True)
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"demo root must be a real directory: {root}")
    if any(root.iterdir()):
        raise ValueError(f"demo root must be empty: {root}")
    if root.stat().st_uid != os.getuid():
        raise ValueError(f"demo root must be owned by the current user: {root}")
    root.chmod(0o700)
    return root


def write_target_tree(engagement_root: Path, engagement: dict[str, object]) -> None:
    targets = engagement.get("targets", [])
    if not isinstance(targets, list):
        raise ValueError("fixture targets must be a list")
    for target in targets:
        if not isinstance(target, dict):
            raise ValueError("fixture target must be an object")
        target_id = str(target["id"])
        display_name = str(target["display_name"])
        directory = str(target["directory"])
        target_root = engagement_root / "targets" / directory
        private_directory(target_root)
        for phase in TARGET_PHASES:
            private_directory(target_root / phase)
        private_text(
            target_root / "NOTES.md",
            f"# {display_name}\n\n"
            f"- Target ID: `{target_id}`\n"
            "- Demo data: synthetic documentation-only fixture\n\n"
            "## Notes\n\n"
            "- Validate every action against the written authorization and scope.\n",
        )


def write_evidence(engagement_root: Path) -> None:
    samples = {
        "targets/T0001-EDGE-WEB/exploitation/console-access.txt": (
            "Synthetic evidence: the authorized administrative console was reachable.\n"
        ),
        "targets/T0001-EDGE-WEB/exploitation/approved-route.txt": (
            "Synthetic evidence: the approved route to the application network was "
            "validated.\n"
        ),
        "targets/T0002-JUMP01/recon/delegation-review.txt": (
            "Synthetic evidence: delegation review produced no additional access path.\n"
        ),
        "targets/T0003-APP01/recon/portal-auth.txt": (
            "Synthetic evidence: the test identity authenticated to the artifact portal.\n"
        ),
        "targets/T0003-APP01/recon/artifact-read.txt": (
            "Synthetic evidence: the test identity could read unintended sample "
            "artifacts.\n"
        ),
    }
    for relative, content in samples.items():
        private_text(engagement_root / relative, content)


def write_finding_documents(
    engagement_root: Path, engagement: dict[str, object]
) -> None:
    findings = engagement.get("findings", [])
    if not isinstance(findings, list):
        raise ValueError("fixture findings must be a list")
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("fixture finding must be an object")
        private_text(
            engagement_root / str(finding["document"]),
            f"# {finding['title']}\n\n"
            f"- **ID:** `{finding['id']}`\n"
            f"- **Severity:** {finding['severity']}\n"
            f"- **State:** {finding['state']}\n\n"
            "## Summary\n\nSynthetic demonstration finding.\n",
        )


def main() -> int:
    args = parse_args()
    try:
        root = require_empty_private_root(args.root)
        engagement = json.loads(FIXTURE.read_text(encoding="utf-8"))
        engagement_id = str(engagement["id"])
        engagement_root = (
            root
            / "workspace"
            / f"{engagement_id}-Synthetic-External-and-Internal-Assessment"
        )

        for relative in (
            "workspace",
            "archives",
            "logs",
            "config/tacmux",
            f"workspace/{engagement_root.name}/.tacmux/imports",
            f"workspace/{engagement_root.name}/.tacmux/jobs",
            f"workspace/{engagement_root.name}/.tacmux/deleting",
            f"workspace/{engagement_root.name}/notes",
            f"workspace/{engagement_root.name}/findings",
            f"workspace/{engagement_root.name}/targets",
        ):
            private_directory(root / relative)

        private_text(
            engagement_root / ".tacmux/engagement.json",
            json.dumps(engagement, indent=2, sort_keys=True) + "\n",
        )
        private_text(
            engagement_root / "ENGAGEMENT.md",
            "# Northstar Example — Synthetic External and Internal Assessment\n\n"
            "> Public, synthetic documentation fixture. No client data is present.\n\n"
            "## Objective\n\nDemonstrate TACMUX's five-view operator cockpit.\n",
        )
        write_target_tree(engagement_root, engagement)
        write_evidence(engagement_root)
        write_finding_documents(engagement_root, engagement)

        config_file = root / "config/tacmux/config.toml"
        private_text(
            config_file,
            "[paths]\n"
            f'workspace = "{root / "workspace"}"\n'
            f'archive_dir = "{root / "archives"}"\n'
            f'log_dir = "{root / "logs"}"\n\n'
            "[behavior]\n"
            "auto_log = false\n"
            "log_outside_tacmux = false\n"
            'startup = "resume_last"\n'
            "include_mermaid = true\n\n"
            "[nocap]\n"
            "enabled = false\n",
        )
        private_text(
            config_file.parent / "state.json",
            json.dumps(
                {
                    "schema": "tacmux.state/v1",
                    "last_engagement_id": engagement_id,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
        )
        private_text(
            root / "demo.env",
            "export TACMUX_CONFIG=" + shlex.quote(str(config_file)) + "\n"
            + "export TACMUX_WORKSPACE="
            + shlex.quote(str(root / "workspace"))
            + "\n"
            + "export TACMUX_ARCHIVE_DIR="
            + shlex.quote(str(root / "archives"))
            + "\n"
            + "export TACMUX_LOG_DIR="
            + shlex.quote(str(root / "logs"))
            + "\n",
        )
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"setup-tacmux-demo: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
