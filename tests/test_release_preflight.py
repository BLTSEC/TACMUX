from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/release-preflight.py"


def run_preflight(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        (sys.executable, str(SCRIPT), "--root", str(ROOT), *args),
        check=False,
        capture_output=True,
        text=True,
    )


def test_current_release_tree_is_complete(tmp_path: Path) -> None:
    notes = tmp_path / "notes.md"
    result = run_preflight("--version", "2.5.1", "--notes-output", str(notes))

    assert result.returncode == 0, result.stderr
    assert "### Added" in notes.read_text()
    assert "2.5.0" not in notes.read_text()


def test_version_mismatch_is_rejected() -> None:
    result = run_preflight("--version", "9.9.9")

    assert result.returncode == 1
    assert "pyproject.toml" in result.stderr
    assert "src/tacmux/__init__.py" in result.stderr
    assert "uv.lock" in result.stderr
    assert "CHANGELOG.md" in result.stderr


def test_non_stable_version_is_rejected() -> None:
    result = run_preflight("--version", "2.5.2-rc1")

    assert result.returncode == 1
    assert "stable X.Y.Z" in result.stderr
