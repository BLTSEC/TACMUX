from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RENDERER = ROOT / "bin/logrender"


def run_renderer(data: bytes, *args: str) -> str:
    result = subprocess.run(
        ["python3", str(RENDERER), *args],
        input=data,
        capture_output=True,
        check=True,
    )
    return result.stdout.decode("utf-8")


def test_default_preserves_repeated_sparse_lines_and_tabs():
    data = b"a\tb\n\nsame\nsame\nsame\n"
    assert run_renderer(data) == "a       b\n\nsame\nsame\nsame\n"


def test_compaction_is_explicit():
    assert run_renderer(b"same\nsame\nsame\n", "--compact") == "same\n  [×3]\n"


def test_carriage_return_updates_the_current_line():
    assert run_renderer(b"progress 10%\rprogress 20%\n") == "progress 20%\n"
