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


def test_compact_restores_legacy_prompt_padding_and_animation_cleanup():
    first = b"[Aug 26, 2026 - 10:00:00 (CDT)] one"
    second = b"[Aug 26, 2026 - 10:01:00 (CDT)] two"
    data = first + second + b"\n~\n~\n~\n.\n..\n.\n..\n.\n..\nkept\n"

    assert run_renderer(data, "--compact") == first.decode() + "\n" + second.decode() + "\nkept\n"


def test_compact_removes_repeated_terminal_redraw_blocks():
    block = b"one\ntwo\nthree\nfour\nfive\n"

    assert run_renderer(block * 2, "--compact") == block.decode()


def test_default_keeps_content_that_compact_is_allowed_to_drop():
    data = b"~\n~\n~\n.\n..\n.\n..\n.\n..\n"

    assert run_renderer(data) == data.decode()
