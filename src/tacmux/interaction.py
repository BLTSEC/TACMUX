"""Small terminal prompts, fzf selection, editor handoff, and plain tables."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Iterable, Sequence

from .config import Settings
from .errors import ExternalToolError, ValidationError


def ask(label: str, default: str = "", *, required: bool = True) -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{label}{suffix}: ").strip()
    value = value or default
    if required and not value:
        raise ValidationError(f"{label.lower()} cannot be empty")
    return value


def confirm(prompt: str) -> bool:
    return input(f"{prompt} [y/N]: ").strip().casefold() in {"y", "yes"}


def choose(
    choices: Sequence[tuple[str, str]],
    prompt: str,
    *,
    default: str = "",
) -> str:
    """Select (display, value) with fzf, placing a default first."""
    if not choices:
        raise ValidationError(f"nothing is available for {prompt.rstrip(': ')}")
    binary = shutil.which("fzf")
    if binary is None:
        raise ExternalToolError("fzf is required; install it before using pickers")
    ordered = list(choices)
    if default:
        ordered.sort(key=lambda item: item[1] != default)
    payload = "".join(f"{display}\t{value}\n" for display, value in ordered)
    result = subprocess.run(
        [
            binary,
            "--delimiter=\t",
            "--with-nth=1",
            "--prompt",
            prompt,
            "--height=60%",
            "--reverse",
            "--border=rounded",
        ],
        input=payload,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode == 130:
        raise ValidationError("selection cancelled")
    if result.returncode != 0:
        raise ExternalToolError((result.stderr or "fzf selection failed").strip())
    line = result.stdout.rstrip("\n")
    _, separator, value = line.partition("\t")
    if not separator:
        raise ExternalToolError("fzf returned an invalid selection")
    return value


def open_editor(settings: Settings, path: Path, line: int | None = None) -> None:
    argv = list(settings.editor_argv)
    executable = Path(argv[0]).name
    if line and executable in {"vi", "vim", "nvim", "view", "nvim-qt"}:
        argv.append(f"+{line}")
    argv.append(str(path))
    try:
        result = subprocess.run(argv, check=False)
    except OSError as exc:
        raise ExternalToolError(f"cannot launch editor: {exc}") from exc
    if result.returncode:
        raise ExternalToolError(f"editor exited with status {result.returncode}")


def edit_text(
    settings: Settings,
    initial: str,
    suffix: str = ".txt",
    *,
    require_save: bool = False,
) -> str:
    descriptor, name = tempfile.mkstemp(prefix="tacmux-", suffix=suffix)
    path = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(initial)
        before = path.stat()
        open_editor(settings, path)
        after = path.stat()
        unchanged = (
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) == (
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if require_save and unchanged:
            raise ValidationError("editor closed without saving; operation cancelled")
        return path.read_text(encoding="utf-8")
    finally:
        path.unlink(missing_ok=True)


def format_table(headers: Sequence[str], rows: Iterable[Sequence[object]]) -> str:
    values = [[str(value) for value in row] for row in rows]
    widths = [len(header) for header in headers]
    for row in values:
        for index, value in enumerate(row):
            widths[index] = min(max(widths[index], len(value)), 48)

    def render(row: Sequence[str]) -> str:
        cells = []
        for index, value in enumerate(row):
            width = widths[index]
            clipped = value if len(value) <= width else value[: width - 1] + "…"
            cells.append(clipped.ljust(width))
        return "  ".join(cells).rstrip()

    lines = [render(headers), render(tuple("-" * width for width in widths))]
    lines.extend(render(row) for row in values)
    return "\n".join(lines)
