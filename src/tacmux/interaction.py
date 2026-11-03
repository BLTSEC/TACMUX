"""Small terminal prompts, fzf selection, editor handoff, and plain tables."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Iterable, Sequence

from .config import Settings
from .errors import ExternalToolError, NonInteractiveError, ValidationError

NONINTERACTIVE_ENV = "TACMUX_NONINTERACTIVE"


def _label(prompt: str) -> str:
    return prompt.strip().rstrip(">:").strip().lower() or "value"


def forced_noninteractive() -> bool:
    return os.environ.get(NONINTERACTIVE_ENV, "").strip() not in {"", "0"}


def text_input_available() -> bool:
    """True when line prompts can read an operator's answer from stdin."""
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False


def picker_available() -> bool:
    """True when fzf can draw on the controlling terminal."""
    try:
        descriptor = os.open("/dev/tty", os.O_RDWR | getattr(os, "O_NOCTTY", 0))
    except OSError:
        return False
    os.close(descriptor)
    return True


def require_interactive(label: str, *, picker: bool = False) -> None:
    """Refuse to prompt from scripts, pipes, or agents; name the missing input."""
    available = picker_available() if picker else text_input_available()
    if forced_noninteractive() or not available:
        raise NonInteractiveError(
            f"missing {label}: pass it as an argument "
            "(run the command with --help for its exact form)"
        )


def _prefilled_input(prompt: str, default: str) -> str:
    try:
        import readline
    except ImportError:  # pragma: no cover - readline exists on supported Linux
        return input(f"{prompt} [{default}]: ") or default
    readline.set_startup_hook(lambda: readline.insert_text(default))
    try:
        return input(f"{prompt}: ")
    finally:
        readline.set_startup_hook()


def ask(
    label: str,
    default: str = "",
    *,
    required: bool = True,
    prefill: bool = False,
) -> str:
    """Prompt for one line; with prefill the default is editable in place."""
    require_interactive(label.lower())
    if prefill and default:
        value = _prefilled_input(label, default).strip()
    else:
        try:
            import readline  # noqa: F401  # enables line editing for input()
        except ImportError:  # pragma: no cover
            pass
        suffix = f" [{default}]" if default else ""
        value = input(f"{label}{suffix}: ").strip()
        value = value or default
    if required and not value:
        raise ValidationError(f"{label.lower()} cannot be empty")
    return value


def confirm(prompt: str, *, default: bool = False) -> bool:
    require_interactive(f"confirmation for: {prompt}")
    answer = input(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").strip().casefold()
    if not answer:
        return default
    return answer in {"y", "yes"}


def _picker_argv(
    binary: str,
    prompt: str,
    *,
    header: str = "",
    preview: bool = False,
    query: str = "",
) -> list[str]:
    argv = [
        binary,
        "--delimiter=\t",
        "--with-nth=1",
        "--prompt",
        prompt,
        "--height=60%",
        "--reverse",
        "--border=rounded",
    ]
    if header:
        argv.extend(["--header", header])
    if preview:
        argv.extend(
            [
                "--preview",
                "printf '%b\\n' {3}",
                "--preview-window=right,45%,wrap",
            ]
        )
    if query:
        argv.extend(["--query", query])
    return argv


def choose(
    choices: Sequence[tuple[str, str]] | Sequence[tuple[str, str, str]],
    prompt: str,
    *,
    default: str = "",
    header: str = "",
    query: str = "",
) -> str:
    """Select (display, value[, preview]) with fzf, placing a default first."""
    if not choices:
        raise ValidationError(f"nothing is available for {prompt.rstrip(': ')}")
    require_interactive(_label(prompt), picker=True)
    binary = shutil.which("fzf")
    if binary is None:
        raise ExternalToolError("fzf is required; install it before using pickers")
    ordered = list(choices)
    if default:
        ordered.sort(key=lambda item: item[1] != default)
    preview = any(len(item) > 2 for item in ordered)
    payload = "".join(
        "\t".join(
            [
                item[0],
                item[1],
                *(
                    [(item[2] if len(item) > 2 else "").replace("\t", " ")]
                    if preview
                    else []
                ),
            ]
        )
        + "\n"
        for item in ordered
    )
    result = subprocess.run(
        _picker_argv(binary, prompt, header=header, preview=preview, query=query),
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
    _, separator, remainder = line.partition("\t")
    if not separator:
        raise ExternalToolError("fzf returned an invalid selection")
    value, _, _preview = remainder.partition("\t")
    return value


def choose_many(choices: Sequence[tuple[str, str]], prompt: str) -> list[str]:
    """Select one or more values with fzf without exposing hidden columns."""
    if not choices:
        raise ValidationError(f"nothing is available for {prompt.rstrip(': ')}")
    require_interactive(_label(prompt), picker=True)
    binary = shutil.which("fzf")
    if binary is None:
        raise ExternalToolError("fzf is required; install it before using pickers")
    payload = "".join(f"{display}\t{value}\n" for display, value in choices)
    result = subprocess.run(
        [
            binary,
            "--multi",
            "--bind=ctrl-a:select-all,ctrl-d:deselect-all",
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
    values: list[str] = []
    for line in result.stdout.splitlines():
        _, separator, value = line.partition("\t")
        if not separator:
            raise ExternalToolError("fzf returned an invalid selection")
        values.append(value)
    if not values:
        raise ValidationError("no targets selected; use the None option to clear")
    return values


EDITOR_NEEDS_TERMINAL = (
    "this step opens $EDITOR, which needs an interactive terminal; run the "
    "command from a terminal, not through a pipe, script, or agent"
)


def can_prompt() -> bool:
    """True when an operator is at a terminal and prompts are allowed."""
    return not forced_noninteractive() and text_input_available()


def require_terminal(message: str) -> None:
    """Refuse a step that needs an operator at a terminal, with its own reason."""
    if forced_noninteractive() or not text_input_available():
        raise NonInteractiveError(message)


def open_editor(settings: Settings, path: Path, line: int | None = None) -> None:
    require_terminal(EDITOR_NEEDS_TERMINAL)
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
