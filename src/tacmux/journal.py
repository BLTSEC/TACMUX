"""Append one shell command to <engagement>/logs/commands.tsv.

Run by the zsh hook from `tacmux shell-init zsh` after each command, as
`python -I journal.py ROOT EPOCH SECONDS EXIT TARGET PANE CWD` with the
command on stdin. Standard library only and no package imports, so it starts
fast. Writes never follow links, never truncate, and hold a lock per row.
"""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat
import sys
from typing import Iterator

DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
COLUMNS = ("epoch", "seconds", "exit", "target", "pane", "cwd", "command")
HEADER = "#" + "\t".join(COLUMNS) + "\n"


@contextmanager
def engagement_logs(root: str | Path) -> Iterator[int]:
    """Open the engagement's logs/ without following linked directories."""
    root = Path(root)
    if not root.is_absolute():
        raise ValueError("engagement root must be absolute")
    root_fd = os.open(root, DIRECTORY_FLAGS)
    try:
        marker_fd = os.open(".tacmux", DIRECTORY_FLAGS, dir_fd=root_fd)
        try:
            version_fd = os.open(
                "version", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=marker_fd
            )
            with os.fdopen(version_fd, "rb") as stream:
                regular = stat.S_ISREG(os.fstat(stream.fileno()).st_mode)
                if not regular or stream.read(16).strip() != b"3":
                    raise ValueError("not a TACMUX v3 engagement")
        finally:
            os.close(marker_fd)
        logs_fd = os.open("logs", DIRECTORY_FLAGS, dir_fd=root_fd)
        try:
            yield logs_fd
        finally:
            os.close(logs_fd)
    finally:
        os.close(root_fd)


def _field(value: object) -> str:
    return str(value).replace("\t", " ").replace("\r", " ").replace("\n", " ; ")


def append_command(
    root: str | Path,
    epoch: str,
    seconds: str,
    exit_code: str,
    target: str,
    pane: str,
    cwd: str,
    command: str,
) -> None:
    row = "\t".join(
        map(_field, (epoch, seconds, exit_code, target, pane, cwd, command))
    )
    with engagement_logs(root) as directory:
        descriptor = os.open(
            "commands.tsv",
            os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
            dir_fd=directory,
        )
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.getuid()
            ):
                raise ValueError("refusing unsafe command journal")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            os.fchmod(descriptor, 0o600)
            payload = row + "\n"
            if os.fstat(descriptor).st_size == 0:
                payload = HEADER + payload
            remaining = payload.encode("utf-8", errors="surrogateescape")
            while remaining:
                written = os.write(descriptor, remaining)
                if written == 0:
                    raise OSError("short command journal write")
                remaining = remaining[written:]
        finally:
            os.close(descriptor)


def read_rows(path: Path) -> list[dict[str, str]]:
    """Parse commands.tsv (3.4 7-column rows and earlier 5-column rows)."""
    rows: list[dict[str, str]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return rows
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) == 5:
            fields = [*fields[:3], "", "", *fields[3:]]
        if len(fields) < 7:
            continue
        rows.append(dict(zip(COLUMNS, [*fields[:6], "\t".join(fields[6:])])))
    return rows


def zsh_snippet(python: str, script: str) -> str:
    import shlex

    writer = f"{shlex.quote(python)} -I {shlex.quote(script)}"
    return f"""# TACMUX command journal (zsh). Records commands only inside TACMUX
# sessions, to <engagement>/logs/commands.tsv. A leading space skips one.
export TACMUX_SHELL_HOOK=zsh
zmodload zsh/datetime 2>/dev/null
autoload -Uz add-zsh-hook
_tacmux_journal_preexec() {{
    unset _tacmux_j_cmd _tacmux_j_start _tacmux_j_root _tacmux_j_cwd
    [[ "$1" == ' '* || -z "${{TACMUX_ROOT:-}}" \\
        || "${{TACMUX_NO_AUTOLOG:-0}}" == 1 ]] && return 0
    _tacmux_j_cmd="$1"
    _tacmux_j_start="$EPOCHREALTIME"
    _tacmux_j_root="$TACMUX_ROOT"
    _tacmux_j_cwd="$PWD"
}}
_tacmux_journal_precmd() {{
    local exit_code=$?
    if [[ -n "${{_tacmux_j_cmd:-}}" && "${{TACMUX_NO_AUTOLOG:-0}}" != 1 ]]; then
        local duration=$(( EPOCHREALTIME - _tacmux_j_start ))
        printf '%s' "$_tacmux_j_cmd" | {writer} \\
            "$_tacmux_j_root" "${{_tacmux_j_start%.*}}" "$(printf '%.1f' "$duration")" \\
            "$exit_code" "${{TACMUX_TARGET_NAME:-}}" "${{TMUX_PANE:-}}" \\
            "$_tacmux_j_cwd" || true
    fi
    unset _tacmux_j_cmd _tacmux_j_start _tacmux_j_root _tacmux_j_cwd
    return 0
}}
add-zsh-hook preexec _tacmux_journal_preexec
# Run first so $? is still the operator command's exit status.
precmd_functions=(_tacmux_journal_precmd ${{precmd_functions:#_tacmux_journal_precmd}})
"""


def main(argv: list[str]) -> int:
    try:
        if len(argv) != 7:
            raise ValueError("expected root, epoch, seconds, exit, target, pane, cwd")
        append_command(*argv, sys.stdin.read())
    except (OSError, ValueError) as exc:
        print(f"[!] TACMUX command journal: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
