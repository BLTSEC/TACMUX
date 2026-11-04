"""Readable text from raw pipe-pane logs (a small line-based terminal model).

Raw pane logs keep every byte, including progress bars, line-editor redraws
and colour codes. render() replays them into the text a reader would have
seen; refresh_readable() writes that text next to each raw log as `.txt`.
Only bytes from the raw log are used, so output from periods when logging
was off can never appear in the readable copy. Rendering streams: memory
stays bounded however large the raw log is.
"""

from __future__ import annotations

import codecs
import io
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Callable, TextIO

CSI = re.compile(r"\x1b\[([0-9:;?<>=]*)([ -/]*)([@-~])")
ALTERNATE_SCREEN = {"1049", "47", "1047"}
FULL_SCREEN_MARKER = "[full-screen program]"
WINDOW = 200  # recent lines that cursor movement may still rewrite
SCREEN = 50  # nominal screen height for absolute cursor positioning
LINE_LIMIT = 20_000  # wrap absurdly long lines to keep memory bounded
STRING_LIMIT = 8192  # an OSC/DCS string never runs past this or a newline
PARAMETER_LIMIT = 10**6  # larger numeric parameters behave like this one
CHUNK = 1 << 20
SIZE_LIMIT = 512 * 1024 * 1024
ANNOUNCE = 50 * 1024 * 1024


def _number(part: str) -> int:
    """A CSI numeric parameter; huge digit runs never reach int()."""
    if not part.isdigit():
        return 0
    return PARAMETER_LIMIT if len(part) > 7 else min(int(part), PARAMETER_LIMIT)


class _Sink:
    """Write finished lines, keeping at most two blank lines in a row."""

    def __init__(self, stream: TextIO) -> None:
        self.stream = stream
        self.blanks = 0

    def line(self, text: str) -> None:
        if not text:
            self.blanks = min(self.blanks + 1, 2)
            return
        self.stream.write("\n" * self.blanks + text + "\n")
        self.blanks = 0


class _Terminal:
    def __init__(self, emit: Callable[[str], None]) -> None:
        self.emit = emit
        self.lines: list[list[str]] = [[]]
        self.row = 0
        self.col = 0
        self.saved = (0, 0)
        self.alternate = False

    def line(self) -> list[str]:
        while self.row >= len(self.lines):
            self.lines.append([])
        return self.lines[self.row]

    def put(self, character: str) -> None:
        line = self.line()
        if self.col >= LINE_LIMIT and self.col >= len(line):
            self.newline()
            line = self.line()
        if self.col > len(line):
            line.extend(" " * (self.col - len(line)))
        if self.col == len(line):
            line.append(character)
        else:
            line[self.col] = character
        self.col += 1

    def newline(self) -> None:
        self.row += 1
        self.col = 0
        self.line()
        if len(self.lines) > WINDOW:
            excess = len(self.lines) - WINDOW
            self.flush(self.lines[:excess])
            del self.lines[:excess]
            self.row -= excess

    def flush(self, lines: list[list[str]]) -> None:
        for line in lines:
            self.emit("".join(line).rstrip())

    def clear_screen(self) -> None:
        self.flush(self.lines)
        self.lines = [[]]
        self.row = self.col = 0

    def leave_alternate(self) -> None:
        self.alternate = False
        pending = self.lines[:-1] if not self.lines[-1] else self.lines
        self.flush(pending)
        self.lines = [[]]
        self.row = self.col = 0
        self.emit(FULL_SCREEN_MARKER)

    def csi(self, params: str, final: str) -> None:
        if params.startswith("?"):
            if final in "hl" and ALTERNATE_SCREEN & set(params[1:].split(";")):
                if final == "h" and not self.alternate:
                    self.alternate = True
                elif final == "l" and self.alternate:
                    self.leave_alternate()
            return
        if self.alternate:
            return
        values = [_number(part) for part in params.split(";")]
        first = values[0] if params else 0
        count = max(first, 1)
        line = self.line()
        if final == "K":
            if first == 0:
                del line[self.col :]
            elif first == 1:
                end = min(self.col + 1, len(line))
                line[:end] = [" "] * end
            else:
                line.clear()
        elif final == "J":
            if first in (2, 3):
                self.clear_screen()
            elif first == 0:
                del line[self.col :]
                del self.lines[self.row + 1 :]
        elif final == "A":
            self.row = max(0, self.row - count)
        elif final == "B":
            # Cursor down stops at the bottom of the (nominal) screen.
            bottom = max(len(self.lines), SCREEN) - 1
            self.row = min(self.row + count, max(bottom, self.row))
        elif final == "C":
            self.col = min(self.col + count, LINE_LIMIT)
        elif final == "D":
            self.col = max(0, self.col - count)
        elif final == "G":
            self.col = min(count, LINE_LIMIT) - 1
        elif final in "Hf":
            row = values[0] if params and values[0] else 1
            column = values[1] if len(values) > 1 and values[1] else 1
            top = max(0, len(self.lines) - SCREEN)
            self.row = top + min(row, SCREEN) - 1
            self.col = min(column, LINE_LIMIT) - 1
        elif final == "P":
            del line[self.col : self.col + count]
        elif final == "@":
            # Characters shifted past the right margin are lost, as on a terminal.
            line[self.col : self.col] = [" "] * min(count, LINE_LIMIT)
            del line[LINE_LIMIT:]
        elif final == "X":
            end = min(len(line), self.col + count)
            if end > self.col:
                line[self.col : end] = [" "] * (end - self.col)

    def _string_end(self, data: str, start: int) -> int:
        """End of an OSC/DCS/APC/PM string: BEL, ST, newline, or the limit."""
        limit = min(len(data), start + STRING_LIMIT)
        index = start
        while index < limit:
            character = data[index]
            if character == "\x07":
                return index + 1
            if character == "\x1b" and data.startswith("\x1b\\", index):
                return index + 2
            if character == "\n":
                return index  # leave the newline to be executed
            index += 1
        return index

    def feed(self, data: str) -> None:
        index = 0
        length = len(data)
        while index < length:
            character = data[index]
            if character == "\x1b":
                match = CSI.match(data, index)
                if match:
                    self.csi(match.group(1), match.group(3))
                    index = match.end()
                    continue
                following = data[index + 1 : index + 2]
                if following in ("]", "P", "_", "^"):  # OSC, DCS, APC, PM
                    index = self._string_end(data, index + 2)
                    continue
                if following in ("(", ")", "*", "+", "#"):
                    index += 3
                    continue
                if not following or following < " ":
                    index += 1  # a control after ESC is still executed
                    continue
                if following == "7":
                    self.saved = (self.row, self.col)
                elif following == "8":
                    row, column = self.saved
                    self.row = min(row, max(len(self.lines), SCREEN) - 1)
                    self.col = min(column, LINE_LIMIT)
                index += 2
                continue
            index += 1
            if self.alternate:
                continue
            if character == "\n":
                self.newline()
            elif character == "\r":
                self.col = 0
            elif character == "\b":
                self.col = max(0, self.col - 1)
            elif character == "\t":
                for _ in range(8 - self.col % 8):
                    self.put(" ")
            elif character >= " " and character != "\x7f":
                self.put(character)

    def finish(self) -> None:
        if self.alternate:
            self.leave_alternate()
        else:
            self.flush(self.lines)
        self.lines = [[]]


def _split_point(text: str) -> int:
    """Where a chunk can be cut without splitting an escape sequence."""
    cut = text.rfind("\n")
    if cut >= 0:
        return cut + 1
    if len(text) < 8 * CHUNK:
        return 0
    escape = text.rfind("\x1b", len(text) - 64)
    return escape if escape > 0 else len(text)


def render_stream(source: TextIO | io.BufferedIOBase, output: TextIO) -> None:
    """Render a binary raw-log stream into readable text on `output`."""
    sink = _Sink(output)
    terminal = _Terminal(sink.line)
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    pending = ""
    while True:
        chunk = source.read(CHUNK)
        if not chunk:
            break
        pending += decoder.decode(chunk)
        cut = _split_point(pending)
        if cut:
            terminal.feed(pending[:cut])
            pending = pending[cut:]
    pending += decoder.decode(b"", final=True)
    terminal.feed(pending)
    terminal.finish()


def render(data: bytes) -> str:
    """Replay a raw terminal stream into readable text."""
    output = io.StringIO()
    render_stream(io.BytesIO(data), output)
    return output.getvalue()


def log_target(path: Path) -> str:
    """The `Target:` line from a TACMUX raw-log header ("" when absent)."""
    try:
        with path.open("rb") as stream:
            head = stream.read(512).decode("utf-8", errors="replace")
    except OSError:
        return ""
    match = re.search(r"^Target: (.+)$", head, re.MULTILINE)
    return match.group(1).strip() if match else ""


def _log_files(root: Path, *, scrollback: bool) -> list[Path]:
    logs = root / "logs"
    if not logs.is_dir() or logs.is_symlink():
        return []
    found = []
    for day in sorted(logs.iterdir()):
        if day.is_symlink() or not day.is_dir():
            continue
        for path in sorted(day.glob("*.log")):
            if path.is_symlink() or not path.is_file():
                continue
            if path.name.startswith("scrollback_") == scrollback:
                found.append(path)
    return found


def raw_logs(root: Path) -> list[Path]:
    """Raw pipe-pane logs (the ones that get a readable `.txt` copy)."""
    return _log_files(root, scrollback=False)


def exact_captures(root: Path) -> list[Path]:
    """Prefix+S captures: plain text already, so they need no readable copy."""
    return _log_files(root, scrollback=True)


def readable_path(raw: Path) -> Path:
    return raw.with_suffix(".txt")


def refresh_readable(root: Path, target: str | None = None) -> list[Path]:
    """Write `<raw>.txt` for raw logs that have none or a stale one.

    The copy takes the raw log's mtime as read, so output appended while (or
    after) it was rendered marks it stale for the next refresh.
    """
    written: list[Path] = []
    for raw in raw_logs(root):
        if target is not None and log_target(raw) != (target or "ENGAGEMENT"):
            continue
        destination = readable_path(raw)
        if destination.is_symlink():
            print(
                f"tacmux: refusing linked readable log {destination}", file=sys.stderr
            )
            continue
        info = raw.stat()
        if info.st_size > SIZE_LIMIT:
            print(f"tacmux: skipped {raw.name} (larger than 512 MiB)", file=sys.stderr)
            continue
        if destination.exists() and destination.stat().st_mtime_ns == info.st_mtime_ns:
            continue
        if info.st_size > ANNOUNCE:
            print(
                f"tacmux: rendering {raw.name} ({info.st_size >> 20} MiB)…",
                file=sys.stderr,
            )
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{destination.name}.", dir=destination.parent
        )
        try:
            with (
                raw.open("rb") as source,
                os.fdopen(descriptor, "w", encoding="utf-8") as output,
            ):
                render_stream(source, output)
            os.chmod(temporary, 0o600)
            os.utime(temporary, ns=(info.st_atime_ns, info.st_mtime_ns))
            os.replace(temporary, destination)
        except Exception as exc:  # one bad log never blocks stop or close
            Path(temporary).unlink(missing_ok=True)
            print(f"tacmux: could not render {raw.name}: {exc!r}", file=sys.stderr)
            continue
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise
        written.append(destination)
    return written
