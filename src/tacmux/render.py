"""Readable text from raw pipe-pane logs (a small line-based terminal model).

Raw pane logs keep every byte, including progress bars, line-editor redraws
and colour codes. render() replays them into the text a reader would have
seen; refresh_readable() writes that text next to each raw log as `.txt`.
Only bytes from the raw log are used, so output from periods when logging
was off can never appear in the readable copy.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import sys
import tempfile

CSI = re.compile(r"\x1b\[([0-9;?<>=]*)([ -/]*)([@-~])")
ALTERNATE_SCREEN = {"1049", "47", "1047"}
FULL_SCREEN_MARKER = "[full-screen program]"
WINDOW = 200
SCREEN = 50
SIZE_LIMIT = 512 * 1024 * 1024


class _Terminal:
    def __init__(self) -> None:
        self.out: list[str] = []
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
        self.out.extend("".join(line).rstrip() for line in lines)

    def clear_screen(self) -> None:
        self.flush(self.lines)
        self.lines = [[]]
        self.row = self.col = 0

    def csi(self, params: str, final: str) -> None:
        if params.startswith("?"):
            if final in "hl" and ALTERNATE_SCREEN & set(params[1:].split(";")):
                if final == "h" and not self.alternate:
                    self.alternate = True
                elif final == "l" and self.alternate:
                    self.alternate = False
                    pending = self.lines[:-1] if not self.lines[-1] else self.lines
                    self.flush(pending)
                    self.lines = [[]]
                    self.row = self.col = 0
                    self.out.append(FULL_SCREEN_MARKER)
            return
        if self.alternate:
            return
        values = [int(part) if part.isdigit() else 0 for part in params.split(";")]
        first = values[0] if params else 0
        count = max(first, 1)
        line = self.line()
        if final == "K":
            if first == 0:
                del line[self.col :]
            elif first == 1:
                for index in range(min(self.col + 1, len(line))):
                    line[index] = " "
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
            self.row += count
        elif final == "C":
            self.col += count
        elif final == "D":
            self.col = max(0, self.col - count)
        elif final == "G":
            self.col = count - 1
        elif final in "Hf":
            row = values[0] if params and values[0] else 1
            column = values[1] if len(values) > 1 and values[1] else 1
            top = max(0, len(self.lines) - SCREEN)
            self.row = top + row - 1
            self.col = column - 1
        elif final == "P":
            del line[self.col : self.col + count]
        elif final == "@":
            line[self.col : self.col] = [" "] * count
        elif final == "X":
            for index in range(self.col, min(len(line), self.col + count)):
                line[index] = " "

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
                if following in ("]", "P", "_", "^"):  # OSC, DCS, APC, PM strings
                    end = index + 2
                    while end < length:
                        if data[end] == "\x07":
                            end += 1
                            break
                        if data.startswith("\x1b\\", end):
                            end += 2
                            break
                        end += 1
                    index = end
                    continue
                if following in ("(", ")", "*", "+", "#"):
                    index += 3
                    continue
                if following == "7":
                    self.saved = (self.row, self.col)
                elif following == "8":
                    self.row, self.col = self.saved
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

    def text(self) -> str:
        self.flush(self.lines)
        self.lines = [[]]
        collapsed: list[str] = []
        for line in self.out:
            if (
                not line
                and len(collapsed) >= 2
                and not collapsed[-1]
                and not collapsed[-2]
            ):
                continue
            collapsed.append(line)
        while collapsed and not collapsed[-1]:
            collapsed.pop()
        return "\n".join(collapsed) + "\n" if collapsed else ""


def render(data: bytes) -> str:
    """Replay a raw terminal stream into readable text."""
    terminal = _Terminal()
    terminal.feed(data.decode("utf-8", errors="replace"))
    return terminal.text()


def log_target(path: Path) -> str:
    """The `Target:` line from a TACMUX raw-log header ("" when absent)."""
    try:
        with path.open("rb") as stream:
            head = stream.read(512).decode("utf-8", errors="replace")
    except OSError:
        return ""
    match = re.search(r"^Target: (.+)$", head, re.MULTILINE)
    return match.group(1).strip() if match else ""


def raw_logs(root: Path) -> list[Path]:
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
            if path.name.startswith("scrollback_"):
                continue
            found.append(path)
    return found


def readable_path(raw: Path) -> Path:
    return raw.with_suffix(".txt")


def refresh_readable(root: Path, target: str | None = None) -> list[Path]:
    """Write `<raw>.txt` for raw logs that have none or a stale one."""
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
        if destination.exists() and destination.stat().st_mtime_ns >= info.st_mtime_ns:
            continue
        text = render(raw.read_bytes())
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{destination.name}.", dir=destination.parent
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(text)
            os.chmod(temporary, 0o600)
            os.replace(temporary, destination)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise
        written.append(destination)
    return written
