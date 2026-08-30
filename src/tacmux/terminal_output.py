"""Small line-oriented terminal renderer for captured command output."""

from __future__ import annotations

import codecs
from collections.abc import Iterator
from io import BytesIO
from typing import BinaryIO


_COLUMN_LIMIT = 500


class TerminalLine:
    """Apply common cursor controls without pretending to be a full terminal."""

    def __init__(self) -> None:
        self.buffer: list[str] = []
        self.column = 0
        self.mode = "text"
        self.escape = ""
        self.osc_escape = False

    def flush(self) -> str:
        line = "".join(self.buffer).rstrip()
        self.buffer = []
        self.column = 0
        return line

    def _csi(self, value: str) -> None:
        final = value[-1:] or ""
        try:
            params = [
                int(item) if item else 0
                for item in value[:-1].lstrip("?").split(";")
            ]
        except ValueError:
            params = [0]
        amount = params[0] if params else 0
        if final == "D":
            self.column = max(0, self.column - (amount or 1))
        elif final == "C":
            self.column = min(self.column + (amount or 1), _COLUMN_LIMIT)
        elif final == "G":
            self.column = min(max(0, (amount or 1) - 1), _COLUMN_LIMIT)
        elif final == "K":
            if amount == 0:
                self.buffer = self.buffer[: self.column]
            elif amount == 1:
                if self.column > len(self.buffer):
                    self.buffer.extend([" "] * (self.column - len(self.buffer)))
                for index in range(min(self.column + 1, len(self.buffer))):
                    self.buffer[index] = " "
            elif amount == 2:
                self.buffer = []
                self.column = 0
        elif final == "J" and amount in {0, 2}:
            self.buffer = self.buffer[: self.column] if amount == 0 else []
            if amount == 2:
                self.column = 0

    def feed(self, text: str) -> list[str]:
        lines: list[str] = []
        for char in text:
            if self.mode == "osc":
                if char == "\x07" or (self.osc_escape and char == "\\"):
                    self.mode = "text"
                    self.osc_escape = False
                else:
                    self.osc_escape = char == "\x1b"
                continue
            if self.mode == "esc":
                if char == "[":
                    self.mode = "csi"
                    self.escape = ""
                elif char == "]":
                    self.mode = "osc"
                    self.osc_escape = False
                else:
                    self.mode = "text"
                continue
            if self.mode == "csi":
                self.escape += char
                if "@" <= char <= "~":
                    self._csi(self.escape)
                    self.mode = "text"
                    self.escape = ""
                elif len(self.escape) > 64:
                    self.mode = "text"
                    self.escape = ""
                continue

            if char == "\x1b":
                self.mode = "esc"
            elif char == "\n":
                lines.append(self.flush())
            elif char == "\r":
                self.column = 0
            elif char == "\x08":
                self.column = max(0, self.column - 1)
            elif char == "\t":
                stop = min(((self.column // 8) + 1) * 8, _COLUMN_LIMIT)
                if stop > len(self.buffer):
                    self.buffer.extend([" "] * (stop - len(self.buffer)))
                self.column = stop
            elif ord(char) < 0x20 or char == "\x7f":
                continue
            else:
                if self.column < len(self.buffer):
                    self.buffer[self.column] = char
                else:
                    if self.column > len(self.buffer):
                        self.buffer.extend([" "] * (self.column - len(self.buffer)))
                    self.buffer.append(char)
                self.column += 1
        return lines


def iter_rendered(stream: BinaryIO, chunk_size: int = 65_536) -> Iterator[str]:
    terminal = TerminalLine()
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    for chunk in iter(lambda: stream.read(chunk_size), b""):
        yield from terminal.feed(decoder.decode(chunk))
    yield from terminal.feed(decoder.decode(b"", final=True))
    if terminal.buffer:
        yield terminal.flush()


def render_sample(data: bytes) -> str:
    return "\n".join(iter_rendered(BytesIO(data)))
