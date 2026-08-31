"""Small helpers for rendering operator-controlled text literally."""

from rich.text import Text


def plain(value: object) -> Text:
    return Text(str(value))


def sentence(value: object) -> str:
    message = str(value).strip()
    return message[:1].upper() + message[1:] if message else message
