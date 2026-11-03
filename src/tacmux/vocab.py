"""Forgiving matching for TACMUX's fixed vocabularies (outcomes, access, fields)."""

from __future__ import annotations

from typing import Mapping, Sequence

from .errors import ValidationError

# Free-text commands (tm log) only treat these exact first words as outcomes, so
# a summary such as "in progress" is never mistaken for the outcome "info".
LOG_OUTCOME_SHORTCUTS: Mapping[str, str] = {
    "f": "failed",
    "p": "partial",
    "s": "success",
}
OUTCOME_ALIASES: Mapping[str, str] = {
    **LOG_OUTCOME_SHORTCUTS,
    "fail": "failed",
    "ok": "success",
}
ACCESS_ALIASES: Mapping[str, str] = {
    "auth": "authenticated",
    "login": "authenticated",
    "shell": "user",
    "root": "admin",
    "adm": "admin",
    "sys": "system",
    "da": "domain",
}
STATUS_ALIASES: Mapping[str, str] = {"done": "complete", "act": "active"}
FIELD_ALIASES: Mapping[str, str] = {
    "as": "principal",
    "via": "method",
    "path": "method",
    "host": "hostnames",
    "hostname": "hostnames",
    "ip": "endpoint",
}


class AmbiguousWordError(ValidationError):
    """A word matched several vocabulary entries (or none)."""

    def __init__(self, message: str, candidates: Sequence[str]):
        super().__init__(message)
        self.candidates = tuple(candidates)


def match_word(
    word: str,
    choices: Sequence[str],
    aliases: Mapping[str, str] | None = None,
    label: str = "value",
) -> str:
    """Resolve exact → alias → unique prefix (case-insensitive)."""
    value = word.strip().casefold()
    lowered = {choice.casefold(): choice for choice in choices}
    if value in lowered:
        return lowered[value]
    if aliases and value in aliases and aliases[value] in choices:
        return aliases[value]
    candidates = [choice for choice in choices if choice.casefold().startswith(value)]
    if value and len(candidates) == 1:
        return candidates[0]
    accepted = ", ".join(choices)
    if candidates:
        raise AmbiguousWordError(
            f"{label} '{word}' is ambiguous: {', '.join(candidates)}", candidates
        )
    raise AmbiguousWordError(f"unknown {label} '{word}'; use one of: {accepted}", [])


def is_word(
    word: str, choices: Sequence[str], aliases: Mapping[str, str] | None = None
) -> bool:
    try:
        match_word(word, choices, aliases)
    except ValidationError:
        return False
    return True
