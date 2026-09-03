"""Small read-only configuration surface for TACMUX v3."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import shlex
import tomllib
from typing import Mapping

from .errors import ValidationError


def _expand(value: str, env: Mapping[str, str]) -> Path:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        return env.get(name, match.group(0))

    expanded = re.sub(
        r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)",
        replace,
        value,
    )
    if re.search(r"\$\{?[A-Za-z_]", expanded):
        raise ValidationError(f"unresolved environment variable in path: {value}")
    if expanded == "~" or expanded.startswith("~/"):
        expanded = env.get("HOME", str(Path.home())) + expanded[1:]
    return Path(expanded).resolve(strict=False)


@dataclass(slots=True, frozen=True)
class Settings:
    workspace: Path
    config_file: Path
    sitrep_root: Path | None = None
    auto_log: bool = True
    session_prefix: str = "tacmux-"

    @property
    def editor_argv(self) -> list[str]:
        value = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "vi"
        try:
            argv = shlex.split(value)
        except ValueError as exc:
            raise ValidationError(f"invalid editor command: {exc}") from exc
        if not argv:
            raise ValidationError("VISUAL or EDITOR is empty")
        return argv


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    env = os.environ if environ is None else environ
    config_home = _expand(env.get("XDG_CONFIG_HOME", "~/.config"), env)
    config_file = _expand(
        env.get("TACMUX_CONFIG", str(config_home / "tacmux/config.toml")), env
    )
    data: dict = {}
    if config_file.is_file():
        try:
            with config_file.open("rb") as stream:
                data = tomllib.load(stream)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ValidationError(f"cannot read config {config_file}: {exc}") from exc
    paths = data.get("paths", {})
    behavior = data.get("behavior", {})
    if not isinstance(paths, dict) or not isinstance(behavior, dict):
        raise ValidationError("paths and behavior must be TOML tables")
    workspace_value = env.get("TACMUX_WORKSPACE", paths.get("workspace", "~/workspace"))
    if not isinstance(workspace_value, str):
        raise ValidationError("paths.workspace must be a string")
    sitrep_value = env.get("TACMUX_SITREP_ROOT", paths.get("sitrep_root", ""))
    if not isinstance(sitrep_value, str):
        raise ValidationError("paths.sitrep_root must be a string")
    auto_log = behavior.get("auto_log", True)
    if not isinstance(auto_log, bool):
        raise ValidationError("behavior.auto_log must be true or false")
    prefix = env.get("TACMUX_SESSION_PREFIX", behavior.get("session_prefix", "tacmux-"))
    if not isinstance(prefix, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", prefix):
        raise ValidationError("session_prefix contains unsupported characters")
    return Settings(
        workspace=_expand(workspace_value, env),
        config_file=config_file,
        sitrep_root=_expand(sitrep_value, env) if sitrep_value.strip() else None,
        auto_log=auto_log,
        session_prefix=prefix,
    )
