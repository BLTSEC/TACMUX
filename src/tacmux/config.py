"""Small, read-only TOML configuration surface for TACMUX."""

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
        r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)", replace, value
    )
    if re.search(r"\$\{?[A-Za-z_]", expanded):
        raise ValidationError(
            f"path contains an unresolved environment variable: {value}"
        )
    if expanded == "~" or expanded.startswith("~/"):
        expanded = env.get("HOME", str(Path.home())) + expanded[1:]
    return Path(expanded).resolve(strict=False)


def _config_home(env: Mapping[str, str]) -> Path:
    return _expand(env.get("XDG_CONFIG_HOME", "~/.config"), env)


@dataclass(slots=True, frozen=True)
class Settings:
    workspace: Path
    archive_dir: Path
    log_dir: Path
    config_file: Path
    state_file: Path
    auto_log: bool = True
    startup: str = "resume_last"
    include_mermaid: bool = True
    nocap_enabled: bool = False
    session_prefix: str = "tacmux-"

    @property
    def editor_argv(self) -> list[str]:
        value = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "vi"
        try:
            argv = shlex.split(value)
        except ValueError as exc:
            raise ValidationError(f"invalid editor command: {exc}") from exc
        if not argv:
            raise ValidationError("VISUAL or EDITOR resolved to an empty command")
        return argv

    @property
    def pager_argv(self) -> list[str]:
        value = os.environ.get("PAGER") or "less -SR"
        try:
            argv = shlex.split(value)
        except ValueError as exc:
            raise ValidationError(f"invalid pager command: {exc}") from exc
        if not argv:
            raise ValidationError("PAGER resolved to an empty command")
        return argv


def _read_toml(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        with path.open("rb") as stream:
            value = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ValidationError(f"cannot read config {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"config root must be a table: {path}")
    return value


def _boolean(table: dict, key: str, default: bool) -> bool:
    value = table.get(key, default)
    if not isinstance(value, bool):
        raise ValidationError(f"{key} must be true or false")
    return value


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    env = os.environ if environ is None else environ
    default_config = _config_home(env) / "tacmux" / "config.toml"
    config_file = _expand(env.get("TACMUX_CONFIG", str(default_config)), env)
    data = _read_toml(config_file)

    paths = data.get("paths", {})
    behavior = data.get("behavior", {})
    nocap = data.get("nocap", {})
    if (
        not isinstance(paths, dict)
        or not isinstance(behavior, dict)
        or not isinstance(nocap, dict)
    ):
        raise ValidationError(
            "config sections paths, behavior, and nocap must be TOML tables"
        )

    def configured_path(environment_key: str, config_key: str, default: str) -> Path:
        raw = env.get(environment_key, paths.get(config_key, default))
        if not isinstance(raw, str):
            raise ValidationError(f"paths.{config_key} must be a string")
        return _expand(raw, env)

    workspace = configured_path("TACMUX_WORKSPACE", "workspace", "~/workspace")
    archive_dir = configured_path("TACMUX_ARCHIVE_DIR", "archive_dir", "~/archives")
    log_dir = configured_path("TACMUX_LOG_DIR", "log_dir", "~/logs")
    state_file = config_file.parent / "state.json"
    startup = behavior.get("startup", "resume_last")
    if not isinstance(startup, str) or startup not in {"resume_last", "picker"}:
        raise ValidationError("behavior.startup must be 'resume_last' or 'picker'")

    prefix = env.get("TACMUX_SESSION_PREFIX", behavior.get("session_prefix", "tacmux-"))
    if not isinstance(prefix, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", prefix):
        raise ValidationError(
            "session prefix must contain only letters, digits, underscore, dot, or hyphen"
        )

    return Settings(
        workspace=workspace,
        archive_dir=archive_dir,
        log_dir=log_dir,
        config_file=config_file,
        state_file=state_file,
        auto_log=_boolean(behavior, "auto_log", True),
        startup=startup,
        include_mermaid=_boolean(behavior, "include_mermaid", True),
        nocap_enabled=_boolean(nocap, "enabled", False),
        session_prefix=prefix,
    )
