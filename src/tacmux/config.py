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
    snapshot_on_stop: bool = True
    shell_log_dirs: tuple[Path, ...] = ()

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
    integrations = data.get("integrations", {})
    if not all(isinstance(table, dict) for table in (paths, behavior, integrations)):
        raise ValidationError("paths, behavior, and integrations must be TOML tables")
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
    snapshot_on_stop = behavior.get("snapshot_on_stop", True)
    if not isinstance(snapshot_on_stop, bool):
        raise ValidationError("behavior.snapshot_on_stop must be true or false")
    shell_dirs = integrations.get("shell_log_dirs", ["~/.penelope/sessions"])
    if not isinstance(shell_dirs, list) or not all(
        isinstance(value, str) and value.strip() for value in shell_dirs
    ):
        raise ValidationError("integrations.shell_log_dirs must be a list of paths")
    return Settings(
        workspace=_expand(workspace_value, env),
        config_file=config_file,
        sitrep_root=_expand(sitrep_value, env) if sitrep_value.strip() else None,
        auto_log=auto_log,
        session_prefix=prefix,
        snapshot_on_stop=snapshot_on_stop,
        shell_log_dirs=tuple(_expand(value, env) for value in shell_dirs),
    )
