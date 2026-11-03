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


def _toml_string(value: str) -> str:
    if any(ord(character) < 32 for character in value):
        raise ValidationError("path contains control characters")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def display_path(path: Path, env: Mapping[str, str] | None = None) -> str:
    """Show a path under HOME as ~/…, for config files and messages."""
    home = Path((os.environ if env is None else env).get("HOME", str(Path.home())))
    try:
        relative = path.relative_to(home.resolve(strict=False))
    except ValueError:
        return str(path)
    return "~" if not relative.parts else f"~/{relative}"


def write_sitrep_root(config_file: Path, root: Path | None) -> None:
    """Set [paths] sitrep_root in place, keeping every other line and comment."""
    value = display_path(root) if root is not None else ""
    line = f"sitrep_root = {_toml_string(value)}\n"
    if config_file.is_symlink():
        raise ValidationError(f"refusing linked config: {config_file}")
    text = config_file.read_text(encoding="utf-8") if config_file.exists() else ""
    lines = text.splitlines(keepends=True)
    header = re.compile(r"^\s*\[paths\]\s*(#.*)?$")
    table = re.compile(r"^\s*\[")
    key = re.compile(r"^\s*sitrep_root\s*=")
    start = next((i for i, item in enumerate(lines) if header.match(item)), None)
    if start is None:
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        lines += (["\n"] if lines else []) + ["[paths]\n", line]
    else:
        end = next(
            (i for i in range(start + 1, len(lines)) if table.match(lines[i])),
            len(lines),
        )
        existing = next((i for i in range(start + 1, end) if key.match(lines[i])), None)
        if existing is None:
            lines.insert(start + 1, line)
        else:
            lines[existing] = line
    updated = "".join(lines)
    try:
        data = tomllib.loads(updated)
    except tomllib.TOMLDecodeError as exc:
        raise ValidationError(f"config rewrite would be invalid: {exc}") from exc
    if data.get("paths", {}).get("sitrep_root") != value:
        raise ValidationError("config rewrite did not set sitrep_root")
    config_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    mode = config_file.stat().st_mode & 0o777 if config_file.exists() else 0o600
    temporary = config_file.with_name(f".{config_file.name}.{os.getpid()}.tmp")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(updated)
        os.replace(temporary, config_file)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
