"""Fast internal commands used by tmux hooks and clipboard bindings."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys

from .config import Settings
from .errors import ExternalToolError, ValidationError
from .workspace import Workspace, _private_directory
from .tmux import TmuxService


def _clean(value: str, fallback: str = "pane") -> str:
    result = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")
    return (result or fallback)[:40]


class LogController:
    def __init__(self, settings: Settings, tmux: TmuxService | None = None):
        self.settings = settings
        self.tmux = tmux or TmuxService(settings)

    def _format(self, pane: str, template: str) -> str:
        result = self.tmux.run(
            ["display-message", "-p", "-t", pane, template], check=False
        )
        if result.returncode:
            raise ExternalToolError(
                (result.stderr or "cannot inspect tmux pane").strip()
            )
        return result.stdout.rstrip("\n")

    def _session_environment(self, pane: str, name: str) -> str:
        session = self._format(pane, "#S")
        result = self.tmux.run(
            ["show-environment", "-t", f"={session}", name], check=False
        )
        prefix = f"{name}="
        value = result.stdout.strip()
        return (
            value[len(prefix) :]
            if result.returncode == 0 and value.startswith(prefix)
            else ""
        )

    def _session_option(self, pane: str, name: str) -> str:
        result = self.tmux.run(["show-option", "-qv", "-t", pane, name], check=False)
        return result.stdout.strip() if result.returncode == 0 else ""

    def _disabled(self, pane: str) -> bool:
        if not self.settings.auto_log or not self._session_option(pane, "@tacmux_root"):
            return True
        return (
            self._session_environment(pane, "TACMUX_NO_AUTOLOG") == "1"
            or self._session_environment(pane, "TACMUX_BOOTSTRAP") == "1"
        )

    def _allocate_log(self, pane: str, *, kind: str) -> Path:
        session, window, title, index = self._format(
            pane, "#S\t#W\t#{pane_title}\t#P"
        ).split("\t", 3)
        log_root_value = self._session_option(pane, "@tacmux_log_dir")
        if not log_root_value:
            raise ValidationError("pane is not attached to a TACMUX engagement")
        engagement_root = self._session_option(pane, "@tacmux_root")
        log_root = self._validated_session_log_root(log_root_value, engagement_root)
        date = datetime.now(timezone.utc).strftime("%Y%m%d")
        log_dir = log_root / date
        _private_directory(log_dir)
        prefix = "scrollback_" if kind == "scrollback" else ""
        target = self._session_option(pane, "@tacmux_target_name") or "ENGAGEMENT"
        stem = (
            f"{prefix}{_clean(target)}_{_clean(window)}_"
            f"{_clean(title)}_p{_clean(index, '0')}"
        )
        stamp = datetime.now(timezone.utc).strftime("%H%M%S_%f")
        path = log_dir / f"{stem}_{stamp}.log"
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(
                f"=== TACMUX {kind} log {datetime.now(timezone.utc).isoformat()} ===\n"
                f"Session: {session}\nTarget: {target}\nPane: {pane}\n\n"
            )
        return path

    def _validated_session_log_root(self, value: str, engagement: str) -> Path:
        workspace = Path(os.path.abspath(self.settings.workspace))
        root = Path(os.path.abspath(engagement))
        candidate = Path(os.path.abspath(value))
        try:
            root.resolve(strict=True).relative_to(workspace.resolve(strict=True))
            Workspace(self.settings).require_engagement(root)
            if candidate != root / "logs":
                raise ValidationError(
                    "TACMUX session log directory does not match its engagement"
                )
            relative = candidate.relative_to(root)
            current = root
            for part in relative.parts:
                current /= part
                if current.is_symlink():
                    raise ValidationError(
                        f"refusing linked TACMUX log directory: {value}"
                    )
            candidate.resolve(strict=False).relative_to(root.resolve(strict=True))
        except (OSError, ValueError) as exc:
            raise ValidationError(
                f"invalid TACMUX session log directory: {value}"
            ) from exc
        return candidate

    def start(
        self, pane: str, *, force: bool = False, kind: str = "pane"
    ) -> Path | None:
        if not pane:
            raise ValidationError("no tmux pane was supplied")
        if not force and self._disabled(pane):
            return None
        if self._format(pane, "#{pane_pipe}") == "1":
            existing = self._session_option(pane, "@tacmux_log_file")
            return Path(existing) if existing else None
        path = self._allocate_log(pane, kind=kind)
        pipe_command = f"cat >> {shlex.quote(str(path))}"
        self.tmux.run(["pipe-pane", "-t", pane, "-o", pipe_command])
        self.tmux.run(["set-option", "-p", "-t", pane, "@tacmux_log_file", str(path)])
        self.tmux.run(
            ["display-message", "-t", pane, f"Logging ON: {path.name}"], check=False
        )
        return path

    def stop(self, pane: str) -> None:
        self.tmux.run(["pipe-pane", "-t", pane])
        self.tmux.run(["display-message", "-t", pane, "Logging OFF"], check=False)

    def toggle(self, pane: str) -> Path | None:
        if self._format(pane, "#{pane_pipe}") == "1":
            self.stop(pane)
            return None
        return self.start(pane, force=True)

    def capture(self, pane: str) -> Path:
        if not pane:
            raise ValidationError("no tmux pane was supplied")
        path = self._allocate_log(pane, kind="scrollback")
        result = self.tmux.run(
            ["capture-pane", "-p", "-S", "-", "-t", pane], text=False
        )
        with path.open("ab") as stream:
            stream.write(result.stdout)
        self.tmux.run(
            ["display-message", "-t", pane, f"Scrollback saved: {path.name}"],
            check=False,
        )
        return path

    def status(self, pane: str) -> str:
        active = self._format(pane, "#{pane_pipe}") == "1"
        path = self._session_option(pane, "@tacmux_log_file")
        return f"Logging {'ON' if active else 'OFF'}{f': {path}' if path else ''}"


def clipboard_copy(tmux: TmuxService, data: bytes) -> int:
    if os.environ.get("TMUX") and tmux.available():
        process = subprocess.run([tmux.binary, "load-buffer", "-w", "-"], input=data)
        return process.returncode
    candidates = []
    if os.environ.get("WAYLAND_DISPLAY"):
        candidates.append(["wl-copy"])
    if os.environ.get("DISPLAY"):
        candidates.extend(
            [["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]]
        )
    if sys.platform == "darwin":
        candidates.append(["pbcopy"])
    for command in candidates:
        if shutil.which(command[0]):
            return subprocess.run(command, input=data).returncode
    descriptor: int | None = 2 if os.isatty(2) else None
    close_descriptor = False
    if os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_TTY"):
        try:
            descriptor = os.open("/dev/tty", os.O_WRONLY | getattr(os, "O_NOCTTY", 0))
            close_descriptor = True
        except OSError:
            pass
    if descriptor is not None:
        import base64

        encoded = base64.b64encode(data).decode("ascii")
        try:
            os.write(descriptor, f"\033]52;c;{encoded}\a".encode())
        finally:
            if close_descriptor:
                os.close(descriptor)
        return 0
    raise ExternalToolError("no trusted clipboard path is available")


def status_segment(settings: Settings, tmux: TmuxService) -> str:
    if not os.environ.get("TMUX"):
        return ""
    result = tmux.run(
        [
            "display-message",
            "-p",
            "#{@tacmux_target_name}\t#{@tacmux_root}\t#{pane_pipe}",
        ],
        check=False,
    )
    name, separator, remainder = result.stdout.rstrip("\r\n").partition("\t")
    if not separator:
        return ""
    root, separator, active = remainder.partition("\t")
    if not root:
        return ""
    state = "LOG" if active == "1" else "---"
    color = "green,bold" if active == "1" else "yellow"
    label = (name or Path(root).name).replace("#", "").replace("\n", " ")
    return f"#[fg={color}][{label} {state}]#[default]"
