"""Thin tmux adapter for engagement operations and target sessions."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Mapping, Sequence

from .config import Settings
from .errors import ConflictError, ExternalToolError, ValidationError
from .workspace import Workspace


@dataclass(slots=True, frozen=True)
class Session:
    name: str
    root: Path
    target: str


def _safe_session_part(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "-", value).strip("-")
    return (cleaned or "engagement")[:40]


class TmuxService:
    def __init__(self, settings: Settings, binary: str = "tmux"):
        self.settings = settings
        self.binary = binary

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def run(
        self,
        args: Sequence[str],
        *,
        check: bool = True,
        capture_output: bool = True,
        text: bool = True,
        env: Mapping[str, str] | None = None,
    ) -> subprocess.CompletedProcess:
        try:
            result = subprocess.run(
                [self.binary, *args],
                check=False,
                capture_output=capture_output,
                text=text,
                env=env,
            )
        except OSError as exc:
            raise ExternalToolError(f"cannot execute tmux: {exc}") from exc
        if check and result.returncode:
            detail_value = result.stderr or result.stdout or "tmux command failed"
            detail = (
                detail_value.decode(errors="replace").strip()
                if isinstance(detail_value, bytes)
                else detail_value.strip()
            )
            raise ExternalToolError(detail)
        return result

    def version(self) -> str:
        if not self.available():
            return "not installed"
        result = self.run(["-V"], check=False)
        return result.stdout.strip() if result.returncode == 0 else "unavailable"

    def session_name(self, root: Path, target: str = "") -> str:
        digest = hashlib.sha256(str(root.resolve()).encode()).hexdigest()[:6]
        suffix = (
            f"{_safe_session_part(target)}-"
            f"{hashlib.sha256(target.encode()).hexdigest()[:4]}"
            if target
            else "ops"
        )
        return (
            f"{self.settings.session_prefix}{_safe_session_part(root.name)}-"
            f"{digest}-{suffix}"
        )

    def has_session(self, name: str) -> bool:
        if not self.available():
            return False
        return self.run(["has-session", "-t", f"={name}:"], check=False).returncode == 0

    def sessions(self) -> list[Session]:
        if not self.available():
            return []
        result = self.run(
            [
                "list-sessions",
                "-F",
                "#{session_name}\t#{@tacmux_root}\t#{@tacmux_target_name}",
            ],
            check=False,
        )
        if result.returncode:
            return []
        sessions: list[Session] = []
        for line in result.stdout.splitlines():
            name, separator, remainder = line.partition("\t")
            root, separator_two, target = remainder.partition("\t")
            if separator and separator_two and root:
                sessions.append(Session(name, Path(root), target))
        return sessions

    def current_context(self) -> tuple[Path | None, str]:
        if not os.environ.get("TMUX") or not self.available():
            return None, ""
        result = self.run(
            [
                "display-message",
                "-p",
                "-t",
                os.environ.get("TMUX_PANE", ""),
                "#{@tacmux_root}\t#{@tacmux_target_name}",
            ],
            check=False,
        )
        if result.returncode:
            return None, ""
        root, separator, target = result.stdout.strip().partition("\t")
        return (Path(root), target) if separator and root else (None, "")

    def session_context(self, name: str) -> tuple[Path | None, str]:
        result = self.run(
            [
                "display-message",
                "-p",
                "-t",
                f"={name}:",
                "#{@tacmux_root}\t#{@tacmux_target_name}",
            ],
            check=False,
        )
        if result.returncode:
            return None, ""
        root, separator, target = result.stdout.strip().partition("\t")
        return (Path(root), target) if separator and root else (None, "")

    def start(self, root: Path, target: str = "") -> Session:
        if not self.available():
            raise ExternalToolError("tmux is not installed")
        workspace = Workspace(self.settings)
        workspace.require_engagement(root)
        if target:
            target = workspace.canonical_target(root, target)
            target_root = root / "targets" / target
            details = workspace.target_details(root, target)
            endpoint = details["Endpoint"][0]
            route = details["Capture Route"][0] or target
        else:
            target_root = root
            endpoint = ""
            route = "ops"
        name = self.session_name(root, target)
        environment = {
            "TACMUX_ROOT": str(root),
            "TACMUX_ENGAGEMENT": root.name,
            "TACMUX_TARGET_NAME": target,
            "TACMUX_TARGET": "captures",
            "TARGET": endpoint,
            "NOCAP_WORKSPACE": str(root),
            "NOCAP_ROUTE_PREFIX": route,
            "TACMUX_BOOTSTRAP": "1",
            "TACMUX_NO_AUTOLOG": "0" if self.settings.auto_log else "1",
        }
        options = {
            "@tacmux_root": str(root),
            "@tacmux_target_name": target,
            "@tacmux_log_dir": str(root / "logs"),
        }
        created = False
        pane = ""
        try:
            exists = self.has_session(name)
            if exists:
                existing_root, existing_target = self.session_context(name)
                if (
                    existing_root is None
                    or existing_root.resolve() != root.resolve()
                    or existing_target != target
                ):
                    raise ConflictError(
                        f"refusing to take over unrelated tmux session: {name}"
                    )
            else:
                args = [
                    "new-session",
                    "-d",
                    "-P",
                    "-F",
                    "#{pane_id}",
                    "-s",
                    name,
                    "-c",
                    str(target_root),
                ]
                for key, value in environment.items():
                    args.extend(["-e", f"{key}={value}"])
                pane = self.run(args).stdout.strip()
                created = True
            for key, value in environment.items():
                self.run(["set-environment", "-t", f"={name}:", key, value])
            for key, value in options.items():
                self.run(["set-option", "-t", f"={name}:", key, value])
            if created and pane and self.settings.auto_log:
                from .hooks import LogController

                LogController(self.settings, self).start(
                    pane, force=True, kind="session"
                )
            self.run(["set-environment", "-t", f"={name}:", "TACMUX_BOOTSTRAP", "0"])
        except BaseException:
            if created:
                self.run(["kill-session", "-t", f"={name}:"], check=False)
            raise
        return Session(name, root, target)

    def stop(self, root: Path, target: str = "") -> None:
        name = self.session_name(root, target)
        if not self.has_session(name):
            label = target or "operations"
            raise ConflictError(f"session is not running: {label}")
        self.run(["kill-session", "-t", f"={name}:"])

    def target_running(self, root: Path, target: str) -> bool:
        return self.has_session(self.session_name(root, target))

    def attach(self, session: Session) -> int:
        action = "switch-client" if os.environ.get("TMUX") else "attach-session"
        result = self.run(
            [action, "-t", f"={session.name}:"],
            check=False,
            capture_output=False,
        )
        return result.returncode

    def refresh_target_environment(self, root: Path, old: str, new: str) -> None:
        """Rename is stopped-only; this guard catches callers that skipped policy."""
        if self.target_running(root, old) or self.target_running(root, new):
            raise ConflictError("stop the target session before renaming it")

    def require_stopped(self, root: Path, target: str) -> None:
        if self.target_running(root, target):
            raise ConflictError(f"stop {target} first with: tacmux stop {target}")

    def validate_session_root(self, session: Session) -> None:
        try:
            session.root.resolve().relative_to(self.settings.workspace.resolve())
        except ValueError as exc:
            raise ValidationError(
                f"tmux session points outside the workspace: {session.name}"
            ) from exc
