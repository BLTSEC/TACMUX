"""Thin tmux adapter; persistent truth stays in engagement manifests."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import shlex
import subprocess
from typing import Mapping, Sequence

from .config import Settings
from .errors import ConflictError, ExternalToolError, ValidationError
from .model import Engagement, Target


@dataclass(slots=True, frozen=True)
class LaunchIntent:
    session_name: str


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

    def session_name(self, engagement: Engagement, target: Target | None = None) -> str:
        suffix = target.id if target else "ops"
        return f"{self.settings.session_prefix}{engagement.id}-{suffix}"

    def job_session_name(self, engagement: Engagement, job_id: str) -> str:
        return f"{self.settings.session_prefix}{engagement.id}-job-{job_id}"

    def has_session(self, session_name: str) -> bool:
        return (
            self.run(["has-session", "-t", f"={session_name}:"], check=False).returncode
            == 0
        )

    def target_session_running(self, engagement: Engagement, target: Target) -> bool:
        return self.has_session(self.session_name(engagement, target))

    def live_target_ids(self, engagement: Engagement) -> set[str]:
        return self.live_target_ids_by_engagement().get(engagement.id, set())

    def live_target_ids_by_engagement(self) -> dict[str, set[str]]:
        if not self.available():
            return {}
        result = self.run(
            [
                "list-sessions",
                "-F",
                "#{@tacmux_engagement_id}\t#{@tacmux_target_id}",
            ],
            check=False,
        )
        if result.returncode:
            return {}
        target_ids: dict[str, set[str]] = {}
        for line in result.stdout.splitlines():
            engagement_id, separator, target_id = line.partition("\t")
            if separator and engagement_id and target_id:
                target_ids.setdefault(engagement_id, set()).add(target_id)
        return target_ids

    def current_context(self) -> tuple[str, str]:
        if not os.environ.get("TMUX") or not self.available():
            return "", ""
        pane = os.environ.get("TMUX_PANE", "")
        target = pane or ""
        result = self.run(
            [
                "display-message",
                "-p",
                "-t",
                target,
                "#{@tacmux_engagement_id}\t#{@tacmux_target_id}",
            ],
            check=False,
        )
        if result.returncode:
            return "", ""
        engagement_id, separator, target_id = result.stdout.strip().partition("\t")
        return (engagement_id, target_id) if separator else ("", "")

    def start_target(
        self,
        engagement_root: Path,
        engagement: Engagement,
        target: Target,
        *,
        start_logging: bool | None = None,
    ) -> LaunchIntent:
        if not self.available():
            raise ExternalToolError("tmux is not installed")
        session = self.session_name(engagement, target)
        target_root = engagement_root / "targets" / target.directory
        if not target_root.is_dir():
            raise ValidationError(f"target directory is missing: {target_root}")
        primary = target.primary_endpoint or (
            target.addresses[0].value if target.addresses else ""
        )
        route = str(target_root.relative_to(self.settings.workspace))
        logging_enabled = self.settings.auto_log and (
            engagement.logging_enabled if start_logging is None else start_logging
        )
        environment = {
            "TACMUX_ENGAGEMENT_ID": engagement.id,
            "TACMUX_ENGAGEMENT": engagement.name,
            "TACMUX_TARGET_ID": target.id,
            "TACMUX_TARGET_NAME": target.display_name,
            "TACMUX_TARGET": route,
            "TARGET": primary,
            "TACMUX_BOOTSTRAP": "1",
            "TACMUX_NO_AUTOLOG": "0" if logging_enabled else "1",
        }
        if self.settings.nocap_enabled:
            environment["NOCAP_WORKSPACE"] = str(self.settings.workspace)
        options = {
            "@tacmux_engagement_id": engagement.id,
            "@tacmux_target_id": target.id,
            "@tacmux_target_name": target.display_name,
            "@tacmux_target_dir": str(target_root),
            "@tacmux_log_dir": str(target_root / "logs"),
        }
        return self._start_session(
            session,
            target_root,
            environment,
            options,
            logging_enabled=logging_enabled,
            removed_environment=()
            if self.settings.nocap_enabled
            else ("NOCAP_WORKSPACE",),
        )

    def start_targets_detached(
        self,
        engagement_root: Path,
        engagement: Engagement,
        targets: Sequence[Target],
    ) -> list[str]:
        return [
            self.start_target(engagement_root, engagement, target).session_name
            for target in targets
        ]

    def start_ops(self, engagement_root: Path, engagement: Engagement) -> LaunchIntent:
        if not self.available():
            raise ExternalToolError("tmux is not installed")
        session = self.session_name(engagement)
        logging_enabled = self.settings.auto_log and engagement.logging_enabled
        environment = {
            "TACMUX_ENGAGEMENT_ID": engagement.id,
            "TACMUX_ENGAGEMENT": engagement.name,
            "TACMUX_TARGET_ID": "",
            "TACMUX_TARGET_NAME": "",
            "TACMUX_TARGET": "",
            "TACMUX_BOOTSTRAP": "1",
            "TACMUX_NO_AUTOLOG": "0" if logging_enabled else "1",
        }
        if self.settings.nocap_enabled:
            environment["NOCAP_WORKSPACE"] = str(self.settings.workspace)
        options = {
            "@tacmux_engagement_id": engagement.id,
            "@tacmux_target_id": "",
            "@tacmux_target_name": "",
            "@tacmux_target_dir": str(engagement_root),
            "@tacmux_log_dir": str(engagement_root / "logs"),
        }
        return self._start_session(
            session,
            engagement_root,
            environment,
            options,
            logging_enabled=logging_enabled,
            removed_environment=()
            if self.settings.nocap_enabled
            else ("NOCAP_WORKSPACE",),
        )

    def _start_session(
        self,
        session: str,
        working_directory: Path,
        environment: Mapping[str, str],
        options: Mapping[str, str],
        *,
        logging_enabled: bool,
        removed_environment: Sequence[str] = (),
    ) -> LaunchIntent:
        args = [
            "new-session",
            "-d",
            "-P",
            "-F",
            "#{pane_id}",
            "-s",
            session,
            "-c",
            str(working_directory),
        ]
        for key, value in environment.items():
            args.extend(["-e", f"{key}={value}"])
        if removed_environment:
            unset = " ".join(f"-u {shlex.quote(key)}" for key in removed_environment)
            shell = shlex.quote(os.environ.get("SHELL") or "/bin/sh")
            args.append(f"exec env {unset} {shell}")
        created = False
        pane_id = ""
        try:
            if not self.has_session(session):
                result = self.run(args)
                pane_id = result.stdout.strip()
                created = True
            for key, value in environment.items():
                self.run(["set-environment", "-t", f"={session}:", key, value])
            for key in removed_environment:
                self.run(["set-environment", "-r", "-t", f"={session}:", key])
            for name, value in options.items():
                self.run(["set-option", "-t", f"={session}:", name, value])
            if logging_enabled and pane_id:
                from .hooks import LogController

                LogController(self.settings, self).start(
                    pane_id, force=True, kind="session"
                )
            self.run(["set-environment", "-t", f"={session}:", "TACMUX_BOOTSTRAP", "0"])
        except BaseException:
            if created:
                self.run(["kill-session", "-t", f"={session}:"], check=False)
            raise
        return LaunchIntent(session)

    def stop_target(self, engagement: Engagement, target: Target) -> None:
        session = self.session_name(engagement, target)
        if not self.has_session(session):
            raise ConflictError(f"target session is not running: {target.display_name}")
        self.run(["kill-session", "-t", f"={session}:"])

    def stop_ops(self, engagement: Engagement) -> None:
        session = self.session_name(engagement)
        if not self.has_session(session):
            raise ConflictError("engagement operations session is not running")
        self.run(["kill-session", "-t", f"={session}:"])

    def stop_engagement_sessions(self, engagement: Engagement) -> int:
        sessions = [
            self.session_name(engagement, target) for target in engagement.targets
        ]
        sessions.append(self.session_name(engagement))
        stopped = 0
        for session in sessions:
            if self.has_session(session):
                self.run(["kill-session", "-t", f"={session}:"])
                stopped += 1
        return stopped

    def attach(self, intent: LaunchIntent) -> int:
        action = "switch-client" if os.environ.get("TMUX") else "attach-session"
        result = self.run(
            [action, "-t", f"={intent.session_name}:"],
            check=False,
            capture_output=False,
        )
        return result.returncode
