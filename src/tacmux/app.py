"""Transient Textual application for TACMUX v2."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
from typing import ClassVar, Iterable

from textual.app import (
    App,
    SuspendNotSupported,
    SystemCommand,
    get_system_commands_provider,
)
from textual.command import DiscoveryHit, Hit, Hits, Provider
from textual.screen import Screen

from .archive import create_archive
from .config import Settings
from .discovery import DiscoveryJobs
from .errors import ConflictError, SafetyError, TacmuxError, ValidationError
from .nocap import NocapReader
from .screens.cockpit import MainScreen
from .screens.picker import EngagementPickerScreen
from .store import EngagementRecord, Workspace, contained_regular_file
from .terminal_output import iter_rendered
from .themes import BLTSEC_THEME, DEFAULT_THEME
from .tmux import LaunchIntent, TmuxService
from .ui import sentence


class OperatorCommands(Provider):
    """Fuzzy access to the same actions exposed by visible UI controls."""

    def _commands(self) -> list[tuple[str, str, str]]:
        screen = self.screen
        available = getattr(screen, "operator_command_available", None)
        commands = list(getattr(screen, "operator_commands", []))
        return [
            command
            for command in commands
            if available is None or available(command[1])
        ]

    async def discover(self) -> Hits:
        for title, action, help_text in self._commands():
            yield DiscoveryHit(
                title,
                lambda name=action: self.screen.run_operator_command(name),
                help=help_text,
            )

    async def search(self, query: str) -> Hits:
        matcher = self.matcher(query)
        for title, action, help_text in self._commands():
            score = matcher.match(title)
            if score > 0:
                yield Hit(
                    score,
                    matcher.highlight(title),
                    lambda name=action: self.screen.run_operator_command(name),
                    help=help_text,
                )


class TacmuxApp(App[LaunchIntent | None]):
    CSS_PATH = "tacmux.tcss"
    COMMANDS: ClassVar[set] = {get_system_commands_provider, OperatorCommands}

    def __init__(self, settings: Settings):
        super().__init__()
        self.settings = settings
        self.workspace = Workspace(settings)
        self.tmux = TmuxService(settings)
        self.jobs = DiscoveryJobs(settings, self.tmux, self.workspace)
        self.nocap = NocapReader(settings)
        for theme_name in tuple(self.available_themes):
            self.unregister_theme(theme_name)
        self.register_theme(BLTSEC_THEME)
        self.theme = DEFAULT_THEME

    def notify(self, message: str, *args, **kwargs) -> None:
        kwargs.setdefault("markup", False)
        super().notify(str(message), *args, **kwargs)

    def get_system_commands(self, screen: Screen) -> Iterable[SystemCommand]:
        """Expose Textual's useful commands without its irrelevant theme picker."""

        yield from (
            command
            for command in super().get_system_commands(screen)
            if command.title != "Theme"
        )

    def on_mount(self) -> None:
        self.workspace.initialize()
        self.bootstrap()

    def bootstrap(self) -> None:
        records = self.workspace.list_engagements()
        engagement_id, target_id = self.tmux.current_context()
        if not engagement_id and self.settings.startup == "resume_last":
            engagement_id = self.workspace.get_last_engagement()
        record = next(
            (item for item in records if item.engagement.id == engagement_id), None
        )
        if record is not None:
            self.workspace.set_last_engagement(record.engagement.id)
            self.push_screen(MainScreen(record, initial_target_id=target_id))
        else:
            self.push_screen(EngagementPickerScreen())

    def open_engagement(self, record: EngagementRecord) -> None:
        self.workspace.set_last_engagement(record.engagement.id)
        self.switch_screen(MainScreen(record))

    def require_idle_engagement(
        self, engagement_id: str, action: str
    ) -> EngagementRecord:
        record = self.workspace.find(engagement_id)
        engagement = record.engagement
        blockers: list[str] = []
        target_sessions = self.tmux.live_target_ids(engagement)
        if target_sessions:
            blockers.append(f"{len(target_sessions)} target session(s)")

        tmux_available = self.tmux.available()
        if tmux_available and self.tmux.has_session(
            self.tmux.session_name(engagement)
        ):
            blockers.append("operations session")

        jobs = self.jobs.list(record.root)
        active_job_ids = {
            str(job["id"])
            for job in jobs
            if job.get("state") in {"queued", "running"}
        }
        if tmux_available:
            active_job_ids.update(
                str(job["id"])
                for job in jobs
                if self.tmux.has_session(
                    self.tmux.job_session_name(engagement, str(job["id"]))
                )
            )
        if active_job_ids:
            blockers.append(f"{len(active_job_ids)} discovery job(s)")

        if blockers:
            raise ConflictError(
                f"Stop or cancel active work before {action}: " + ", ".join(blockers)
            )
        return record

    def render_runtime_documents(
        self,
        record: EngagementRecord,
        *,
        live_target_ids: set[str] | None = None,
    ) -> int:
        live = (
            self.tmux.live_target_ids(record.engagement)
            if live_target_ids is None
            else live_target_ids
        )
        jobs = self.jobs.list(record.root)
        return self.workspace.render_documents(
            record.root,
            record.engagement,
            live_target_ids=live,
            jobs=jobs,
        )

    def archive_engagement(self, engagement_id: str) -> Path:
        record = self.require_idle_engagement(
            engagement_id, "archiving the engagement"
        )
        self.render_runtime_documents(record, live_target_ids=set())
        archive, _ = create_archive(
            record.root,
            self.settings.archive_dir,
            kind="engagements",
            engagement_id=record.engagement.id,
            object_id=record.engagement.id,
        )
        return archive

    def show_error(self, message: str) -> None:
        self.notify(sentence(message), title="TACMUX", severity="error", timeout=8)

    def edit_file(self, path: Path, *, allowed_root: Path | None = None) -> None:
        try:
            root = allowed_root or self.settings.workspace
            if not contained_regular_file(root, path):
                raise SafetyError(f"file is missing, linked, or outside its engagement: {path}")
            path = path.resolve(strict=True)
            with self.suspend():
                result = subprocess.run(
                    [*self.settings.editor_argv, str(path)], check=False
                )
            if result.returncode:
                self.show_error(f"editor exited with status {result.returncode}")
        except (OSError, ValueError, TacmuxError, SuspendNotSupported) as exc:
            self.show_error(str(exc))

    def page_file(
        self,
        path: Path,
        *,
        terminal_output: bool = False,
        allowed_root: Path | None = None,
    ) -> None:
        try:
            root = allowed_root or self.settings.workspace
            if not contained_regular_file(root, path):
                raise SafetyError(f"file is missing, linked, or outside its engagement: {path}")
            path = path.resolve(strict=True)
            with path.open("rb") as stream:
                if b"\0" in stream.read(64 * 1024):
                    raise ValidationError(
                        "binary evidence cannot be displayed in the terminal pager"
                    )
            candidates = [self.settings.pager_argv, ["less", "-SR"], ["more"]]
            pager = next(
                (argv for argv in candidates if shutil.which(argv[0]) is not None),
                None,
            )
            if pager is None:
                raise ValidationError(
                    "no terminal pager is available; set $PAGER or install less"
                )
            with self.suspend():
                if terminal_output:
                    process = subprocess.Popen(pager, stdin=subprocess.PIPE)
                    assert process.stdin is not None
                    try:
                        with path.open("rb") as stream:
                            for line in iter_rendered(stream):
                                process.stdin.write((line + "\n").encode())
                    except BrokenPipeError:
                        pass
                    finally:
                        try:
                            process.stdin.close()
                        except BrokenPipeError:
                            pass
                        return_code = process.wait()
                else:
                    return_code = subprocess.run(
                        [*pager, str(path)], check=False
                    ).returncode
            if return_code:
                self.show_error(f"pager exited with status {return_code}")
        except (OSError, ValueError, TacmuxError, SuspendNotSupported) as exc:
            self.show_error(str(exc))
