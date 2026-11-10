"""Evidence helpers: offer the latest capture, take screenshots, attach later."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time
from typing import Sequence

from . import sitrep
from .errors import TacmuxError
from .interaction import confirm, forced_noninteractive, text_input_available
from .workspace import CaptureRecord, Workspace

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_SCHEDULED = False


def screenshot_scheduled() -> bool:
    """True once this process has queued a screenshot (the popup must close)."""
    return _SCHEDULED


# Variables a GUI screenshot tool needs when started from a tmux job.
GUI_ENVIRONMENT = (
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
)


def latest_unattached_capture(
    workspace: Workspace, root: Path, target: str
) -> CaptureRecord | None:
    """The route's latest finished NOCAP capture, unless an entry already has it."""
    if not shutil.which("cap"):
        return None
    try:
        record = workspace.inspect_capture(root, target)
        events = sitrep.read_events(workspace.read(root))
    except TacmuxError:
        return None
    if any(event.capture_id == record.identifier for event in events):
        return None
    # Only output that is new since this target's last entry: an older scan
    # was already passed over, so it is not offered again at every entry.
    finished = _moment(record.finished)
    if finished is not None and any(
        event.target == target
        and (logged := _moment(event.timestamp)) is not None
        and _passed_over(finished, logged)
        for event in events
    ):
        return None
    return record


def _passed_over(finished: datetime, logged: datetime) -> bool:
    """True when an entry was logged after (or alongside) the capture finished.

    Entries are stored to the second, so an entry covers its whole second: a
    capture that finished anywhere in that second counts as passed over. Older
    entries with fractional seconds compare exactly.
    """
    if logged.microsecond:
        return finished <= logged
    return finished < logged + timedelta(seconds=1)


def _moment(value: str) -> datetime | None:
    try:
        moment = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def offer_capture(
    workspace: Workspace, root: Path, target: str
) -> CaptureRecord | None:
    """Ask (default yes) to attach the latest unattached capture; never in scripts."""
    if forced_noninteractive() or not text_input_available():
        return None
    record = latest_unattached_capture(workspace, root, target)
    if record is None:
        return None
    command = record.command if len(record.command) <= 70 else record.command[:69] + "…"
    return (
        record
        if confirm(f"Attach capture {record.tool}: {command}?", default=True)
        else None
    )


def _notify(message: str) -> None:
    if os.environ.get("TMUX") and shutil.which("tmux"):
        subprocess.run(["tmux", "display-message", message], check=False)
    else:
        print(message)


def schedule_screenshot(
    workspace: Workspace,
    root: Path,
    target: str,
    identifier: str,
    *,
    delay: str = "0.4",
    then: Sequence[str] | None = None,
    wait: bool = False,
) -> bool:
    """Take the screenshot after any popup closes, then attach it to the entry.

    `then` runs once the shot finishes (flameshot blocks until you select).
    With `wait`, capture inline, after the delay, so this terminal can safely
    continue to an interactive close-out only after the screenshot finishes.
    """
    if not shutil.which("flameshot"):
        print(
            "tacmux: flameshot is not installed; attach an image later with "
            "tm → 📷 Screenshot → entry, or tm log edit",
            file=sys.stderr,
        )
        return False
    executable = shutil.which("tacmux") or str(Path.home() / ".local/bin/tacmux")
    environment = [
        f"{name}={os.environ[name]}" for name in GUI_ENVIRONMENT if os.environ.get(name)
    ]
    command = shlex.join(
        [
            "env",
            *environment,
            executable,
            "_internal",
            "shot",
            str(root),
            target,
            identifier,
        ]
    )
    global _SCHEDULED
    if not wait and os.environ.get("TMUX") and shutil.which("tmux"):
        # The palette popup closes as soon as this process exits; the delay
        # makes sure it is gone before flameshot freezes the screen.
        follow = f"; {shlex.join(then)}" if then else ""
        try:
            result = subprocess.run(
                ["tmux", "run-shell", "-b", f"sleep {delay}; {command}{follow}"],
                check=False,
                capture_output=True,
                text=True,
            )
        except OSError as exc:
            print(f"tacmux: could not schedule screenshot: {exc}", file=sys.stderr)
            return False
        if result.returncode:
            detail = (
                result.stderr or result.stdout or f"tmux exited {result.returncode}"
            ).strip()
            print(f"tacmux: could not schedule screenshot: {detail}", file=sys.stderr)
            return False
        _SCHEDULED = True
        print(f"Screenshot: select a region for {identifier} (Esc cancels).")
        return True
    if wait:
        time.sleep(float(delay))
    captured = take_screenshot(workspace, root, target, identifier) is not None
    if then:
        subprocess.run(then, check=False)
    return captured


def take_screenshot(
    workspace: Workspace, root: Path, target: str, identifier: str
) -> Path | None:
    """Run flameshot, store the PNG under the target, and attach it to the entry."""
    try:
        result = subprocess.run(
            ["flameshot", "gui", "--raw"],
            capture_output=True,
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        _notify(f"tacmux: screenshot failed: {exc}")
        return None
    data = result.stdout or b""
    if not data.startswith(PNG_SIGNATURE):
        _notify(
            f"Screenshot cancelled; attach later: tm → 📷 Screenshot → {identifier}"
        )
        return None
    folder = root / "targets" / target / "screenshots"
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = folder / f"{identifier}-{stamp}.png"
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
    workspace.change_label = f"screenshot → {identifier}"
    try:
        workspace.attach_to_event(root, identifier, images=[path])
    except TacmuxError as exc:
        _notify(f"tacmux: screenshot saved to {path} but not attached: {exc}")
        return path
    _notify(f"Screenshot attached to {identifier}")
    return path
