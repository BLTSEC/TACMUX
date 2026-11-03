"""Evidence helpers: offer the latest capture, take screenshots, attach later."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

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
    return record


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
) -> bool:
    """Take the screenshot after any popup closes, then attach it to the entry."""
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
    if os.environ.get("TMUX") and shutil.which("tmux"):
        # The palette popup closes as soon as this process exits; the delay
        # makes sure it is gone before flameshot freezes the screen.
        _SCHEDULED = True
        subprocess.run(
            ["tmux", "run-shell", "-b", f"sleep {delay}; {command}"], check=False
        )
        print(f"Screenshot: select a region for {identifier} (Esc cancels).")
        return True
    return take_screenshot(workspace, root, target, identifier) is not None


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
