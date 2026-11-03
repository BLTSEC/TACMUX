"""`tm notes`: choose the folder where new engagements keep their SITREP.

Each engagement remembers its own notes folder (`.tacmux/notes_root`), so
switching the folder for new work never hides or moves existing engagements.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Sequence

from .config import Settings, display_path, write_sitrep_root
from .errors import TacmuxError, ValidationError
from .interaction import ask, can_prompt, choose, confirm
from .vocab import match_word
from .workspace import Workspace

NONE_WORDS = {"none", "local", "workspace"}
NEW_FOLDER = "\x1fnew"
OTHER_PATH = "\x1fother"
WORKSPACE_ONLY = "\x1fnone"
MOVE = "\x1fmove"


def engagement_folders(workspace: Workspace) -> dict[Path, list[str]]:
    """Notes folder → engagement names stored there (external notes only)."""
    folders: dict[Path, list[str]] = {}
    for root in workspace.engagement_candidates():
        if not (root / "SITREP.md").is_symlink():
            continue
        try:
            folder = workspace.notes_root(root)
        except (TacmuxError, OSError):
            continue
        folders.setdefault(folder, []).append(root.name)
    return folders


def _subfolders(folder: Path) -> list[Path]:
    if not folder.is_dir():
        return []
    try:
        children = list(folder.iterdir())
    except OSError:
        return []
    return sorted(
        (
            child
            for child in children
            if child.is_dir()
            and not child.is_symlink()
            and not child.name.startswith(".")
            and not (child / "SITREP.md").exists()
        ),
        key=lambda path: path.name.casefold(),
    )


def candidate_folders(workspace: Workspace) -> list[Path]:
    """Folders in use, the current one, and their subfolders (course folders)."""
    current = workspace.settings.sitrep_root
    anchors = list(engagement_folders(workspace))
    if current is not None and current not in anchors:
        anchors.insert(0, current)
    found: list[Path] = []
    for anchor in anchors:
        for folder in (anchor, *_subfolders(anchor)):
            if folder not in found:
                found.append(folder)
    if current is not None and not _subfolders(current):
        # A leaf course folder: offer its sibling courses too.
        for folder in (current.parent, *_subfolders(current.parent)):
            if folder not in found and folder.parent == current.parent:
                found.append(folder)
    return found


def _label(folder: Path, folders: Sequence[Path]) -> str:
    """Shortest readable name: the folder, or parent/folder when nested."""
    parent = folder.parent
    if parent in folders:
        return f"{parent.name}/{folder.name}"
    return folder.name


def folder_label(workspace: Workspace, root: Path) -> str:
    """Course tag for an engagement, e.g. PG or Engagements; local when inside."""
    if not (root / "SITREP.md").is_symlink():
        return "local"
    try:
        return workspace.notes_root(root).name
    except (TacmuxError, OSError):
        return "?"


def _resolve_argument(workspace: Workspace, value: str) -> Path | None:
    if value.casefold() in NONE_WORDS:
        return None
    if "/" in value or value.startswith("~"):
        expanded = os.path.expanduser(value)
        return Path(expanded).absolute()
    folders = candidate_folders(workspace)
    names = {}
    for folder in folders:
        names.setdefault(_label(folder, folders), folder)
        names.setdefault(folder.name, folder)
    chosen = match_word(value, list(names), label="notes folder")
    return names[chosen]


def _create_if_missing(folder: Path) -> None:
    if folder.exists() or folder.is_symlink():
        return
    if not can_prompt() or not confirm(f"Create {display_path(folder)}?", default=True):
        raise ValidationError(f"notes folder does not exist: {display_path(folder)}")
    folder.mkdir(parents=True, mode=0o700)


def _pin_all(workspace: Workspace) -> list[str]:
    return [
        root.name
        for root in workspace.engagement_candidates()
        if workspace.pin_legacy(root)
    ]


def switch_folder(settings: Settings, workspace: Workspace, folder: Path | None) -> int:
    if folder is not None:
        _create_if_missing(folder)
        folder = workspace.validate_notes_folder(folder)
    pinned = _pin_all(workspace)
    if pinned:
        print(f"Pinned {', '.join(pinned)} to their current notes (nothing moves).")
    write_sitrep_root(settings.config_file, folder)
    target = display_path(folder) if folder else "inside each engagement (workspace)"
    print(f"New engagements → {target}")
    print("Existing engagements keep their notes where they are.")
    if os.environ.get("TACMUX_SITREP_ROOT"):
        print("Note: TACMUX_SITREP_ROOT is set in this shell and overrides the config.")
    return 0


def _print_current(workspace: Workspace) -> None:
    current = workspace.settings.sitrep_root
    print(
        "Notes folder for new engagements: "
        + (display_path(current) if current else "inside each engagement")
    )
    for folder, names in sorted(engagement_folders(workspace).items()):
        print(f"  {display_path(folder)}: {', '.join(sorted(names))}")


def move_command(workspace: Workspace, arguments: Sequence[str]) -> int:
    linked = [
        root
        for root in workspace.engagement_candidates()
        if (root / "SITREP.md").is_symlink()
    ]
    names = {root.name: root for root in linked}
    if arguments:
        name = match_word(arguments[0], list(names), label="engagement")
    else:
        if not names:
            raise ValidationError("no engagement keeps external notes")
        name = choose(
            [
                (f"{root.name}  [{folder_label(workspace, root)}]", root.name)
                for root in linked
            ],
            "Move notes of> ",
        )
    root = names[name]
    if len(arguments) > 1:
        folder = _resolve_argument(workspace, arguments[1])
    else:
        folder = Path(_pick_folder(workspace, allow_special=False))
    if folder is None:
        raise ValidationError("moving notes into the workspace is not supported")
    _create_if_missing(folder)
    destination = workspace.move_notes(root, folder)
    print(f"Moved {root.name} notes → {display_path(destination)}")
    return 0


def _pick_folder(workspace: Workspace, *, allow_special: bool = True) -> str:
    current = workspace.settings.sitrep_root
    folders = candidate_folders(workspace)
    usage = engagement_folders(workspace)
    choices: list[tuple[str, str, str]] = []
    for folder in folders:
        names = usage.get(folder, [])
        mark = "  ← current" if folder == current else ""
        count = f"{len(names)} engagement{'s' if len(names) != 1 else ''}"
        preview = display_path(folder) + (
            "\\n\\n" + "\\n".join(sorted(names)) if names else ""
        )
        choices.append(
            (f"{_label(folder, folders):32} {count}{mark}", str(folder), preview)
        )
    base = current or (folders[0] if folders else None)
    if base is not None:
        choices.append(
            ("New folder…", NEW_FOLDER, f"Create a folder in {display_path(base)}")
        )
    choices.append(("Other path…", OTHER_PATH, "Type any folder path"))
    if allow_special:
        choices.append(
            (
                "Workspace only",
                WORKSPACE_ONLY,
                "New engagements keep SITREP.md inside the workspace",
            )
        )
        choices.append(
            (
                "Move an engagement's notes…",
                MOVE,
                "Relocate an existing engagement's note folder (SITREP + images)",
            )
        )
    selected = choose(choices, "Notes folder> ", default=str(current or ""))
    if selected == NEW_FOLDER and base is not None:
        name = ask("Folder name")
        if "/" in name or name in {".", ".."}:
            raise ValidationError("folder name must be a single name")
        return str(base / name)
    if selected == OTHER_PATH:
        return str(Path(os.path.expanduser(ask("Path"))).absolute())
    return selected


def notes_command(
    settings: Settings, workspace: Workspace, arguments: Sequence[str]
) -> int:
    if arguments and arguments[0] == "move":
        return move_command(workspace, arguments[1:])
    if arguments:
        return switch_folder(settings, workspace, _resolve_argument(workspace, arguments[0]))
    if not can_prompt():
        _print_current(workspace)
        return 0
    _print_current(workspace)
    selected = _pick_folder(workspace)
    if selected == MOVE:
        return move_command(workspace, [])
    if selected == WORKSPACE_ONLY:
        return switch_folder(settings, workspace, None)
    return switch_folder(settings, workspace, Path(selected))
