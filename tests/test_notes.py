from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from tacmux import cli
from tacmux.config import load_settings, write_sitrep_root
from tacmux.errors import TacmuxError
from tacmux.notes import candidate_folders, notes_command
from tacmux.workspace import NOTES_PIN, Workspace


def _external(settings, notes: Path) -> Workspace:
    notes.mkdir(parents=True, exist_ok=True)
    value = Workspace(dataclasses.replace(settings, sitrep_root=notes.resolve()))
    value.initialize()
    return value


def test_new_engagement_is_pinned_to_its_notes_folder(settings, tmp_path):
    workspace = _external(settings, tmp_path / "notes")
    root = workspace.create_engagement("ACME")
    pin = root / ".tacmux" / NOTES_PIN
    assert pin.read_text().strip() == str((tmp_path / "notes").resolve())
    assert pin.stat().st_mode & 0o777 == 0o600


def test_switching_root_keeps_existing_engagements(settings, tmp_path):
    base = tmp_path / "notes"
    old = _external(settings, base).create_engagement("ACME")
    (base / "PG").mkdir()
    moved = _external(settings, base / "PG")
    assert moved.is_engagement(old)
    assert moved.sitrep_path(old) == base.resolve() / "ACME" / "SITREP.md"
    new = moved.create_engagement("Fractal")
    assert moved.sitrep_path(new) == (base / "PG").resolve() / "Fractal" / "SITREP.md"
    assert [root.name for root in moved.engagements()] == ["ACME", "Fractal"]


def test_legacy_engagement_is_pinned_on_mutation(settings, tmp_path):
    base = tmp_path / "notes"
    workspace = _external(settings, base)
    root = workspace.create_engagement("ACME")
    (root / ".tacmux" / NOTES_PIN).unlink()  # a pre-3.4 engagement
    workspace.add_task(root, "ENGAGEMENT", "Enumerate SMB")
    assert (root / ".tacmux" / NOTES_PIN).is_file()
    (base / "PG").mkdir()
    assert _external(settings, base / "PG").is_engagement(root)


def test_unpinned_engagement_breaks_without_pin(settings, tmp_path):
    base = tmp_path / "notes"
    root = _external(settings, base).create_engagement("ACME")
    (root / ".tacmux" / NOTES_PIN).unlink()
    (base / "PG").mkdir()
    other = _external(settings, base / "PG")
    assert not other.is_engagement(root)
    # pin_legacy only blesses a link that validates under the current root.
    assert not other.pin_legacy(root)


def test_write_sitrep_root_keeps_comments_and_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    config = tmp_path / "config.toml"
    config.write_text(
        '# top comment\n[paths]\nworkspace = "~/ws"\n'
        '# Optional notes\nsitrep_root = "~/old"\n\n[behavior]\nauto_log = true\n'
    )
    config.chmod(0o600)
    write_sitrep_root(config, tmp_path / "notes" / "PG")
    text = config.read_text()
    assert "# top comment" in text and "# Optional notes" in text
    assert 'sitrep_root = "~/notes/PG"' in text and "~/old" not in text
    assert config.stat().st_mode & 0o777 == 0o600
    loaded = load_settings({"HOME": str(tmp_path), "TACMUX_CONFIG": str(config)})
    assert loaded.sitrep_root == (tmp_path / "notes" / "PG").resolve()
    assert loaded.auto_log is True
    write_sitrep_root(config, None)
    assert (
        load_settings({"HOME": str(tmp_path), "TACMUX_CONFIG": str(config)}).sitrep_root
        is None
    )


def test_write_sitrep_root_inserts_paths_table(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    config = tmp_path / "config.toml"
    config.write_text("[behavior]\nauto_log = false\n")
    write_sitrep_root(config, Path("/srv/notes"))
    loaded = load_settings({"HOME": str(tmp_path), "TACMUX_CONFIG": str(config)})
    assert loaded.sitrep_root == Path("/srv/notes") and loaded.auto_log is False


def test_notes_by_name_pins_and_switches(settings, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    base = tmp_path / "notes"
    workspace = _external(settings, base)
    root = workspace.create_engagement("ACME")
    (root / ".tacmux" / NOTES_PIN).unlink()
    (base / "PG").mkdir()
    (base / "HTB").mkdir()
    assert {path.name for path in candidate_folders(workspace)} >= {"PG", "HTB"}
    assert notes_command(workspace.settings, workspace, ["pg"]) == 0
    out = capsys.readouterr().out
    assert "Pinned ACME" in out and "New engagements → ~/notes/PG" in out
    loaded = load_settings(
        {"HOME": str(tmp_path), "TACMUX_CONFIG": str(settings.config_file)}
    )
    assert loaded.sitrep_root == (base / "PG").resolve()
    assert Workspace(
        dataclasses.replace(settings, sitrep_root=loaded.sitrep_root)
    ).is_engagement(root)


def test_notes_refuses_workspace_and_symlink(settings, tmp_path):
    workspace = _external(settings, tmp_path / "notes")
    with pytest.raises(TacmuxError, match="outside the workspace"):
        workspace.validate_notes_folder(settings.workspace)
    (tmp_path / "link").symlink_to(tmp_path / "notes")
    with pytest.raises(TacmuxError, match="linked"):
        workspace.validate_notes_folder(tmp_path / "link")


def test_move_notes_moves_folder_with_images(settings, tmp_path):
    base = tmp_path / "notes"
    workspace = _external(settings, base)
    root = workspace.create_engagement("ACME")
    (base / "ACME" / "images").mkdir()
    (base / "ACME" / "images" / "a.png").write_bytes(b"png")
    (base / "PG").mkdir()
    destination = workspace.move_notes(root, base / "PG")
    assert destination == (base / "PG").resolve() / "ACME" / "SITREP.md"
    assert (base / "PG" / "ACME" / "images" / "a.png").is_file()
    assert not (base / "ACME").exists()
    assert workspace.sitrep_path(root) == destination
    assert workspace.pinned_notes_root(root) == (base / "PG").resolve()


def test_move_notes_rolls_back(settings, tmp_path, monkeypatch):
    base = tmp_path / "notes"
    workspace = _external(settings, base)
    root = workspace.create_engagement("ACME")
    (base / "PG").mkdir()
    original = workspace._write_pin
    calls = []

    def failing_pin(root_value, folder):
        calls.append(folder)
        if len(calls) == 1:
            raise OSError("disk full")
        original(root_value, folder)

    monkeypatch.setattr(workspace, "_write_pin", failing_pin)
    with pytest.raises(OSError):
        workspace.move_notes(root, base / "PG")
    assert (base / "ACME" / "SITREP.md").is_file()
    assert workspace.sitrep_path(root) == base.resolve() / "ACME" / "SITREP.md"
    (base / "PG" / "ACME").mkdir()
    monkeypatch.setattr(workspace, "_write_pin", original)
    with pytest.raises(TacmuxError, match="already exist"):
        workspace.move_notes(root, base / "PG")


def test_switcher_tags_and_orders(settings, tmp_path, monkeypatch):
    workspace = _external(settings, tmp_path / "notes")
    done = workspace.create_engagement("Alpha")
    workspace.add_target(done, "WEB", "192.0.2.1")
    workspace.set_target_detail(done, "WEB", "Status", "complete")
    live = workspace.create_engagement("Bravo")
    workspace.add_target(live, "DC", "192.0.2.2")

    class FakeTmux:
        def sessions(self):
            return []

    choices = cli._session_choices(workspace, FakeTmux())
    assert choices[0][0].startswith("STOP  Bravo / OPS  [notes]")
    assert choices[-1][0].endswith("[notes]") and "Alpha" in choices[-1][0]
