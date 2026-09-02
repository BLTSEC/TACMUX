from __future__ import annotations

import subprocess

import pytest

from tacmux.errors import ValidationError
from tacmux.interaction import choose_many, edit_text


def test_edit_text_requires_an_explicit_save(settings, monkeypatch):
    monkeypatch.setattr("tacmux.interaction.open_editor", lambda *_args: None)

    with pytest.raises(ValidationError, match="without saving"):
        edit_text(settings, "unchanged\n", require_save=True)


def test_edit_text_accepts_a_saved_unchanged_buffer(settings, monkeypatch):
    def save_file(_settings, path, _line=None):
        path.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")

    monkeypatch.setattr("tacmux.interaction.open_editor", save_file)

    assert edit_text(settings, "accepted\n", require_save=True) == "accepted\n"


def test_choose_many_uses_fzf_multi_and_returns_hidden_values(monkeypatch):
    monkeypatch.setattr("tacmux.interaction.shutil.which", lambda _name: "/usr/bin/fzf")

    def fake_run(argv, **_kwargs):
        assert "--multi" in argv
        assert "--bind=ctrl-a:select-all,ctrl-d:deselect-all" in argv
        return subprocess.CompletedProcess(
            argv, 0, "WEB01  192.0.2.10\tWEB01\nDB01  192.0.2.20\tDB01\n", ""
        )

    monkeypatch.setattr("tacmux.interaction.subprocess.run", fake_run)
    assert choose_many(
        [("WEB01  192.0.2.10", "WEB01"), ("DB01  192.0.2.20", "DB01")],
        "Targets> ",
    ) == ["WEB01", "DB01"]
