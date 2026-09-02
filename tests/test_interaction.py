from __future__ import annotations

import pytest

from tacmux.errors import ValidationError
from tacmux.interaction import edit_text


def test_edit_text_requires_an_explicit_save(settings, monkeypatch):
    monkeypatch.setattr("tacmux.interaction.open_editor", lambda *_args: None)

    with pytest.raises(ValidationError, match="without saving"):
        edit_text(settings, "unchanged\n", require_save=True)


def test_edit_text_accepts_a_saved_unchanged_buffer(settings, monkeypatch):
    def save_file(_settings, path, _line=None):
        path.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")

    monkeypatch.setattr("tacmux.interaction.open_editor", save_file)

    assert edit_text(settings, "accepted\n", require_save=True) == "accepted\n"
