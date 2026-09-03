from __future__ import annotations

from tacmux.config import load_settings


def test_optional_sitrep_root_expands_from_config(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text(
        '[paths]\nworkspace = "~/work"\nsitrep_root = "~/notes"\n'
    )
    settings = load_settings(
        {"HOME": str(tmp_path), "TACMUX_CONFIG": str(config)}
    )
    assert settings.workspace == tmp_path / "work"
    assert settings.sitrep_root == tmp_path / "notes"


def test_sitrep_root_is_disabled_when_omitted(tmp_path):
    settings = load_settings(
        {
            "HOME": str(tmp_path),
            "TACMUX_CONFIG": str(tmp_path / "missing.toml"),
        }
    )
    assert settings.sitrep_root is None
