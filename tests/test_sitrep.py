from __future__ import annotations

import pytest

from tacmux.errors import ValidationError
from tacmux import sitrep


def test_initial_document_has_exact_empty_tables():
    text = sitrep.initial_document("ACME")
    assert sitrep.read_global(text, "NARRATIVE") == []
    assert sitrep.read_global(text, "CREDENTIALS") == []
    assert sitrep.target_sections(text) == []


def test_target_round_trip_and_escaped_cells():
    text = sitrep.add_target(
        sitrep.initial_document("ACME"), "WEB [prod]", "192.0.2.10"
    )
    text = sitrep.write_global(
        text,
        "NARRATIVE",
        [["2026-01-01T00:00:00Z", "WEB [prod]", "info", "pipe | slash \\", "note"]],
    )
    assert sitrep.target_sections(text)[0].name == "WEB [prod]"
    assert sitrep.read_global(text, "NARRATIVE")[0][3] == "pipe | slash \\"
    assert sitrep.details_map(text, "WEB [prod]")["Endpoint"][0] == "192.0.2.10"


def test_rename_updates_only_structured_target_columns():
    text = sitrep.add_target(sitrep.initial_document("ACME"), "WEB01", "192.0.2.10")
    text = sitrep.write_global(
        text,
        "NARRATIVE",
        [["now", "WEB01", "info", "WEB01 appears in prose", ""]],
    )
    text = sitrep.write_global(
        text,
        "CREDENTIALS",
        [
            [
                "C001",
                "alice",
                "password",
                "secret",
                "manual",
                "WEB01 · SSH · user",
                "now",
                "now",
                "",
            ]
        ],
    )
    updated = sitrep.rename_target(text, "WEB01", "APP01")
    row = sitrep.read_global(updated, "NARRATIVE")[0]
    assert row[1] == "APP01"
    assert row[3] == "WEB01 appears in prose"
    assert sitrep.read_global(updated, "CREDENTIALS")[0][5] == (
        "APP01 · SSH · user"
    )


def test_confirmed_access_round_trip_and_malformed_value():
    entries = [("WEB01", "SSH", "user"), ("DC01", "SMB", "admin")]
    rendered = sitrep.render_confirmed_access(entries)
    assert sitrep.parse_confirmed_access(rendered) == entries
    with pytest.raises(ValidationError, match="target · service · access"):
        sitrep.parse_confirmed_access("WEB01 - SSH - user")


def test_malformed_managed_table_fails_closed():
    text = sitrep.initial_document("ACME").replace(
        "| Time (UTC) | Target | Outcome | Summary | Notes |",
        "| Time | Summary |",
    )
    with pytest.raises(ValidationError, match="columns must be"):
        sitrep.read_global(text, "NARRATIVE")


def test_heading_line_accepts_sections_and_targets():
    text = sitrep.add_target(sitrep.initial_document("ACME"), "WEB01", "192.0.2.10")
    assert sitrep.heading_line(text, "narrative") > 0
    assert sitrep.heading_line(text, "WEB01") > sitrep.heading_line(text, "targets")
