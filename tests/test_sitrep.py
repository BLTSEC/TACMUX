from __future__ import annotations

import re

import pytest

from tacmux.errors import ValidationError
from tacmux import sitrep


def test_initial_document_has_current_state_and_empty_operations():
    text = sitrep.initial_document("ACME")
    assert sitrep.read_global(text, "CREDENTIALS") == []
    assert sitrep.read_tasks(text, "TODO") == []
    assert sitrep.read_tasks(text, "CLEANUP") == []
    assert sitrep.read_events(text) == []
    assert sitrep.target_sections(text) == []
    for name in ("CREDENTIALS", "TODO", "CLEANUP", "OPERATIONS"):
        assert f"<!-- TACMUX:{name}:START -->\n\n" in text
        assert f"\n\n<!-- TACMUX:{name}:END -->" in text


def test_event_and_target_round_trip():
    text = sitrep.add_target(
        sitrep.initial_document("ACME"), "WEB [prod]", "192.0.2.10"
    )
    event = sitrep.Event(
        "E001",
        "2026-01-01T00:00:00Z",
        "WEB [prod]",
        "info",
        "pipe | slash \\",
        body="#### Notes\n\nnote",
    )
    text = sitrep.append_event(text, event)
    assert sitrep.target_sections(text)[0].name == "WEB [prod]"
    assert sitrep.read_events(text)[0] == event
    assert sitrep.details_map(text, "WEB [prod]")["Endpoint"][0] == "192.0.2.10"
    assert "<!-- TACMUX:EVENT:START E001 -->\n\n### " in text
    assert "\n\n<!-- TACMUX:EVENT:END E001 -->" in text


def test_compact_legacy_wrapper_spacing_is_still_accepted_and_normalized():
    text = sitrep.add_target(sitrep.initial_document("ACME"), "WEB01", "192.0.2.10")
    text = sitrep.append_event(
        text,
        sitrep.Event("E001", "now", "WEB01", "info", "Observed service"),
    )
    compact = re.sub(r"(-->)\n\n", r"\1\n", text)
    compact = re.sub(r"\n\n(<!-- TACMUX:[^\n]+:END(?: E001)? -->)", r"\n\1", compact)

    assert sitrep.read_events(compact)[0].summary == "Observed service"
    assert sitrep.details_map(compact, "WEB01")["Endpoint"][0] == "192.0.2.10"
    normalized = sitrep.normalize_document(compact)
    assert "<!-- TACMUX:DETAILS:START -->\n\n| Field" in normalized
    assert "\n\n<!-- TACMUX:EVENT:END E001 -->" in normalized


def test_event_notes_do_not_treat_structured_evidence_as_notes():
    event = sitrep.Event(
        "E001",
        "2026-01-01T00:00:00Z",
        "ENGAGEMENT",
        "success",
        "Discovery complete",
        body="#### Evidence\n\n- **Tool:** nmap",
    )
    assert sitrep.event_notes(event) == ""


def test_native_checklists_accept_manual_toggle_and_sort_open_first():
    text = sitrep.initial_document("ACME")
    tasks = [
        sitrep.Task("T001", "ENGAGEMENT", "First", complete=True),
        sitrep.Task("T002", "ENGAGEMENT", "Second"),
    ]
    text = sitrep.write_tasks(text, "TODO", tasks)
    rendered = text[text.index("<!-- TACMUX:TODO:START -->") :]
    assert rendered.index("T002") < rendered.index("T001")
    text = text.replace("- [ ] T002:", "- [x] T002:")
    assert all(task.complete for task in sitrep.read_tasks(text, "TODO"))


def test_checklist_normalization_clears_stale_manual_completion_time():
    text = sitrep.initial_document("ACME")
    text = sitrep.write_tasks(
        text,
        "TODO",
        [
            sitrep.Task(
                "T001",
                "ENGAGEMENT",
                "Review evidence",
                completed_at="2026-01-01T00:00:00Z",
                complete=False,
            )
        ],
    )
    normalized = sitrep.normalize_checklists(text)
    assert sitrep.read_tasks(normalized, "TODO")[0].completed_at == ""


def test_rename_updates_structured_references_but_not_prose():
    text = sitrep.add_target(sitrep.initial_document("ACME"), "WEB01", "192.0.2.10")
    text = sitrep.append_event(
        text,
        sitrep.Event(
            "E001",
            "now",
            "WEB01",
            "info",
            "WEB01 appears in prose",
        ),
    )
    text = sitrep.write_tasks(
        text, "TODO", [sitrep.Task("T001", "WEB01", "Review WEB01")]
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
    event = sitrep.read_events(updated)[0]
    assert event.target == "APP01"
    assert event.summary == "WEB01 appears in prose"
    assert sitrep.read_tasks(updated, "TODO")[0].target == "APP01"
    assert sitrep.read_global(updated, "CREDENTIALS")[0][5] == ("APP01 · SSH · user")


def test_confirmed_access_round_trip_and_malformed_value():
    entries = [("WEB01", "SSH", "user"), ("DC01", "SMB", "admin")]
    rendered = sitrep.render_confirmed_access(entries)
    assert sitrep.parse_confirmed_access(rendered) == entries
    with pytest.raises(ValidationError, match="target · service · access"):
        sitrep.parse_confirmed_access("WEB01 - SSH - user")


def test_malformed_event_fails_closed():
    text = sitrep.initial_document("ACME").replace(
        "- **Outcome:** success", "- Outcome: success"
    )
    text = sitrep.append_event(
        text,
        sitrep.Event("E001", "now", "ENGAGEMENT", "success", "Started"),
    )
    text = text.replace("- **Outcome:** success", "- Outcome: success")
    with pytest.raises(ValidationError, match="missing Outcome"):
        sitrep.read_events(text)


def test_legacy_upgrade_preserves_rows_and_completion():
    narrative = sitrep.table_block(
        "NARRATIVE",
        sitrep.LEGACY_TABLES["NARRATIVE"],
        [["now", "ENGAGEMENT", "success", "Started", "detail"]],
    )
    todo = sitrep.table_block(
        "TODO", sitrep.LEGACY_TABLES["TODO"], [["T001", "ENGAGEMENT", "Open", "a", "n"]]
    )
    completed = sitrep.table_block(
        "COMPLETED",
        sitrep.LEGACY_TABLES["COMPLETED"],
        [["T002", "ENGAGEMENT", "Done", "b", "n"]],
    )
    cleanup = sitrep.table_block(
        "CLEANUP",
        sitrep.LEGACY_TABLES["CLEANUP"],
        [["X001", "ENGAGEMENT", "Remove", "complete", "a", "b", "n"]],
    )
    legacy = (
        "# ACME SITREP\n\n## Narrative\n\n"
        + narrative
        + "\n\n## Targets\n\n_No targets yet._\n\n## Credentials\n\n"
        + sitrep.table_block("CREDENTIALS", sitrep.CREDENTIALS, [])
        + "\n\n## TODO\n\n"
        + todo
        + "\n\n## Completed\n\n"
        + completed
        + "\n\n## Cleanup\n\n"
        + cleanup
        + "\n"
    )
    upgraded = sitrep.upgrade_legacy(legacy)
    assert sitrep.read_events(upgraded)[0].summary == "Started"
    tasks = sitrep.read_tasks(upgraded, "TODO")
    assert [(task.identifier, task.complete) for task in tasks] == [
        ("T001", False),
        ("T002", True),
    ]
    assert sitrep.read_tasks(upgraded, "CLEANUP")[0].complete


def test_heading_line_accepts_sections_and_targets():
    text = sitrep.add_target(sitrep.initial_document("ACME"), "WEB01", "192.0.2.10")
    assert sitrep.heading_line(text, "log") > 0
    assert sitrep.heading_line(text, "notes") == sitrep.heading_line(text, "log")
    assert sitrep.heading_line(text, "WEB01") > sitrep.heading_line(text, "targets")
