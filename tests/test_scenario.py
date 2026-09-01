from __future__ import annotations

import json
from pathlib import Path

from tacmux.export import ExportProfile, render_handoff
from tacmux.model import AccessLevel, ActivityResult, Engagement
from tacmux.render import attack_paths_text, render_sitrep, topology_text
from tacmux.store import EngagementRecord


FIXTURES = Path(__file__).parent / "fixtures"


def test_synthetic_example_is_a_complete_offline_acceptance_fixture():
    engagement = Engagement.from_dict(
        json.loads((FIXTURES / "external_internal_example.json").read_text())
    )

    assert len(engagement.targets) == 4
    assert len(engagement.target_by_id("T0001").addresses) == 2
    assert engagement.scope_by_id("S0002").via_target_id == "T0001"
    assert engagement.strongest_access("T0003") == AccessLevel.AUTHENTICATED
    assert engagement.strongest_access("T0004") is None
    assert engagement.activities[1].result == ActivityResult.NO_RESULT

    topology = topology_text(engagement)
    path = attack_paths_text(engagement)
    sitrep = render_sitrep(engagement)
    assert "Public Services" in topology and "Application Network" in topology
    assert "EDGE-WEB" in topology and "DB01" in topology
    assert "Delegation review" not in path
    assert "only as authenticated access" in path
    assert "```mermaid" in sitrep
    assert "Artifact repository permitted unintended reads" in sitrep


def test_synthetic_example_produces_a_complete_multi_target_handoff(record):
    engagement = Engagement.from_dict(
        json.loads((FIXTURES / "external_internal_example.json").read_text())
    )
    scenario = EngagementRecord(record.root, engagement)

    document = render_handoff(
        scenario,
        profile=ExportProfile.HANDOFF,
        generated_at="2026-09-01T12:00:00Z",
    )

    assert "EDGE-WEB" in document and "DB01" in document
    assert "Public console to internal authenticated access" in document
    assert "Artifact repository permitted unintended reads" in document
    assert "build_reader" in document
    assert document.count("## Targets and Services") == 1
    assert document.index("## Machine-readable Manifest") > document.index(
        "## Evidence Coverage and Inventory"
    )
