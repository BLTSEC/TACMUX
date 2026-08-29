from __future__ import annotations

import json
from pathlib import Path

from tacmux.model import AccessLevel, ActivityResult, Engagement
from tacmux.render import attack_paths_text, render_sitrep, topology_text


FIXTURES = Path(__file__).parent / "fixtures"


def test_sanitized_recap_is_a_complete_offline_acceptance_fixture():
    engagement = Engagement.from_dict(
        json.loads((FIXTURES / "recap_sanitized.json").read_text())
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
    assert "Internet Perimeter" in topology and "Corporate LAN" in topology
    assert "MAIL" in topology and "TPM-DC" in topology
    assert "LLMNR" not in path
    assert "only as authenticated access" in path
    assert "```mermaid" in sitrep
    assert "Readable deployment share" in sitrep
