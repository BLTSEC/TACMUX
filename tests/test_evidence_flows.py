"""TACMUX 3.2 foundation: one-step access records and evidence attached later."""

from __future__ import annotations

from pathlib import Path

import pytest

from tacmux import sitrep
from tacmux.errors import ConflictError, ValidationError
from tacmux.workspace import CaptureRecord

PNG = b"\x89PNG\r\n\x1a\n" + b"\0" * 64


@pytest.fixture
def web01(workspace, engagement):
    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    return engagement


def _png(tmp_path: Path, name: str = "proof.png") -> Path:
    path = tmp_path / name
    path.write_bytes(PNG)
    return path


def _capture(engagement: Path, ident: str = "cap-1") -> CaptureRecord:
    evidence = engagement / "captures/WEB01/nmap.txt"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text("22/tcp open ssh\n")
    return CaptureRecord(ident, "done", "nmap", "WEB01/nmap.txt", "nmap -sV x")


def test_record_access_is_one_undoable_change(workspace, web01):
    credential = workspace.add_credential(web01, "admin", "admin", "password")
    before = workspace.read(web01)
    event = workspace.record_access(
        web01,
        "WEB01",
        "user",
        "Access: user as app via http :8000 (CVE-2021-43857 RCE)",
        principal="app",
        method="CVE-2021-43857 RCE via http :8000",
        credential=credential,
        credential_access="authenticated",
        service="http :8000",
    )
    text = workspace.read(web01)
    details = sitrep.details_map(text, "WEB01")
    assert (details["Access"][0], details["Principal"][0]) == ("user", "app")
    assert details["Method/Path"][0] == "CVE-2021-43857 RCE via http :8000"
    row = sitrep.read_global(text, "CREDENTIALS")[0]
    assert "WEB01 · http :8000 · authenticated" in row[5]
    assert sitrep.read_events(text)[-1].identifier == event
    workspace.undo_last_change(web01, expected=workspace.last_change(web01))
    assert workspace.read(web01) == before


def test_record_access_never_lowers(workspace, web01):
    workspace.record_access(web01, "WEB01", "admin", "root", principal="root")
    workspace.record_access(web01, "WEB01", "user", "user shell", principal="app")
    details = workspace.target_details(web01, "WEB01")
    assert (details["Access"][0], details["Principal"][0]) == ("admin", "root")
    assert [e.outcome for e in sitrep.read_events(workspace.read(web01))] == [
        "success",
        "success",
    ]


def test_attach_screenshot_replaces_the_placeholder(workspace, web01, tmp_path):
    capture = _capture(web01)
    event = workspace.add_event(web01, "WEB01", "success", "Shell", capture=capture)
    assert "_Not attached._" in workspace.read(web01)
    workspace.attach_to_event(web01, event, images=[_png(tmp_path)])
    body = sitrep.read_events(workspace.read(web01))[-1].body
    assert "_Not attached._" not in body
    assert "](<images/proof.png>)" in body
    assert body.count("#### Screenshots") == 1


def test_attach_screenshot_and_capture_to_a_plain_entry(workspace, web01, tmp_path):
    event = workspace.add_event(web01, "WEB01", "success", "root flag /root/proof.txt")
    workspace.attach_to_event(web01, event, images=[_png(tmp_path, "a.png")])
    workspace.attach_to_event(web01, event, images=[_png(tmp_path, "b.png")])
    workspace.attach_to_event(web01, event, capture=_capture(web01))
    entry = sitrep.read_events(workspace.read(web01))[-1]
    assert entry.capture_id == "cap-1"
    assert entry.body.startswith("#### Evidence")
    assert entry.body.count("#### Screenshots") == 1
    assert "images/a.png" in entry.body and "images/b.png" in entry.body
    assert workspace.validate(web01) == []


def test_attach_refuses_unknown_and_duplicate_captures(workspace, web01):
    first = workspace.add_event(web01, "WEB01", "info", "one", capture=_capture(web01))
    second = workspace.add_event(web01, "WEB01", "info", "two")
    with pytest.raises(ValidationError, match="unknown event"):
        workspace.attach_to_event(web01, "E999", capture=_capture(web01, "x"))
    with pytest.raises(ConflictError, match="already attached"):
        workspace.attach_to_event(web01, second, capture=_capture(web01))
    with pytest.raises(ConflictError, match="already has capture"):
        workspace.attach_to_event(web01, first, capture=_capture(web01, "cap-2"))
    with pytest.raises(ValidationError, match="nothing to attach"):
        workspace.attach_to_event(web01, second)
