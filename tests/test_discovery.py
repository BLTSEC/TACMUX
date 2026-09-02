from __future__ import annotations

import subprocess

import pytest

from tacmux.discovery import (
    create_reviewed_targets,
    review_candidates,
    run_host_discovery,
)
from tacmux.errors import ValidationError
from tacmux.workspace import parse_host_candidates


def test_parse_grepable_nmap_and_pasted_hosts():
    nmap = "Host: 192.0.2.10 (web.acme.test)\tStatus: Up\nHost: 192.0.2.11 ()\tStatus: Down\n"
    assert parse_host_candidates(nmap) == [("web.acme.test", "192.0.2.10")]
    pasted = "WEB01 192.0.2.10\n192.0.2.11\ninvalid\n"
    assert parse_host_candidates(pasted) == [
        ("WEB01", "192.0.2.10"),
        ("192.0.2.11", "192.0.2.11"),
    ]


def test_parse_netexec_smb_output():
    output = "SMB  192.0.2.20  445  DC01  [*] Windows Server\n"
    assert parse_host_candidates(output, "netexec") == [("DC01", "192.0.2.20")]


def test_parse_netexec_strips_terminal_color():
    output = "\x1b[32mSMB  192.0.2.20  445  DC01  [*] Windows Server\x1b[0m\n"
    assert parse_host_candidates(output, "netexec") == [("DC01", "192.0.2.20")]


def test_run_discovery_is_fixed_profile(monkeypatch):
    monkeypatch.setattr("tacmux.discovery.shutil.which", lambda _: "/usr/bin/nmap")
    monkeypatch.setattr("tacmux.discovery.confirm", lambda _: True)
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(
            argv, 0, "Host: 192.0.2.1 () Status: Up\n", ""
        )

    monkeypatch.setattr("tacmux.discovery.subprocess.run", fake_run)
    run_host_discovery("192.0.2.0/24")
    assert calls == [["/usr/bin/nmap", "-sn", "--reason", "-oG", "-", "192.0.2.0/24"]]


def test_ipv6_discovery_adds_only_family_flag(monkeypatch):
    monkeypatch.setattr("tacmux.discovery.shutil.which", lambda _: "/usr/bin/nmap")
    monkeypatch.setattr("tacmux.discovery.confirm", lambda _: True)
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr("tacmux.discovery.subprocess.run", fake_run)
    run_host_discovery("2001:db8::10")
    assert calls[0] == [
        "/usr/bin/nmap",
        "-6",
        "-sn",
        "--reason",
        "-oG",
        "-",
        "2001:db8::10",
    ]


def test_discovery_refuses_option_injection():
    with pytest.raises(ValidationError, match="IP or CIDR"):
        run_host_discovery("--script=unsafe")


def test_review_commit_skips_existing_endpoint(workspace, engagement):
    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    created, skipped = create_reviewed_targets(
        workspace,
        engagement,
        [("DUP", "192.0.2.10"), ("DB01", "192.0.2.20")],
    )
    assert created == ["DB01"]
    assert skipped == ["DUP (192.0.2.10)"]


def test_review_commit_rejects_reserved_confirmation_delimiter_before_writes(
    workspace, engagement
):
    with pytest.raises(ValidationError, match="cannot contain"):
        create_reviewed_targets(
            workspace,
            engagement,
            [("GOOD", "192.0.2.20"), ("BAD;NAME", "192.0.2.30")],
        )
    assert workspace.targets(engagement) == []


def test_review_requires_save_and_final_confirmation(settings, monkeypatch):
    edit_calls = []

    def fake_edit(_settings, initial, suffix, *, require_save):
        edit_calls.append((initial, suffix, require_save))
        return "WEB01\t192.0.2.10\n"

    monkeypatch.setattr("tacmux.discovery.edit_text", fake_edit)
    monkeypatch.setattr("tacmux.discovery.confirm", lambda _prompt: False)

    with pytest.raises(ValidationError, match="import cancelled"):
        review_candidates(settings, [("WEB01", "192.0.2.10")])
    assert edit_calls[0][1:] == (".targets", True)


def test_review_returns_only_saved_confirmed_candidates(settings, monkeypatch):
    monkeypatch.setattr(
        "tacmux.discovery.edit_text",
        lambda *_args, **_kwargs: "WEB01\t192.0.2.10\n",
    )
    prompts = []

    def approve(prompt):
        prompts.append(prompt)
        return True

    monkeypatch.setattr("tacmux.discovery.confirm", approve)

    assert review_candidates(settings, [("OLD", "192.0.2.10")]) == [
        ("WEB01", "192.0.2.10")
    ]
    assert prompts == ["Create 1 reviewed target(s)?"]
