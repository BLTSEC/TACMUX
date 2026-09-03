from __future__ import annotations

from tacmux import sitrep
from tacmux.cli import main
from tacmux.workspace import CaptureRecord


def _configure(monkeypatch, settings):
    monkeypatch.setenv("TACMUX_WORKSPACE", str(settings.workspace))
    monkeypatch.setenv("TACMUX_CONFIG", str(settings.config_file))


def test_version_help_and_unknown(monkeypatch, settings, capsys):
    _configure(monkeypatch, settings)
    assert main(["version"]) == 0
    assert "3.0.0" in capsys.readouterr().out
    assert main(["help"]) == 0
    assert "tacmux log" in capsys.readouterr().out
    assert main(["unknown"]) == 1
    assert "unknown command" in capsys.readouterr().err


def test_prompt_eof_is_a_clean_cancel(monkeypatch, settings, capsys):
    _configure(monkeypatch, settings)
    monkeypatch.setattr(
        "builtins.input", lambda _prompt: (_ for _ in ()).throw(EOFError)
    )
    assert main(["init"]) == 130
    assert "cancelled" in capsys.readouterr().err


def test_cli_operational_flow(monkeypatch, settings, workspace, engagement, capsys):
    _configure(monkeypatch, settings)
    monkeypatch.chdir(engagement)
    assert main(["target", "add", "WEB01", "192.0.2.10"]) == 0
    monkeypatch.chdir(engagement / "targets/WEB01")
    assert main(["log", "partial", "Shell", "drops"]) == 0
    assert main(["done", "Obtained", "shell"]) == 0
    assert main(["todo", "add", "Enumerate", "SMB"]) == 0
    assert main(["cleanup", "add", "Remove", "payload"]) == 0
    assert main(["history", "WEB01"]) == 0
    output = capsys.readouterr().out
    assert "Shell drops" in output
    assert "Obtained shell" in output
    text = workspace.read(engagement)
    assert len(sitrep.read_events(text)) == 2
    assert sitrep.read_tasks(text, "TODO")[0].target == "WEB01"


def test_cli_capture_image_and_reopen_workflow(
    monkeypatch, settings, workspace, engagement, tmp_path, capsys
):
    _configure(monkeypatch, settings)
    monkeypatch.chdir(engagement)
    capture = CaptureRecord(
        "capture-1", "completed", "nmap", "ops/recon/scan.txt", "nmap -sV"
    )
    monkeypatch.setattr(
        "tacmux.workspace.Workspace.inspect_capture", lambda *_args: capture
    )
    image = tmp_path / "proof.png"
    image.write_bytes(b"\x89PNG\r\n\x1a\nproof")
    assert main(["done", "-c", "-i", str(image), "Service", "validated"]) == 0
    event = sitrep.read_events(workspace.read(engagement))[0]
    assert event.capture_id == "capture-1"
    assert "images/proof.png" in event.body

    assert main(["todo", "add", "Draft", "finding"]) == 0
    identifier = sitrep.read_tasks(workspace.read(engagement), "TODO")[0].identifier
    assert main(["todo", "done", identifier]) == 0
    assert main(["todo", "reopen", identifier]) == 0
    assert not sitrep.read_tasks(workspace.read(engagement), "TODO")[0].complete
    assert "Logged E001" in capsys.readouterr().out


def test_cli_target_export_all_multi_select_and_none(
    monkeypatch, settings, workspace, engagement, capsys
):
    _configure(monkeypatch, settings)
    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    workspace.add_target(engagement, "DB01", "192.0.2.20")
    monkeypatch.chdir(engagement)

    assert main(["target", "export", "--all"]) == 0
    assert (engagement / "targets.txt").read_text().splitlines() == [
        "192.0.2.20",
        "192.0.2.10",
    ]

    monkeypatch.setattr("tacmux.cli.choose", lambda *_args, **_kwargs: "select")
    monkeypatch.setattr("tacmux.cli.choose_many", lambda *_args, **_kwargs: ["WEB01"])
    assert main(["target", "export"]) == 0
    assert (engagement / "targets.txt").read_text() == "192.0.2.10\n"

    assert main(["target", "export", "--none"]) == 0
    assert (engagement / "targets.txt").read_text() == ""
    assert "Wrote 0 target(s)" in capsys.readouterr().out


def test_cli_ports_pipe(monkeypatch, settings, workspace, engagement, capsys):
    _configure(monkeypatch, settings)
    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    monkeypatch.chdir(engagement)

    class Input:
        def isatty(self):
            return False

        def read(self):
            return "445/tcp open microsoft-ds Windows Server\n"

    monkeypatch.setattr("sys.stdin", Input())
    assert main(["ports", "add", "WEB01"]) == 0
    assert "Imported 1 port" in capsys.readouterr().out
    assert (
        sitrep.read_target(workspace.read(engagement), "WEB01", "PORTS")[0][0] == "445"
    )


def test_cli_credential_first_colon(monkeypatch, settings, workspace, engagement):
    _configure(monkeypatch, settings)
    monkeypatch.chdir(engagement)
    assert main(["creds", "add", "hash", "alice:aad3:31d6"]) == 0
    assert (engagement / "credentials/hashes.txt").read_text() == "aad3:31d6\n"


def test_cli_credential_view_alias(
    monkeypatch, settings, workspace, engagement, capsys
):
    _configure(monkeypatch, settings)
    workspace.add_credential(engagement, "alice", "secret", "password")
    monkeypatch.chdir(engagement)
    assert main(["creds", "view"]) == 0
    assert "alice" in capsys.readouterr().out


def test_cli_confirms_credential_without_exposing_secret_in_target_status(
    monkeypatch, settings, workspace, engagement, capsys
):
    _configure(monkeypatch, settings)
    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    credential = workspace.add_credential(
        engagement, "alice", "do-not-print", "password"
    )
    monkeypatch.chdir(engagement)

    assert (
        main(
            [
                "creds",
                "confirm",
                credential,
                "WEB01",
                "user",
                "SSH",
                "shell access",
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert main(["status", "WEB01"]) == 0
    output = capsys.readouterr().out
    assert "Confirmed Credentials" in output
    assert "alice" in output
    assert "do-not-print" not in output


def test_cli_updates_target_details_and_guards_live_identity_fields(
    monkeypatch, settings, workspace, engagement, capsys
):
    _configure(monkeypatch, settings)
    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    monkeypatch.chdir(engagement)

    assert main(["target", "update", "WEB01", "os", "Linux"]) == 0
    assert main(["target", "update", "WEB01", "role", "mail server"]) == 0
    assert main(["target", "update", "WEB01", "role", "--clear"]) == 0
    details = workspace.target_details(engagement, "WEB01")
    assert details["OS"][0] == "Linux"
    assert details["Role"][0] == ""

    monkeypatch.setattr("tacmux.tmux.TmuxService.target_running", lambda *_: True)
    assert main(["target", "update", "WEB01", "endpoint", "192.0.2.11"]) == 1
    assert "stop WEB01 first" in capsys.readouterr().err


def test_sync_prompts_for_missing_target_section(
    monkeypatch, settings, workspace, engagement
):
    _configure(monkeypatch, settings)
    (engagement / "targets/MANUAL").mkdir()
    monkeypatch.chdir(engagement)
    monkeypatch.setattr("tacmux.cli.ask", lambda _label: "192.0.2.30")
    assert main(["sitrep", "sync"]) == 0
    assert workspace.target_details(engagement, "MANUAL")["Endpoint"][0] == "192.0.2.30"


def test_completion_values_are_contextual_and_never_print_secrets(
    monkeypatch, settings, workspace, engagement, capsys
):
    _configure(monkeypatch, settings)
    workspace.add_target(engagement, "WEB01", "192.0.2.10")
    credential = workspace.add_credential(
        engagement, "alice", "do-not-complete-this", "password"
    )
    task = workspace.add_task(engagement, "WEB01", "Enumerate SMB")
    cleanup = workspace.add_cleanup(engagement, "WEB01", "Remove payload")
    monkeypatch.chdir(engagement)

    assert main(["_complete", "engagement"]) == 0
    assert capsys.readouterr().out.splitlines() == ["ACME"]
    assert main(["_complete", "target"]) == 0
    assert capsys.readouterr().out.splitlines() == ["WEB01"]
    assert main(["_complete", "credential"]) == 0
    credential_output = capsys.readouterr().out
    assert credential_output.splitlines() == [credential]
    assert "do-not-complete-this" not in credential_output
    assert main(["_complete", "todo"]) == 0
    assert capsys.readouterr().out.splitlines() == [task]
    assert main(["_complete", "cleanup"]) == 0
    assert capsys.readouterr().out.splitlines() == [cleanup]
    assert main(["_complete", "sitrep"]) == 0
    assert {"log", "cleanup", "WEB01"} <= set(capsys.readouterr().out.splitlines())
