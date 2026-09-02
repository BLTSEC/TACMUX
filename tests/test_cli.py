from __future__ import annotations

from tacmux import sitrep
from tacmux.cli import main


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
    assert len(sitrep.read_global(text, "NARRATIVE")) == 2
    assert sitrep.read_global(text, "TODO")[0][1] == "WEB01"


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
    assert {"narrative", "cleanup", "WEB01"} <= set(
        capsys.readouterr().out.splitlines()
    )
