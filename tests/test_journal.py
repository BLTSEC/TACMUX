from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from tacmux import journal


def test_writer_adds_header_once_and_rows(engagement):
    journal.append_command(engagement, "1", "0.5", "0", "WEB", "%1", "/x", "id")
    journal.append_command(engagement, "2", "1.0", "1", "", "%2", "/x", "a\tb\nc")
    text = (engagement / "logs/commands.tsv").read_text()
    assert text.count("#epoch") == 1
    rows = journal.read_rows(engagement / "logs/commands.tsv")
    assert rows[0]["target"] == "WEB" and rows[1]["command"] == "a b ; c"
    assert (engagement / "logs/commands.tsv").stat().st_mode & 0o777 == 0o600


def test_read_rows_accepts_legacy_five_columns(tmp_path):
    path = tmp_path / "commands.tsv"
    path.write_text("1\t0.1\t0\t/x\twhoami\n")
    assert journal.read_rows(path)[0] == {
        "epoch": "1",
        "seconds": "0.1",
        "exit": "0",
        "target": "",
        "pane": "",
        "cwd": "/x",
        "command": "whoami",
    }


def test_writer_refuses_links(engagement, tmp_path):
    (tmp_path / "elsewhere").write_text("")
    (engagement / "logs/commands.tsv").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(OSError):
        journal.append_command(engagement, "1", "0", "0", "", "", "/", "id")
    assert (tmp_path / "elsewhere").read_text() == ""


def test_writer_refuses_non_engagement(tmp_path):
    (tmp_path / "logs").mkdir()
    with pytest.raises(OSError):
        journal.append_command(tmp_path, "1", "0", "0", "", "", "/", "id")


@pytest.mark.skipif(shutil.which("zsh") is None, reason="zsh not installed")
def test_zsh_snippet_journals_with_exit_codes_and_skips(engagement):
    snippet = journal.zsh_snippet(sys.executable, str(Path(journal.__file__)))
    script = (
        snippet
        + "_tacmux_journal_preexec 'true'; true; _tacmux_journal_precmd\n"
        + "_tacmux_journal_preexec 'false'; false; _tacmux_journal_precmd\n"
        + "_tacmux_journal_preexec ' secret'; true; _tacmux_journal_precmd\n"
        + "TACMUX_NO_AUTOLOG=1 _tacmux_journal_preexec 'quiet'; _tacmux_journal_precmd\n"
    )
    env = {
        **os.environ,
        "TACMUX_ROOT": str(engagement),
        "TACMUX_TARGET_NAME": "WEB",
        "TMUX_PANE": "%7",
    }
    subprocess.run(["zsh", "-f", "-c", script], env=env, check=True)
    rows = journal.read_rows(engagement / "logs/commands.tsv")
    assert [(r["command"], r["exit"], r["target"], r["pane"]) for r in rows] == [
        ("true", "0", "WEB", "%7"),
        ("false", "1", "WEB", "%7"),
    ]
    env.pop("TACMUX_ROOT")
    subprocess.run(["zsh", "-f", "-c", script], env=env, check=True)
    assert len(journal.read_rows(engagement / "logs/commands.tsv")) == 2


def test_shell_init_rejects_other_shells(capsys):
    from tacmux.cli import main

    assert main(["shell-init", "bash"]) == 1
    assert "zsh only" in capsys.readouterr().err
    assert main(["shell-init", "zsh"]) == 0
    assert "add-zsh-hook preexec _tacmux_journal_preexec" in capsys.readouterr().out
