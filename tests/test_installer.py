import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_install_reinstall_and_uninstall_preserve_user_data(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / ".zshrc").write_text("# user zsh config\n")
    (home / ".bashrc").write_text("# user bash config\n")
    workspace = tmp_path / "workspace"
    env = os.environ.copy()
    env.update(
        HOME=str(home),
        XDG_CONFIG_HOME=str(home / ".config"),
        PATH=f"{home}/.local/bin:{env['PATH']}",
    )

    command = [
        str(ROOT / "install.sh"),
        "--unattended",
        "--skip-tmux",
        "--workspace",
        str(workspace),
    ]
    for _ in range(2):
        result = subprocess.run(command, env=env, text=True, capture_output=True)
        assert result.returncode == 0, result.stderr

    zshrc = (home / ".zshrc").read_text()
    assert zshrc.count("# >>> TACMUX >>>") == 1
    assert "tacmux-completions.zsh" in zshrc
    assert "tacmux-core" not in zshrc
    assert (home / ".local/bin/tacmux").is_file()
    assert (home / ".local/share/tacmux/lib/tacmux-logging.sh").is_file()

    evidence = workspace / "keep-me.txt"
    evidence.write_text("preserve")
    result = subprocess.run([str(ROOT / "uninstall.sh")], env=env, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert not (home / ".local/bin/tacmux").exists()
    assert (home / ".config/tacmux/tacmux.conf").is_file()
    assert evidence.read_text() == "preserve"
    assert "# user zsh config" in (home / ".zshrc").read_text()
    assert "TACMUX" not in (home / ".zshrc").read_text()
