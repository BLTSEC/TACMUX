import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "lib/tacmux-core.zsh"


def run_zsh(tmp_path, script, **extra_env):
    env = os.environ.copy()
    for name in (
        "TACMUX_ENGAGEMENT",
        "TACMUX_TARGET",
        "TARGET",
        "RPORT",
        "LOADOUT_TARGET",
    ):
        env.pop(name, None)
    env.update(
        HOME=str(tmp_path / "home"),
        TACMUX_HOME=str(ROOT),
        TACMUX_CONFIG=str(tmp_path / "no-config"),
        TACMUX_ENGAGEMENT_STATE=str(tmp_path / "home/.config/tacmux/engagementrc"),
        TACMUX_WORKSPACE=str(tmp_path / "workspace"),
        TACMUX_ARCHIVE_DIR=str(tmp_path / "archives"),
        TACMUX_LOG_DIR=str(tmp_path / "logs"),
        TACMUX_COLOR="false",
        **extra_env,
    )
    return subprocess.run(
        ["zsh", "-fc", script],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
    )


def test_engagement_state_and_structure(tmp_path):
    result = run_zsh(
        tmp_path,
        f"""
        source {CORE}
        _tacmux_engagement_set 'acme client' >/dev/null
        [[ "$TACMUX_ENGAGEMENT" == acme_client ]]
        [[ "$(_tacmux_relpath host)" == acme_client/targets/host ]]
        [[ -f "$TACMUX_WORKSPACE/acme_client/ENGAGEMENT.md" ]]
        [[ -f "$TACMUX_WORKSPACE/acme_client/notes/activity.md" ]]
        [[ -f "$TACMUX_WORKSPACE/acme_client/notes/attack-path.md" ]]
        [[ -f "$TACMUX_WORKSPACE/acme_client/notes/payloads.md" ]]
        [[ -f "$TACMUX_WORKSPACE/acme_client/findings/README.md" ]]
        [[ -d "$TACMUX_WORKSPACE/acme_client/targets" ]]
        [[ ! -e "$TACMUX_WORKSPACE/acme_client/credentials.md" ]]
        [[ $(wc -l < "$TACMUX_ENGAGEMENT_STATE") -eq 1 ]]
        _tacmux_engagement_clear >/dev/null
        [[ "$(_tacmux_engagement_set)" == flat ]]
        [[ "$(_tacmux_relpath host)" == host ]]
        """,
    )
    assert result.returncode == 0, result.stderr


def test_state_file_overrides_inherited_session_context(tmp_path):
    state = tmp_path / "home/.config/tacmux/engagementrc"
    state.parent.mkdir(parents=True)
    state.write_text("export TACMUX_ENGAGEMENT=''\n")
    result = run_zsh(
        tmp_path,
        f"""
        export TACMUX_ENGAGEMENT=stale_session
        source {CORE}
        [[ -z "$TACMUX_ENGAGEMENT" ]]
        """,
    )
    assert result.returncode == 0, result.stderr


def test_target_normalization_rejects_traversal_components(tmp_path):
    result = run_zsh(
        tmp_path,
        f"""
        source {CORE}
        [[ "$(_normalize_target ..)" == target ]]
        [[ "$(_normalize_target 10.10.10.0/24)" == 10.10.10.0-24 ]]
        [[ "$(_normalize_target 10.10.10.5:445)" == 10.10.10.5_445 ]]
        export TACMUX_ENGAGEMENT=..
        ! _tacmux_relpath host
        """,
    )
    assert result.returncode == 0, result.stderr


def test_no_log_start_uses_canonical_engagement_route(tmp_path):
    targets = tmp_path / "targets file;safe.txt"
    targets.touch()
    result = run_zsh(
        tmp_path,
        f"""
        source {CORE}
        _tacmux_engagement_set acme >/dev/null
        tmux() {{
            case "$1" in
                has-session) return 1 ;;
                new-session) print -r -- "$*" > "$HOME/new-session-args" ;;
                *) return 0 ;;
            esac
        }}
        TMUX=test _tacmux_start -n -a "$TARGETS_FILE" >/dev/null
        args=$(<"$HOME/new-session-args")
        [[ "$args" == *"-s op_acme_targets_targets_file_safe"* ]]
        [[ "$args" == *"-e TACMUX_TARGET=acme/targets/targets_file_safe"* ]]
        [[ "$args" == *"-e LOADOUT_TARGET=acme/targets/targets_file_safe"* ]]
        [[ "$args" == *"-e TACMUX_NO_AUTOLOG=1"* ]]
        [[ -d "$TACMUX_WORKSPACE/acme/targets/targets_file_safe/recon" ]]
        [[ -d "$TACMUX_WORKSPACE/acme/targets/targets_file_safe/logs" ]]
        """,
        TARGETS_FILE=str(targets),
    )
    assert result.returncode == 0, result.stderr


def test_cli_version_and_unknown_command(tmp_path):
    env = os.environ.copy()
    env.update(HOME=str(tmp_path / "home"), TACMUX_HOME=str(ROOT))
    version = subprocess.run(
        [str(ROOT / "bin/tacmux"), "version"],
        env=env,
        text=True,
        capture_output=True,
    )
    assert version.returncode == 0
    assert version.stdout.strip() == "tacmux 1.0.0"
    unknown = subprocess.run(
        [str(ROOT / "bin/tacmux"), "nope"],
        env=env,
        text=True,
        capture_output=True,
    )
    assert unknown.returncode == 2
