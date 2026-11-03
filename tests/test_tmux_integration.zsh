#!/usr/bin/env zsh

emulate -L zsh
setopt pipe_fail

ROOT="${0:A:h:h}"
if [[ ! -x "$ROOT/tests/bin/tmux" ]]; then
    print -u2 -- "[FAIL] cannot resolve the repository tmux test shim"
    exit 1
fi

export TEST_ROOT=$(mktemp -d /tmp/tacmux-v3-integration.XXXXXX) || exit 1
export TACMUX_REAL_TMUX=$(command -v tmux)
export TACMUX_TEST_SOCKET="$TEST_ROOT/tmux.sock"
export TMUX_TMPDIR="$TEST_ROOT/tmux-runtime"
export HOME="$TEST_ROOT/home"
export PATH="$ROOT/tests/bin:$HOME/.local/bin:$PATH"
export PYTHONPATH="$ROOT/src"
export TACMUX_CONFIG="$HOME/.config/tacmux/config.toml"
export HISTFILE=/dev/null

cleanup() {
    "$TACMUX_REAL_TMUX" -S "$TACMUX_TEST_SOCKET" kill-server >/dev/null 2>&1 || true
    [[ "$TEST_ROOT" == /tmp/tacmux-v3-integration.* ]] && rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT INT TERM

rehash
if [[ "$(command -v tmux)" != "$ROOT/tests/bin/tmux" ]]; then
    print -u2 -- "[FAIL] tmux integration test is not using its isolated shim"
    exit 1
fi

fail() { print -u2 -- "[FAIL] $*"; return 1; }
wait_for() {
    local command="$1" attempt
    for attempt in {1..100}; do
        eval "$command" && return 0
        sleep 0.05
    done
    return 1
}

mkdir -p "$HOME/.local/bin" "$HOME/.config/tacmux" "$TMUX_TMPDIR"
chmod 700 "$TMUX_TMPDIR"
ln -s "$ROOT/bin/tacmux" "$HOME/.local/bin/tacmux"
print -r -- "[paths]
workspace = \"$TEST_ROOT/workspace\"

[behavior]
auto_log = true" > "$TACMUX_CONFIG"

tmux new-session -d -s bootstrap -c "$TEST_ROOT" || exit 1
prefix_before=$(tmux show-option -gv prefix)
tmux source-file "$ROOT/tmux/tacmux-integration.conf" || exit 1
[[ "$(tmux show-option -gv prefix)" == "$prefix_before" ]] || \
    fail "integration changed the operator prefix" || exit 1
tmux set-hook -g 'after-new-window[90]' \
    'run-shell -b "$HOME/.local/bin/tacmux _internal log start \"#{pane_id}\""'
tmux set-hook -g 'after-new-window[91]' 'display-message "operator hook"'

tacmux init ACME >/dev/null || exit 1
cd "$TEST_ROOT/workspace/ACME" || exit 1
tacmux target add WEB01 192.0.2.10 >/dev/null || exit 1
session=$(python -c 'from pathlib import Path; from tacmux.config import load_settings; from tacmux.tmux import TmuxService; s=load_settings(); print(TmuxService(s).start(Path.cwd(), "WEB01").name)') || exit 1
tacmux _internal hooks repair >/dev/null || exit 1
tmux show-hooks -g after-new-window | rg -q 'after-new-window\[91\].*operator hook' || \
    fail "legacy cleanup removed an unrelated indexed hook" || exit 1

[[ "$(tmux show-environment -t "$session" TACMUX_ROOT)" == "TACMUX_ROOT=$PWD" ]] || \
    fail "engagement root was not exported" || exit 1
[[ "$(tmux show-environment -t "$session" TACMUX_TARGET)" == "TACMUX_TARGET=captures" ]] || \
    fail "central NOCAP root was not exported" || exit 1
[[ "$(tmux show-environment -t "$session" NOCAP_ROUTE_PREFIX)" == "NOCAP_ROUTE_PREFIX=WEB01" ]] || \
    fail "target capture route was not exported" || exit 1
[[ "$(tmux show-environment -t "$session" TARGET)" == "TARGET=192.0.2.10" ]] || \
    fail "primary endpoint was not exported" || exit 1
[[ "$(tmux show-option -t "$session" -qv @tacmux_log_dir)" == "$PWD/logs" ]] || \
    fail "central log path was not configured" || exit 1
for hook in after-new-window after-split-window; do
    tmux show-hooks -t "$session:" "$hook" | rg -q '\[90\].*_internal log start' || \
        fail "$hook was not installed on the TACMUX session" || exit 1
    if tmux show-hooks -g "$hook" | rg -q '_internal log start'; then
        fail "$hook leaked into global tmux state" || exit 1
    fi
done

wait_for '[[ "$(tmux display-message -t "$session:0.0" -p "#{pane_pipe}")" == 1 ]]' || \
    fail "landing pane did not start logging" || exit 1
tmux send-keys -t "$session:0.0" 'printf "TACMUX_V3_MARKER\n"' Enter
wait_for 'rg -q TACMUX_V3_MARKER "$PWD/logs"' || \
    fail "pane output was not logged centrally" || exit 1

tmux split-window -t "$session:0" -v -c "$PWD/targets/WEB01"
wait_for '[[ "$(tmux display-message -t "$session:0.1" -p "#{pane_pipe}")" == 1 ]]' || \
    fail "split pane did not inherit logging" || exit 1

tmux new-window -d -t "$session:" -n ligolo -c "$PWD/targets/WEB01"
wait_for '[[ "$(tmux display-message -t "$session:1.0" -p "#{pane_pipe}")" == 1 ]]' || \
    fail "new window did not inherit logging" || exit 1
tmux split-window -d -t "$session:1" -h -c "$PWD/targets/WEB01"
wait_for '[[ "$(tmux display-message -t "$session:1.1" -p "#{pane_pipe}")" == 1 ]]' || \
    fail "service-style split did not inherit logging" || exit 1

print -- '[PASS] v3 central logging, context, and NOCAP environment'

# Exercise the actual binding's shell formats, not just the Python popup argv.
# The stub records arguments without opening a popup or touching user sessions.
python3 - "$ROOT" <<'PY' || exit 1
import os
from pathlib import Path
import shlex
import subprocess
import sys

root = Path(sys.argv[1])
test_root = Path(os.environ["TEST_ROOT"])
home = test_root / "popup home"
launcher = home / ".local/bin/tacmux"
launcher.parent.mkdir(parents=True)
launcher.write_text(
    '#!/bin/sh\nprintf \'%s\\0\' "$@" > "$TEST_ROOT/popup-args"\n'
)
launcher.chmod(0o700)
marker = test_root / "popup-injected"
subprocess.run(
    ["tmux", "set-environment", "-g", "TACMUX_POPUP_MARKER", str(marker)],
    check=True,
)
binding = next(
    line for line in (root / "tmux/tacmux-integration.conf").read_text().splitlines()
    if line.startswith("bind-key M ")
)
command = shlex.split(binding)[-1]
names = (
    "spaces in directory",
    "single'quote",
    'double"quote',
    '$(touch "$TACMUX_POPUP_MARKER")',
    '`touch "$TACMUX_POPUP_MARKER"`',
    "semi; amp& pipe| redirect> dollar$HOME hash#",
)
for name in names:
    folder = test_root / name
    folder.mkdir()
    pane = subprocess.run(
        # Pass the path through the environment: tmux versions differ in how
        # they expand "$" and "#" inside -c, but never touch -e values.
        ["tmux", "new-window", "-d", "-P", "-F", "#{pane_id}",
         "-t", "bootstrap:", "-e", f"POPUP_TEST_DIR={folder}",
         'cd "$POPUP_TEST_DIR" && exec sleep 120'],
        text=True, capture_output=True, check=True,
    ).stdout.strip()
    try:
        import time
        for _ in range(50):  # the pane's shell must finish its cd first
            actual_directory = subprocess.run(
                ["tmux", "display-message", "-p", "-t", pane, "#{pane_current_path}"],
                text=True, capture_output=True, check=True,
            ).stdout.strip()
            if actual_directory == str(folder):
                break
            time.sleep(0.1)
        assert actual_directory == str(folder), (name, actual_directory)
        arguments = test_root / "popup-args"
        arguments.unlink(missing_ok=True)
        subprocess.run(
            ["tmux", "run-shell", "-t", pane,
             f"export HOME={shlex.quote(str(home))}; {command}"],
            check=True,
        )
        argv = arguments.read_bytes().split(b"\0")[:-1]
        assert argv[:3] == [b"_internal", b"popup", pane.encode()], argv
        assert argv[-1].decode() == str(folder), (name, argv)
        assert not marker.exists(), f"popup binding executed directory syntax: {name}"
    finally:
        subprocess.run(["tmux", "kill-window", "-t", pane], check=True)
print("[PASS] popup binding preserves shell-sensitive paths without executing them")
PY
