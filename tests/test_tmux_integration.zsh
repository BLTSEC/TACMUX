#!/usr/bin/env zsh

emulate -L zsh
setopt pipe_fail

ROOT="${0:A:h:h}"
export TEST_ROOT=$(mktemp -d /tmp/tacmux-v2-integration.XXXXXX) || exit 1
export TACMUX_REAL_TMUX=$(command -v tmux)
export TACMUX_TEST_SOCKET="$TEST_ROOT/tmux.sock"
export HOME="$TEST_ROOT/home"
export PATH="$HOME/.local/bin:$ROOT/tests/bin:$PATH"
export PYTHONPATH="$ROOT/src"
export TACMUX_CONFIG="$HOME/.config/tacmux/config.toml"
export TMUX=test
export HISTFILE=/dev/null

cleanup() {
    "$TACMUX_REAL_TMUX" -S "$TACMUX_TEST_SOCKET" kill-server >/dev/null 2>&1 || true
    [[ "$TEST_ROOT" == /tmp/tacmux-v2-integration.* ]] && rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT INT TERM

fail() { print -u2 -- "[FAIL] $*"; return 1; }
wait_for() {
    local command="$1" attempt
    for attempt in {1..100}; do
        eval "$command" && return 0
        sleep 0.05
    done
    return 1
}

mkdir -p "$HOME/.local/share" "$HOME/.config/tacmux" "$HOME/.local/bin"
ln -s "$ROOT" "$HOME/.local/share/tacmux"
ln -s "$ROOT/bin/tacmux" "$HOME/.local/bin/tacmux"
print -r -- "[paths]
workspace = \"$TEST_ROOT/workspace\"
archive_dir = \"$TEST_ROOT/archives\"
log_dir = \"$TEST_ROOT/logs\"

[behavior]
auto_log = true
startup = \"picker\"
include_mermaid = false

[nocap]
enabled = false" > "$TACMUX_CONFIG"

# Load hooks first so this covers startup ordering and the bootstrap guard.
tmux new-session -d -s bootstrap -c "$TEST_ROOT" || exit 1
tmux source-file "$ROOT/tmux/tacmux-integration.conf" || exit 1

"$ROOT/.venv/bin/python" -c '
from pathlib import Path
import os
from tacmux.config import load_settings
from tacmux.model import AssessmentType, ScopeGroup, TargetAddress
from tacmux.store import Workspace
settings = load_settings(); workspace = Workspace(settings)
record = workspace.create_engagement("ACME", "Integration", AssessmentType.BOTH)
scope = record.engagement.add_scope("LAN", ScopeGroup.INTERNAL, "10.20.0.0/24")
workspace.save(record.root, record.engagement)
target = workspace.create_target(record.root, record.engagement, "host20", addresses=[TargetAddress("10.20.0.20", scope.id)], primary_endpoint="10.20.0.20")
root = Path(os.environ["TEST_ROOT"])
(root / "engagement-id").write_text(record.engagement.id)
(root / "target-id").write_text(target.id)
(root / "target-dir").write_text(target.directory)
' || exit 1

engagement_id=$(<"$TEST_ROOT/engagement-id")
target_id=$(<"$TEST_ROOT/target-id")
target_dir=$(<"$TEST_ROOT/target-dir")
session="tacmux-${engagement_id}-${target_id}"

"$ROOT/.venv/bin/python" -c '
from tacmux.config import load_settings
from tacmux.store import Workspace
from tacmux.tmux import TmuxService
settings = load_settings(); workspace = Workspace(settings); record = workspace.list_engagements()[0]
TmuxService(settings).start_target(record.root, record.engagement, record.engagement.targets[0])
' || exit 1

[[ "$(tmux show-environment -t "$session" TACMUX_TARGET_ID)" == "TACMUX_TARGET_ID=$target_id" ]] || \
    fail "target ID was not exported" || exit 1
[[ "$(tmux show-environment -t "$session" TARGET)" == 'TARGET=10.20.0.20' ]] || \
    fail "primary endpoint was not exported" || exit 1
[[ "$(tmux show-environment -t "$session" NOCAP_WORKSPACE)" == '-NOCAP_WORKSPACE' ]] || \
    fail "disabled NOCAP workspace was not removed" || exit 1
[[ "$(tmux show-option -t "$session" -qv @tacmux_engagement_id)" == "$engagement_id" ]] || \
    fail "engagement option missing" || exit 1
wait_for '[[ "$(tmux display-message -t "$session:0.0" -p "#{pane_pipe}")" == 1 ]]' || \
    fail "landing pane did not start logging" || exit 1

target_root="$TEST_ROOT/workspace/${engagement_id}-Integration/targets/$target_dir"
tmux send-keys -t "$session:0.0" 'printf "TACMUX_V2_MARKER\n"' Enter
tmux split-window -t "$session:" -v -c "$target_root"
wait_for '[[ "$(tmux display-message -t "$session:0.1" -p "#{pane_pipe}")" == 1 ]]' || \
    fail "split pane did not inherit logging" || exit 1
wait_for 'rg -q TACMUX_V2_MARKER "$target_root/logs"' || \
    fail "target output was not logged" || exit 1

tacmux _internal log capture "$session:0.0" || exit 1
[[ "$(tmux display-message -t "$session:0.0" -p '#{pane_pipe}')" == 1 ]] || \
    fail "scrollback capture interrupted continuous logging" || exit 1
scrollback_logs=("$target_root"/logs/*/scrollback_*.log(N))
(( ${#scrollback_logs} == 1 )) || fail "scrollback evidence was not created" || exit 1
rg -q TACMUX_V2_MARKER "$scrollback_logs[1]" || \
    fail "scrollback evidence did not contain pane history" || exit 1

printf 'clipboard-v2' | tacmux _internal clip
[[ "$(tmux show-buffer)" == clipboard-v2 ]] || fail "clipboard buffer mismatch" || exit 1

tmux new-session -d -s plain -c "$TEST_ROOT"
wait_for '[[ "$(tmux display-message -t "=plain:" -p "#{pane_pipe}")" == 1 ]]' || \
    fail "ordinary session did not use fallback logging" || exit 1
plain_log=$(tmux show-option -p -t '=plain:' -qv @tacmux_log_file)
[[ "$plain_log" == "$TEST_ROOT/logs"/* ]] || fail "fallback log path was incorrect" || exit 1

print -- '[PASS] v2 session context, continuous logging, scrollback, and clipboard'
