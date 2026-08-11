#!/usr/bin/env zsh

emulate -L zsh
setopt pipe_fail

ROOT="${0:A:h:h}"
TEST_ROOT=$(mktemp -d /tmp/tacmux-integration.XXXXXX) || exit 1
export TACMUX_TEST_SOCKET="$TEST_ROOT/tmux.sock"
export HOME="$TEST_ROOT/home"
export PATH="$HOME/.local/bin:$ROOT/tests/bin:$PATH"
export TACMUX_HOME="$ROOT"
export TACMUX_CONFIG="$TEST_ROOT/no-config"
export TACMUX_ENGAGEMENT_STATE="$HOME/.config/tacmux/engagementrc"
export TACMUX_WORKSPACE="$TEST_ROOT/workspace"
export TACMUX_ARCHIVE_DIR="$TEST_ROOT/archives"
export TACMUX_LOG_DIR="$TEST_ROOT/logs"
export TACMUX_COLOR=false
export TMUX=test

cleanup() {
    /usr/bin/tmux -S "$TACMUX_TEST_SOCKET" kill-server >/dev/null 2>&1 || true
    [[ "$TEST_ROOT" == /tmp/tacmux-integration.* ]] && rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT INT TERM

fail() { print -u2 -- "[FAIL] $*"; return 1; }
wait_for() {
    local command="$1"
    local attempt
    for attempt in {1..80}; do
        eval "$command" && return 0
        sleep 0.05
    done
    return 1
}

mkdir -p "$HOME/.local/share" "$HOME/.config/tacmux" "$HOME/.local/bin"
ln -s "$ROOT" "$HOME/.local/share/tacmux"
ln -s "$ROOT/bin/tacmux" "$HOME/.local/bin/tacmux"

tacmux engagement acme >/dev/null || exit 1
tacmux start 10.20.0.20 >/dev/null || exit 1
session='=op_acme_targets_10_20_0_20'
tmux source-file "$ROOT/tmux/tacmux-integration.conf" || exit 1

[[ "$(tmux show-environment -t "$session" TACMUX_TARGET)" == \
   'TACMUX_TARGET=acme/targets/10.20.0.20' ]] || fail "wrong target route" || exit 1
[[ "$(tmux show-environment -t "$session" RPORT)" == 'RPORT=' ]] || fail "stale port" || exit 1
wait_for '[[ "$(tmux display-message -t "$session:0.0" -p "#{pane_pipe}")" == 1 ]]' || \
    fail "initial pane did not start logging" || exit 1

tmux send-keys -t "$session:0.0" 'print -r -- TACMUX_LOG_MARKER' Enter
tmux split-window -t "$session:" -v -c "$TACMUX_WORKSPACE/acme/targets/10.20.0.20"
wait_for '[[ "$(tmux display-message -t "$session:0.1" -p "#{pane_pipe}")" == 1 ]]' || \
    fail "split pane did not start logging" || exit 1
wait_for 'rg -q TACMUX_LOG_MARKER "$TACMUX_WORKSPACE/acme/targets/10.20.0.20/logs"' || \
    fail "pane output was not logged" || exit 1

printf 'osc52-test' | tacmux clip
[[ "$(tmux show-buffer)" == osc52-test ]] || fail "tmux clipboard buffer mismatch" || exit 1

tacmux start -n 10.20.0.21 >/dev/null || exit 1
no_log_session='=op_acme_targets_10_20_0_21'
sleep 0.2
[[ "$(tmux display-message -t "$no_log_session:0.0" -p '#{pane_pipe}')" == 0 ]] || \
    fail "--no-log session was logged" || exit 1
TACMUX_NO_AUTOLOG=1 TMUX_PANE="$(tmux display-message -t "$no_log_session:0.0" -p '#{pane_id}')" \
    tacmux log toggle >/dev/null
[[ "$(tmux display-message -t "$no_log_session:0.0" -p '#{pane_pipe}')" == 1 ]] || \
    fail "manual toggle did not enable logging" || exit 1

tmux new-session -d -s plain -c "$TEST_ROOT"
wait_for '[[ "$(tmux display-message -t "=plain:" -p "#{pane_pipe}")" == 1 ]]' || \
    fail "ordinary tmux session did not start fallback logging" || exit 1
plain_log=$(tmux show-option -p -t '=plain:' -qv @tacmux_log_file)
[[ "$plain_log" == "$TACMUX_LOG_DIR"/* ]] || fail "ordinary session used target log path" || exit 1

print -- '[PASS] target/fallback logging, routing, no-log, and clipboard'
