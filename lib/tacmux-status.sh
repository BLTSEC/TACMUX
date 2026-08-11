#!/usr/bin/env bash
# ─── TACMUX Tmux Status Bar Segment ─────────────────────────────────────────
# Called by: set -g status-right '#(~/.local/share/tacmux/lib/tacmux-status.sh) %H:%M '
#
# Output:
#   op_* session: [10.10.10.5 LOG] (green) or [10.10.10.5 ---] (yellow)
#   other session: (empty)

session=$(tmux display-message -p '#S' 2>/dev/null)

# Only show for op_* sessions
[[ "$session" != op_* ]] && exit 0

# Prefer the exact workspace route stored by _tacmux_start (including engagement).
# Fall back to the historical session-name reversal for older sessions.
target=$(tmux show-environment -t "=$session" TACMUX_TARGET 2>/dev/null)
target="${target#TACMUX_TARGET=}"
if [[ -z "$target" ]]; then
    target="${session#op_}"
    target="${target//_/.}"
fi

# Check if logging is active on the current pane
logging=$(tmux display-message -p '#{pane_pipe}' 2>/dev/null)

if [[ "$logging" == "1" ]]; then
    echo "#[fg=green,bold][$target LOG]#[default]"
else
    echo "#[fg=yellow][$target ---]#[default]"
fi
