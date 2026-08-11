#!/bin/sh
# ─── TACMUX — Pane Title Pin Guard ──────────────────────────────────────────
# Called by the pane-title-changed hook. If a pane has a pinned title (set via
# Ctrl+Space P), this restores it after the shell's escape sequences try to
# overwrite it. Intentionally lightweight (/bin/sh, no zsh source) since it
# fires on every command execution in pinned panes.

pane=${1:-${TMUX_PANE:-}}
[ -z "$pane" ] && exit 0

p=$(tmux display-message -t "$pane" -p '#{@pinned_title}')
[ -z "$p" ] && exit 0

c=$(tmux display-message -t "$pane" -p '#{pane_title}')
[ "$c" = "$p" ] && exit 0

tmux select-pane -t "$pane" -T "$p"
