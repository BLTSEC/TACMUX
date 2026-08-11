#!/usr/bin/env zsh
# ─── TACMUX fzf Session Picker ──────────────────────────────────────────────
# Usage: tacmux pick  or  _tacmux_fzf_pick
#
# Lists active op_* sessions in fzf, then shows an action menu.

_tacmux_fzf_pick() {
    if ! command -v fzf &>/dev/null; then
        echo "fzf is required for session picker. Install: apt install fzf"
        return 1
    fi

    # Build session list with metadata
    local sessions
    sessions=$(tmux list-sessions -F '#S' 2>/dev/null | grep '^op_' || true)

    if [[ -z "$sessions" ]]; then
        echo "No active op sessions found."
        return 0
    fi

    # Format for display: target | status | panes | created
    local formatted=()
    while IFS= read -r session; do
        local target=$(_session_to_target "$session")
        local panes=$(tmux list-panes -t "$session" 2>/dev/null | wc -l)
        local attached=$(tmux display-message -t "$session" -p "#{session_attached}" 2>/dev/null)
        local status_str="detached"
        [[ "$attached" -gt 0 ]] && status_str="attached"
        formatted+=("${target}  (${status_str}, ${panes} panes)")
    done <<< "$sessions"

    # Pick a session
    local choice
    choice=$(printf '%s\n' "${formatted[@]}" | fzf \
        --prompt="op > " \
        --header="Select an op session" \
        --no-multi)

    [[ -z "$choice" ]] && return 0

    # Extract target from choice (first word before double-space)
    local target="${choice%%  *}"
    # A picker can select a session from any engagement. Management helpers use
    # ambient engagement state, so scope it dynamically to the selected route.
    local selected_target="$target"
    local TACMUX_ENGAGEMENT=""
    if [[ "$selected_target" == */targets/* ]]; then
        TACMUX_ENGAGEMENT="${selected_target%%/targets/*}"
        selected_target="${selected_target#*/targets/}"
    fi

    # Action menu
    local action
    action=$(printf '%s\n' \
        "resume  — Attach to session" \
        "status  — Show session status" \
        "pause   — Detach session" \
        "stop    — Kill session" \
        "archive — Stop and archive" \
        | fzf \
            --prompt="action > " \
            --header="Action for: $target" \
            --no-multi)

    [[ -z "$action" ]] && return 0

    # Extract action keyword (first word)
    local cmd="${action%% *}"

    case "$cmd" in
        resume)  _tacmux_resume "$selected_target" ;;
        status)  _tacmux_status "$selected_target" ;;
        pause)   _tacmux_pause "$selected_target" ;;
        stop)    _tacmux_stop "$selected_target" ;;
        archive) _tacmux_stop "$selected_target" archive ;;
    esac
}
