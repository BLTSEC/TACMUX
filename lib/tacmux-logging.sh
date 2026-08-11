#!/usr/bin/env zsh
# TACMUX logging controller. All hooks, keybindings, and CLI log commands route
# through this file so a pane can have at most one intentional logging pipe.

emulate -L zsh
setopt pipe_fail no_unset

TACMUX_HOME="${TACMUX_HOME:-$HOME/.local/share/tacmux}"
TACMUX_CONFIG="${TACMUX_CONFIG:-$HOME/.config/tacmux/tacmux.conf}"
[[ -f "$TACMUX_CONFIG" ]] && source "$TACMUX_CONFIG"

: "${TACMUX_WORKSPACE:=$HOME/workspace}"
: "${TACMUX_LOG_DIR:=$HOME/logs}"
: "${TACMUX_AUTOLOG:=true}"
: "${TACMUX_UMASK:=077}"

case "$TACMUX_UMASK" in
    [0-7][0-7][0-7]|0[0-7][0-7][0-7]) umask "$TACMUX_UMASK" ;;
    *) print -u2 -- "tacmux log: invalid TACMUX_UMASK '$TACMUX_UMASK'"; exit 2 ;;
esac
typeset -gi _tx_umask_value=$(( 8#$TACMUX_UMASK ))
typeset -g _tx_file_mode
printf -v _tx_file_mode '%03o' $(( 8#666 & ~_tx_umask_value ))

_tx_log_ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }

_tx_log_clean() {
    local value="$1"
    value="${value//[^a-zA-Z0-9._-]/_}"
    while [[ "$value" == *__* ]]; do value="${value//__/_}"; done
    value="${value#_}"
    value="${value%_}"
    [[ -z "$value" ]] && value="pane"
    print -r -- "${value[1,40]}"
}

_tx_log_format() {
    local pane="$1" format="$2"
    tmux display-message -t "$pane" -p "$format"
}

_tx_log_session_env() {
    local pane="$1" name="$2" value
    value=$(tmux show-environment -t "$pane" "$name" 2>/dev/null) || return 1
    print -r -- "${value#${name}=}"
}

_tx_log_path() {
    local pane="$1" kind="${2:-pane}"
    local session window title index route log_dir stem

    session=$(_tx_log_format "$pane" '#S') || return 1
    window=$(_tx_log_format "$pane" '#W') || return 1
    title=$(_tx_log_format "$pane" '#{pane_title}') || return 1
    index=$(_tx_log_format "$pane" '#P') || return 1
    route=$(_tx_log_session_env "$pane" TACMUX_TARGET 2>/dev/null || true)

    if [[ "$kind" != fallback && "$session" == op_* && -n "$route" ]]; then
        log_dir="$TACMUX_WORKSPACE/$route/logs/$(date +%Y%m%d)"
        case "$kind" in
            session|resumed|renamed) stem="$kind" ;;
            scrollback) stem="scrollback_$(_tx_log_clean "$window")_$(_tx_log_clean "$title")_p${index}" ;;
            *) stem="$(_tx_log_clean "$window")_$(_tx_log_clean "$title")_p${index}" ;;
        esac
    else
        log_dir="$TACMUX_LOG_DIR/$(date +%Y%m%d)"
        case "$kind" in
            scrollback) stem="scrollback_$(_tx_log_clean "$session")_$(_tx_log_clean "$title")_p${index}" ;;
            *) stem="tmux_$(_tx_log_clean "$session")_$(_tx_log_clean "$title")_p${index}" ;;
        esac
    fi

    mkdir -p "$log_dir" || return 1
    reply=("$log_dir/${stem}_$(date +%H%M%S).log" "$session" "$window" "$title" "$index" "$route")
}

_tx_log_disabled() {
    local pane="$1" bootstrap no_autolog
    [[ "$TACMUX_AUTOLOG" != true ]] && return 0
    bootstrap=$(_tx_log_session_env "$pane" TACMUX_BOOTSTRAP 2>/dev/null || true)
    no_autolog=$(_tx_log_session_env "$pane" TACMUX_NO_AUTOLOG 2>/dev/null || true)
    [[ "$bootstrap" == 1 || "$no_autolog" == 1 ]]
}

_tx_log_start() {
    local pane="$1" kind="${2:-pane}" force="${3:-false}"
    [[ -n "$pane" ]] || { print -u2 -- "tacmux log: no pane target"; return 1; }
    [[ "$force" == true ]] || ! _tx_log_disabled "$pane" || return 0
    [[ "$(_tx_log_format "$pane" '#{pane_pipe}')" == 1 ]] && return 0

    _tx_log_path "$pane" "$kind" || return 1
    local log_file="$reply[1]" session="$reply[2]" window="$reply[3]"
    local title="$reply[4]" index="$reply[5]" route="$reply[6]" pipe_command
    printf -v pipe_command 'cat >> %q' "$log_file"

    {
        print -r -- "=== TACMUX Logging Started ==="
        [[ -n "$route" ]] && print -r -- "Target: $route"
        print -r -- "Session: $session"
        print -r -- "Window: $window"
        print -r -- "Pane: $index"
        print -r -- "Pane Title: $title"
        print -r -- "Date: $(_tx_log_ts)"
        print -r -- "================================"
    } >> "$log_file"
    chmod "$_tx_file_mode" "$log_file" || return 1

    tmux pipe-pane -t "$pane" -o "$pipe_command"
    tmux set-option -p -t "$pane" @tacmux_log_file "$log_file"
    tmux display-message -t "$pane" "Logging ON: ${log_file:t}"
}

_tx_log_stop() {
    local pane="$1"
    tmux pipe-pane -t "$pane"
    tmux set-option -p -t "$pane" -u @tacmux_log_file 2>/dev/null || true
    tmux display-message -t "$pane" "Logging OFF"
}

_tx_log_toggle() {
    local pane="$1"
    if [[ "$(_tx_log_format "$pane" '#{pane_pipe}')" == 1 ]]; then
        _tx_log_stop "$pane"
    else
        tmux set-environment -t "$pane" TACMUX_NO_AUTOLOG 0
        _tx_log_start "$pane" pane true
    fi
}

_tx_log_capture() {
    local pane="$1"
    _tx_log_path "$pane" scrollback || return 1
    local log_file="$reply[1]"
    tmux capture-pane -t "$pane" -S -50000 -p > "$log_file"
    chmod "$_tx_file_mode" "$log_file" || return 1
    tmux display-message -t "$pane" "Scrollback saved: ${log_file:t}"
    print -r -- "$log_file"
}

_tx_log_status() {
    local pane="$1" active file
    active=$(_tx_log_format "$pane" '#{pane_pipe}') || return 1
    file=$(tmux show-option -p -t "$pane" -qv @tacmux_log_file 2>/dev/null || true)
    if [[ "$active" == 1 ]]; then
        print -r -- "Logging ON${file:+: $file}"
    else
        print -r -- "Logging OFF"
    fi
}

_tx_log_retitle() {
    local pane="$1" title="${2:-}" was_active
    was_active=$(_tx_log_format "$pane" '#{pane_pipe}') || return 1
    if [[ -z "$title" ]]; then
        tmux set-option -p -t "$pane" -u @pinned_title 2>/dev/null || true
        tmux display-message -t "$pane" "Pane title unpinned"
        return 0
    fi
    tmux select-pane -t "$pane" -T "$title"
    tmux set-option -p -t "$pane" @pinned_title "$title"
    if [[ "$was_active" == 1 ]]; then
        _tx_log_stop "$pane" >/dev/null
        _tx_log_start "$pane" pane true
    fi
    tmux display-message -t "$pane" "Pane title pinned: $title"
}

command_name="${1:-}"
pane="${2:-${TMUX_PANE:-}}"
kind="${3:-pane}"

case "$command_name" in
    start)   _tx_log_start "$pane" "$kind" false ;;
    force)   _tx_log_start "$pane" "$kind" true ;;
    stop)    _tx_log_stop "$pane" ;;
    toggle)  _tx_log_toggle "$pane" ;;
    capture) _tx_log_capture "$pane" ;;
    status)  _tx_log_status "$pane" ;;
    retitle) shift 2; _tx_log_retitle "$pane" "$*" ;;
    *)
        print -u2 -- "Usage: tacmux log start|force|stop|toggle|capture|status [pane]"
        exit 2
        ;;
esac
