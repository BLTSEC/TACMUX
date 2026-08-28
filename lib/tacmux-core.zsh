#!/usr/bin/zsh
# ─── TACMUX — Cybersecurity Operations Workspace Manager ─────────────────────
# Internal command library. The installer does not source this into user shells.
# https://github.com/BLTSEC/TACMUX

TACMUX_VERSION="1.2.0"

# ─── Configuration ───────────────────────────────────────────────────────────

TACMUX_HOME="${TACMUX_HOME:-$HOME/.local/share/tacmux}"
TACMUX_CONFIG="${TACMUX_CONFIG:-$HOME/.config/tacmux/tacmux.conf}"
[[ -f "$TACMUX_CONFIG" ]] && source "$TACMUX_CONFIG"
TACMUX_ENGAGEMENT_STATE="${TACMUX_ENGAGEMENT_STATE:-$HOME/.config/tacmux/engagementrc}"

# The state file intentionally contains only the selected engagement. Target
# routing belongs to each tmux session and must never leak between hosts.
_tacmux_load_engagement_state() {
    unset TACMUX_ENGAGEMENT
    [[ -f "$TACMUX_ENGAGEMENT_STATE" ]] && source "$TACMUX_ENGAGEMENT_STATE"
}

_tacmux_load_engagement_state

: "${TACMUX_WORKSPACE:=$HOME/workspace}"
: "${TACMUX_ARCHIVE_DIR:=$HOME/archives}"
: "${TACMUX_LOG_DIR:=$HOME/logs}"
: "${TACMUX_AUTOLOG:=true}"
: "${TACMUX_TARGET_DIRS:=recon exploitation loot screenshots reports logs}"
: "${TACMUX_NOCAP_INTEGRATION:=true}"
: "${TACMUX_COLOR:=true}"
: "${TACMUX_UMASK:=077}"

# Assessment workspaces routinely contain credentials, payloads, client data,
# and complete terminal transcripts. New TACMUX data is private to the current
# user unless an operator deliberately selects a group-sharing umask such as 027.
case "$TACMUX_UMASK" in
    [0-7][0-7][0-7]|0[0-7][0-7][0-7]) umask "$TACMUX_UMASK" ;;
    *)
        echo "TACMUX: invalid TACMUX_UMASK '$TACMUX_UMASK' (expected 077, 027, or similar)" >&2
        return 1 2>/dev/null || exit 1
        ;;
esac
typeset -gi _tx_umask_value=$(( 8#$TACMUX_UMASK ))
typeset -g _tx_file_mode
printf -v _tx_file_mode '%03o' $(( 8#666 & ~_tx_umask_value ))

# ─── Nocap Integration ───────────────────────────────────────────────────────

if [[ "$TACMUX_NOCAP_INTEGRATION" == "true" ]]; then
    export NOCAP_WORKSPACE="$TACMUX_WORKSPACE"
fi

# ─── Color Helpers ───────────────────────────────────────────────────────────

if [[ "$TACMUX_COLOR" == "true" ]]; then
    _tx_bold=$'\e[1m'
    _tx_green=$'\e[32m'
    _tx_yellow=$'\e[33m'
    _tx_red=$'\e[31m'
    _tx_cyan=$'\e[36m'
    _tx_dim=$'\e[2m'
    _tx_reset=$'\e[0m'
else
    _tx_bold="" _tx_green="" _tx_yellow="" _tx_red="" _tx_cyan="" _tx_dim="" _tx_reset=""
fi

# ─── Internal Helpers ────────────────────────────────────────────────────────

# Normalize a raw target string to a safe workspace/filesystem name.
# Idempotent: already-normalized names pass through unchanged.
#   10.10.10.0/24    → 10.10.10.0-24   (slash → dash, CIDR)
#   192.168.1.2:1337 → 192.168.1.2_1337 (colon → underscore, ip:port)
#   10.10.10.5       → 10.10.10.5      (no change)
_normalize_target() {
    local t="$1"
    t="${t//\//-}"    # slash → dash (CIDR)
    t="${t//:/_}"     # colon → underscore (port)
    t="${t//[^a-zA-Z0-9._-]/_}"
    [[ -z "$t" || "$t" == "." || "$t" == ".." ]] && t="target"
    echo "$t"
}

# Convert an op session name (op_10_10_10_5) back to target (10.10.10.5)
# Prefers stored TACMUX_TARGET env var (set by _tacmux_start), falls back to sed reversal
_session_to_target() {
    local stored
    stored=$(tmux show-environment -t "=$1" TACMUX_TARGET 2>/dev/null | sed 's/^TACMUX_TARGET=//') || true
    if [[ -n "$stored" ]]; then
        echo "$stored"
    else
        echo "$1" | sed 's/^op_//; s/_/./g'
    fi
}

# ISO-8601 UTC timestamp for log banners — unambiguous across a team and
# correlatable with a client's blue-team timeline. Filenames keep local HHMMSS.
_tx_ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# ─── Engagement Resolution ───────────────────────────────────────────────────
# The selected engagement affects future commands. An empty value keeps the
# original flat, per-target workflow.

# Current engagement name, or empty. Validate the ambient value too: callers may
# export it directly instead of using _tacmux_engagement_set, and it is used in paths.
_tacmux_engagement() {
    local eng="${TACMUX_ENGAGEMENT:-}"
    if [[ -n "$eng" && ( "$eng" == *[^a-zA-Z0-9._-]* || "$eng" == "." || "$eng" == ".." ) ]]; then
        echo "${_tx_red}Error:${_tx_reset} Invalid TACMUX_ENGAGEMENT: $eng" >&2
        return 1
    fi
    echo "$eng"
}

# Sanitize a workspace/relpath component into a tmux-session-safe token.
# Matches the historical `${ws//[.:]/_}` for flat names (ws never holds a slash),
# and additionally folds the engagement separator '/' and spaces.
_tacmux_sanitize() {
    local s="$1"
    s="${s//\//_}"; s="${s//./_}"; s="${s//:/_}"; s="${s// /_}"
    echo "$s"
}

# Workspace-relative path for a target.
_tacmux_relpath() {
    local ws="$1" eng
    eng=$(_tacmux_engagement) || return 1
    if [[ -n "$eng" ]]; then
        echo "${eng}/targets/${ws}"
    else
        echo "$ws"
    fi
}

# Resolve the three values every management function needs. Results use zsh's
# conventional $reply array: relative path, tmux session, absolute directory.
_tacmux_resolve() {
    local relpath
    relpath=$(_tacmux_relpath "$1") || return 1
    reply=("$relpath" "op_$(_tacmux_sanitize "$relpath")" "$TACMUX_WORKSPACE/$relpath")
}

# Seed the minimal engagement notes tree. Optional administrative and delivery
# directories are created by the operator only when an engagement needs them.
# No-op when no engagement is active (flat/HTB workspaces stay clean).
_engagement_root_init() {
    local eng
    eng=$(_tacmux_engagement) || return 1
    [[ -z "$eng" ]] && return 0
    local root="$TACMUX_WORKSPACE/$eng"
    mkdir -p "$root"/{notes,findings,targets}
    local overview="$root/ENGAGEMENT.md"
    if [[ ! -f "$overview" ]]; then
        cat > "$overview" << EOF
# Engagement: $eng

> Confirm written authorization and scope before testing.

## Authorization
- Client:
- Authorized by:
- Contract / SOW ref:
- Testing window (UTC):
- Emergency contact:

## Scope — IN
-

## Scope — OUT (do NOT touch)
-

## Rules of Engagement
- Allowed techniques:
- Prohibited (e.g. DoS, social engineering, prod data exfil):
- Testing hours:
- Data handling / evidence retention:

## Objectives
-

## Network Boundaries
| Boundary | CIDR / Host | Access Path | Notes |
|---|---|---|---|

## Targets
| Target | Boundary | Role | Status | Notes |
|---|---|---|---|---|

---
Created: $(_tx_ts)
EOF
    fi
    [[ -f "$root/notes/activity.md" ]] || printf '# Activity Log\n\n| UTC | Action | Target | Result |\n|---|---|---|---|\n' > "$root/notes/activity.md"
    [[ -f "$root/notes/attack-path.md" ]] || printf '# Attack Path\n' > "$root/notes/attack-path.md"
    [[ -f "$root/notes/payloads.md" ]] || printf '# Payload Log\n\n| UTC | Target | Path | SHA-256 | Cleanup |\n|---|---|---|---|---|\n' > "$root/notes/payloads.md"
    [[ -f "$root/findings/README.md" ]] || printf '# Findings\n\nCreate one directory per reportable finding.\n' > "$root/findings/README.md"
    echo "  ${_tx_bold}Engagement:${_tx_reset} $eng  ${_tx_dim}($overview)${_tx_reset}"
}

# Persist only the selected engagement.
_tacmux_save_engagementrc() {
    local rc="$TACMUX_ENGAGEMENT_STATE"
    if [[ -z "${TACMUX_ENGAGEMENT:-}" ]]; then
        mkdir -p "${rc:h}"
        printf "export TACMUX_ENGAGEMENT=''\n" > "$rc"
        chmod 600 "$rc"
        return 0
    fi
    mkdir -p "${rc:h}"
    {
        printf 'export TACMUX_ENGAGEMENT=%q\n' "$TACMUX_ENGAGEMENT"
    } > "$rc"
    chmod 600 "$rc"
}

# Ambient engagement selection for multi-host work.
_tacmux_engagement_set() {
    if [[ -z "${1:-}" ]]; then
        if [[ -n "${TACMUX_ENGAGEMENT:-}" ]]; then
            echo "$TACMUX_ENGAGEMENT"
        else
            echo "flat"
        fi
        return 0
    fi
    if [[ "$1" == "clear" || "$1" == "-c" || "$1" == "--clear" ]]; then
        _tacmux_engagement_clear
        return 0
    fi
    local engagement="${1//[^a-zA-Z0-9._-]/_}"
    if [[ -z "$engagement" || "$engagement" == "." || "$engagement" == ".." ]]; then
        echo "${_tx_red}Error:${_tx_reset} Invalid engagement name"
        return 1
    fi
    local previous_engagement="${TACMUX_ENGAGEMENT:-}"
    export TACMUX_ENGAGEMENT="$engagement"
    if ! _engagement_root_init >/dev/null; then
        if [[ -n "$previous_engagement" ]]; then
            export TACMUX_ENGAGEMENT="$previous_engagement"
        else
            unset TACMUX_ENGAGEMENT
        fi
        return 1
    fi
    _tacmux_save_engagementrc
    local root="$TACMUX_WORKSPACE/$TACMUX_ENGAGEMENT"
    echo "[*] ENGAGEMENT=$TACMUX_ENGAGEMENT → $root/"
    echo "    overview: $root/ENGAGEMENT.md"
}

_tacmux_engagement_clear() {
    unset TACMUX_ENGAGEMENT
    _tacmux_save_engagementrc
    echo "[*] Cleared ENGAGEMENT (ops now flat under \$TACMUX_WORKSPACE)"
}

# ─── Session Management Functions ───────────────────────────────────────────────────────────────────────────────────────

# Create a target directory structure without starting tmux.
_tacmux_mkop() {
    local target="${1:-}"

    if [[ -z "$target" ]]; then
        echo "Usage: tacmux mkop <target_directory>"
        return 1
    fi

    local dirs=(${(s: :)TACMUX_TARGET_DIRS})
    if mkdir -p "$target"/${^dirs}; then
        echo "Created op directory: $target"
    else
        echo "Failed to create directory: $target"
        return 1
    fi
}

# Start op session
# Usage: tacmux start [-n] [-a] <target|cidr|targets_file>
#   -n / --no-log  disable auto-logging (Ctrl+Space T still toggles it on/off)
#   -a / --auto    run autorecon; accepts a single IP, CIDR range, or targets file
_tacmux_start() {
    local no_log=0 use_auto=0

    while [[ "$1" == -* ]]; do
        case "$1" in
            -n|--no-log) no_log=1;   shift ;;
            -a|--auto)   use_auto=1; shift ;;
            --) shift; break ;;
            *) echo "Unknown flag: $1"; return 1 ;;
        esac
    done

    local target="${1:-}"

    if [[ -z "$target" ]]; then
        echo "Usage: tacmux start [-n] [-a] <target|cidr|targets_file>"
        echo "  -n         disable auto-logging (Ctrl+Space T to enable)"
        echo "  -a         run autorecon instead of skeleton folder setup"
        echo "Examples:"
        echo "  tacmux start 10.10.10.5"
        echo "  tacmux start -n 10.10.10.5"
        echo "  tacmux start -a 10.10.10.5"
        echo "  tacmux start -a 10.10.10.0/24"
        echo "  tacmux start -a targets.txt"
        return 1
    fi

    # ── Derive workspace name and autorecon args from input type ─────────────
    # AutoRecon arguments must be resolved here, while the CWD is still the caller's,
    # because the tmux pane is created in $base_dir (a relative file path would
    # not resolve there).
    local workspace_name ar_command raw_host="$target" raw_port=""
    local -a autorecon_args

    if [[ -f "$target" ]]; then
        # Targets file — autorecon reads it via -t (a positional arg would be
        # treated as a hostname). Absolutize before the pane's cwd changes.
        autorecon_args=(-t "${target:A}")
        workspace_name=$(_normalize_target "${${target:t}%.*}")
        raw_host="$workspace_name"
    elif [[ "$target" == *:* && "$target" != */* ]]; then
        # ip:port — split for autorecon (-p flag) and filesystem safety
        autorecon_args=("${target%%:*}" -p "${target##*:}")
        workspace_name=$(_normalize_target "$target")
        raw_host="${target%%:*}"
        raw_port="${target##*:}"
    else
        # IP, hostname, or CIDR — normalize for filesystem safety
        autorecon_args=("$target")
        workspace_name=$(_normalize_target "$target")
    fi
    ar_command="autorecon -o recon ${(q)autorecon_args}"

    # Engagement-aware: session/dir nest under $TACMUX_ENGAGEMENT when set,
    # else collapse to the historical flat layout. relpath is what nocap and the
    # autolog hook route by (via TACMUX_TARGET below).
    local -a reply
    _tacmux_resolve "$workspace_name" || return 1
    local relpath="$reply[1]" session="$reply[2]" base_dir="$reply[3]"

    # ── Session conflict check ───────────────────────────────────────────────
    if tmux has-session -t "=$session" 2>/dev/null; then
        echo "Session '$session' already exists. Use 'tacmux resume $workspace_name' to reconnect."
        read -q "REPLY?Kill existing session and create new one? (y/N): "
        echo
        if [[ $REPLY == [Yy] ]]; then
            tmux kill-session -t "=$session"
        else
            return 1
        fi
    fi

    # ── Workspace directories ────────────────────────────────────────────────
    _engagement_root_init || return 1
    local dirs=(${(s: :)TACMUX_TARGET_DIRS})
    mkdir -p "$base_dir"/${^dirs} || return 1

    # ── Create tmux session (detached so we can configure before attaching) ──
    # TARGET = raw host/IP (for tools like nmap that need a network address)
    # TACMUX_TARGET = engagement-relative workspace path (for nocap routing)
    # Set the whole tuple explicitly so stale values in tmux's global
    # environment cannot leak from a prior engagement or port-keyed target.
    local -a session_env=(
        -e "TACMUX_ENGAGEMENT=${TACMUX_ENGAGEMENT:-}"
        -e "TARGET=$raw_host"
        -e "TACMUX_TARGET=$relpath"
        -e "RPORT=$raw_port"
        -e "NOCAP_WORKSPACE=$TACMUX_WORKSPACE"
        -e "TACMUX_BOOTSTRAP=1"
        -e "TACMUX_NO_AUTOLOG=$no_log"
    )
    # Keep the concrete landing-pane ID. Addressing it indirectly as
    # "session:" later can resolve differently across tmux versions/clients.
    local first_pane
    if ! first_pane=$(tmux new-session -d -P -F '#{pane_id}' \
        -s "$session" -c "$base_dir" "${session_env[@]}"); then
        echo "${_tx_red}Error:${_tx_reset} Failed to create tmux session '$session'"
        return 1
    fi
    echo ""
    [[ -n "${TACMUX_ENGAGEMENT:-}" ]] && \
        echo "  ${_tx_bold}Engagement:${_tx_reset} $TACMUX_ENGAGEMENT"
    echo "  ${_tx_bold}Target:${_tx_reset}    $target"
    echo "  ${_tx_bold}Session:${_tx_reset}   $session"
    echo "  ${_tx_bold}Directory:${_tx_reset} $base_dir"

    # ── Logging ──────────────────────────────────────────────────────────────
    # Start the landing pane while TACMUX_BOOTSTRAP still suppresses the
    # asynchronous after-new-session hook. Releasing the hook first lets two
    # logger processes race on the initial pane.
    if [[ $no_log -eq 1 ]]; then
        echo "  ${_tx_bold}Logging:${_tx_reset}   ${_tx_yellow}OFF${_tx_reset} (Ctrl+Space T to enable)"
    elif [[ "$TACMUX_AUTOLOG" != true ]]; then
        echo "  ${_tx_bold}Logging:${_tx_reset}   ${_tx_yellow}OFF${_tx_reset} (TACMUX_AUTOLOG=false)"
    else
        if zsh "$TACMUX_HOME/lib/tacmux-logging.sh" force "$first_pane" session &&
            [[ "$(tmux display-message -p -t "$first_pane" '#{pane_pipe}' 2>/dev/null)" == 1 ]]; then
            local log_file=$(tmux show-option -p -t "$first_pane" -qv @tacmux_log_file 2>/dev/null)
            echo "  ${_tx_bold}Log:${_tx_reset}       $log_file"
        else
            echo "  ${_tx_bold}Logging:${_tx_reset}   ${_tx_red}FAILED${_tx_reset} (run: tacmux log start)" >&2
        fi
    fi

    # New panes/windows may now be handled by the normal tmux hooks.
    tmux set-environment -t "=$session" TACMUX_BOOTSTRAP 0

    # ── AutoRecon launch ─────────────────────────────────────────────────────
    if [[ $use_auto -eq 1 ]]; then
        echo "  ${_tx_bold}AutoRecon:${_tx_reset} ${(q)autorecon_args} → $base_dir/recon/"
        tmux rename-window -t "=$session" "autorecon"
        tmux send-keys -t "=$session:" "$ar_command" Enter
        # Split a shell pane below for parallel work while autorecon runs
        tmux split-window -t "=$session:" -v -c "$base_dir"
    fi

    echo ""
    if [[ -n "$TMUX" ]]; then
        tmux switch-client -t "=$session"
    else
        tmux attach -t "=$session"
    fi
}

# Pause op session (detach from tmux)
_tacmux_pause() {
    local target="${1:-}"

    if [[ -z "$target" ]]; then
        echo "Usage: tacmux pause <target>"
        return 1
    fi

    local workspace_name=$(_normalize_target "$target")
    local -a reply
    _tacmux_resolve "$workspace_name" || return 1
    local session="$reply[2]"

    if ! tmux has-session -t "=$session" 2>/dev/null; then
        echo "No active session found for target: $target"
        return 1
    fi

    tmux detach -s "$session"

    echo "Paused op session for $target"
    echo "Use 'tacmux resume $workspace_name' to continue"
    echo "Use 'tacmux list' to see all active sessions"
}

# Stop op session
_tacmux_stop() {
    local target="${1:-}"
    local archive_option="${2:-}"

    if [[ -z "$target" ]]; then
        echo "Usage: tacmux stop <target> [archive]"
        return 1
    fi

    local workspace_name=$(_normalize_target "$target")
    local -a reply
    _tacmux_resolve "$workspace_name" || return 1
    local session="$reply[2]" base_dir="$reply[3]"

    if ! tmux has-session -t "=$session" 2>/dev/null; then
        echo "No active session found for target: $target"
        return 1
    fi

    # Write end marker to most recent log, then kill session
    local latest_log=$(ls -t "$base_dir/logs"/*/*.log 2>/dev/null | head -1)
    if [[ -n "$latest_log" ]]; then
        echo "=== Session Ended at $(_tx_ts) ===" >> "$latest_log"
    fi

    tmux kill-session -t "=$session"
    echo "Stopped op session for $target"

    if [[ "$archive_option" == "archive" ]]; then
        _tacmux_archive "$workspace_name"
    else
        echo "Engagement directory preserved: $base_dir"
        echo "Use 'tacmux archive $workspace_name' to archive when complete"
    fi
}

# Resume existing op session
_tacmux_resume() {
    local target="${1:-}"

    if [[ -z "$target" ]]; then
        echo "Usage: tacmux resume <target>"
        return 1
    fi

    local workspace_name=$(_normalize_target "$target")
    local -a reply
    _tacmux_resolve "$workspace_name" || return 1
    local session="$reply[2]" base_dir="$reply[3]"

    if ! tmux has-session -t "=$session" 2>/dev/null; then
        echo "No active session found for target: $target"
        echo "Use 'tacmux start $target' to create a new session"
        return 1
    fi

    # Respect no-log flag set at session start
    if [[ "$(tmux show-environment -t "=$session" TACMUX_NO_AUTOLOG 2>/dev/null)" == "TACMUX_NO_AUTOLOG=1" ]]; then
        echo "Resuming op session for $target (logging disabled)..."
        if [[ -n "$TMUX" ]]; then
            tmux switch-client -t "=$session"
        else
            tmux attach-session -t "=$session"
        fi
        return 0
    fi

    zsh "$TACMUX_HOME/lib/tacmux-logging.sh" stop "=$session:" >/dev/null
    zsh "$TACMUX_HOME/lib/tacmux-logging.sh" force "=$session:" resumed

    echo "Resuming op session for $target..."
    if [[ -n "$TMUX" ]]; then
        tmux switch-client -t "=$session"
    else
        tmux attach-session -t "=$session"
    fi
}

# List all active op sessions
_tacmux_list() {
    echo "${_tx_bold}Active Op Sessions:${_tx_reset}"
    echo "======================="

    local sessions=$(tmux list-sessions -F '#{session_name}' 2>/dev/null | grep "^op_")

    if [[ -z "$sessions" ]]; then
        echo "${_tx_dim}No active op sessions found${_tx_reset}"
        return 0
    fi

    while IFS= read -r session; do
        local target=$(_session_to_target "$session")
        local created=$(tmux display-message -t "=$session" -p "#{session_created}")
        local panes=$(tmux list-panes -t "=$session" | wc -l)
        local attached=$(tmux display-message -t "=$session" -p "#{session_attached}")

        local status_str
        if [[ "$attached" -gt 0 ]]; then
            status_str="${_tx_green}ATTACHED${_tx_reset}"
        else
            status_str="${_tx_yellow}DETACHED${_tx_reset}"
        fi

        echo "${_tx_cyan}$target${_tx_reset}  $status_str"
        echo "  Session: $session"
        echo "  Panes:   $panes"
        echo "  Created: $(date -d @$created 2>/dev/null || date -r $created 2>/dev/null || echo "Unknown")"
        echo
    done <<< "$sessions"
}

# Archive a completed target and write a sidecar manifest derived from the
# finished tarball. Hashing the archive itself avoids races with a live source
# tree and makes the manifest describe the exact bytes an operator preserves.
_tacmux_archive() {
    local target="${1:-}"

    if [[ -z "$target" ]]; then
        echo "Usage: tacmux archive <target>"
        return 1
    fi

    local workspace_name=$(_normalize_target "$target")
    local -a reply
    _tacmux_resolve "$workspace_name" || return 1
    local relpath="$reply[1]" session="$reply[2]" base_dir="$reply[3]"
    local archive_dir="$TACMUX_ARCHIVE_DIR"
    # Flatten the engagement separator so the archive name reflects the full path.
    local archive_file="$archive_dir/${relpath//\//_}_$(date +%Y%m%d_%H%M%S).tar.gz"
    local manifest_file="${archive_file}.manifest.json"
    local created_utc=$(_tx_ts)

    if [[ ! -d "$base_dir" ]]; then
        echo "Engagement directory not found: $base_dir"
        return 1
    fi

    mkdir -p "$archive_dir"

    if tmux has-session -t "=$session" 2>/dev/null; then
        local attached=$(tmux display-message -t "=$session" -p "#{session_attached}" 2>/dev/null)
        if [[ "${attached:-0}" -gt 0 ]]; then
            echo "${_tx_yellow}Warning:${_tx_reset} Session '$session' is currently attached."
            read -q "REPLY?Kill it and continue archiving? (y/N): "
            echo
            [[ $REPLY != [Yy] ]] && return 1
        fi
        echo "Stopping active session: $session"
        tmux kill-session -t "=$session"
    fi

    echo "Creating archive..."
    if COPYFILE_DISABLE=1 tar -czf "$archive_file" -C "$TACMUX_WORKSPACE" -- "$relpath"; then
        chmod "$_tx_file_mode" "$archive_file" || {
            echo "${_tx_red}Failed to secure archive permissions:${_tx_reset} $archive_file"
            return 1
        }

        if ! python3 "$TACMUX_HOME/lib/tacmux-manifest.py" \
            --archive "$archive_file" \
            --output "$manifest_file" \
            --file-mode "$_tx_file_mode" \
            --created-utc "$created_utc" \
            --tacmux-version "$TACMUX_VERSION" \
            --engagement "${TACMUX_ENGAGEMENT:-}" \
            --target "$workspace_name" \
            --workspace-relative-path "$relpath" \
            --session "$session"; then
            echo "${_tx_red}Archive manifest generation failed.${_tx_reset}"
            echo "Archive retained and source preserved: $archive_file"
            return 1
        fi

        echo "${_tx_green}Archive created:${_tx_reset} $archive_file"
        echo "Manifest: $manifest_file"
        echo "Archive size: $(ls -lh "$archive_file" | awk '{print $5}')"

        read -q "REPLY?Remove original engagement directory? (y/N): "
        echo
        if [[ $REPLY == [Yy] ]]; then
            rm -rf "$base_dir"
            echo "Removed: $base_dir"
        fi
    else
        echo "${_tx_red}Failed to create archive${_tx_reset}"
        return 1
    fi
}

# Show engagement status
_tacmux_status() {
    local target="${1:-}"

    if [[ -z "$target" ]]; then
        echo "Usage: tacmux status <target>"
        return 1
    fi

    local workspace_name=$(_normalize_target "$target")
    local -a reply
    _tacmux_resolve "$workspace_name" || return 1
    local session="$reply[2]" base_dir="$reply[3]"

    echo "${_tx_bold}Op Status for $target${_tx_reset}"
    echo "=========================="

    if tmux has-session -t "=$session" 2>/dev/null; then
        echo "Status:  ${_tx_green}ACTIVE${_tx_reset}"
        echo "Session: $session"
        echo "Panes:   $(tmux list-panes -t "=$session" | wc -l)"
    else
        echo "Status:  ${_tx_dim}INACTIVE${_tx_reset}"
    fi

    if [[ -d "$base_dir" ]]; then
        echo "Directory: $base_dir"
        echo "Size:    $(du -sh "$base_dir" 2>/dev/null | cut -f1)"

        echo
        echo "${_tx_bold}Recent Log Activity:${_tx_reset}"
        echo "==================="
        local latest_log=$(find "$base_dir/logs" -name "*.log" -type f 2>/dev/null | sort -V | tail -1)
        if [[ -n "$latest_log" ]]; then
            echo "Latest log: $latest_log"
            echo "Last modified: $(stat -c %y "$latest_log" 2>/dev/null || stat -f %Sm "$latest_log" 2>/dev/null)"
            echo "Size: $(ls -lh "$latest_log" 2>/dev/null | awk '{print $5}')"
        else
            echo "No log files found"
        fi
    else
        echo "Directory: ${_tx_red}NOT FOUND${_tx_reset}"
    fi
}

# ─── Health Check ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

_tacmux_health_check() {
    local ok=0 warn=0 fail=0

    echo "${_tx_bold}TACMUX Health Check${_tx_reset}"
    echo "===================="
    echo

    # Required dependencies
    echo "${_tx_bold}Dependencies:${_tx_reset}"
    for cmd in tmux zsh python3; do
        if command -v "$cmd" &>/dev/null; then
            echo "  ${_tx_green}[ok]${_tx_reset} $cmd  $(command -v "$cmd")"
            ((ok++))
        else
            echo "  ${_tx_red}[FAIL]${_tx_reset} $cmd  NOT FOUND"
            ((fail++))
        fi
    done

    # Optional dependencies
    for cmd in fzf autorecon; do
        if command -v "$cmd" &>/dev/null; then
            echo "  ${_tx_green}[ok]${_tx_reset} $cmd  $(command -v "$cmd")"
            ((ok++))
        else
            echo "  ${_tx_yellow}[warn]${_tx_reset} $cmd  not found (optional)"
            ((warn++))
        fi
    done

    echo

    # Paths
    echo "${_tx_bold}Paths:${_tx_reset}"
    # `path` is a special zsh array tied to PATH; do not use it as an iterator.
    local label check_path
    for label check_path in \
        "TACMUX_HOME" "$TACMUX_HOME" \
        "TACMUX_WORKSPACE" "$TACMUX_WORKSPACE" \
        "TACMUX_CONFIG" "$TACMUX_CONFIG" \
        "TACMUX_ARCHIVE_DIR" "$TACMUX_ARCHIVE_DIR" \
        "TACMUX_LOG_DIR" "$TACMUX_LOG_DIR"; do
        if [[ -e "$check_path" ]]; then
            echo "  ${_tx_green}[ok]${_tx_reset} $label = $check_path"
            ((ok++))
        else
            echo "  ${_tx_yellow}[warn]${_tx_reset} $label = $check_path  (does not exist yet)"
            ((warn++))
        fi
    done

    echo

    # Shell integration
    echo "${_tx_bold}Shell Integration:${_tx_reset}"
    if [[ -f "$HOME/.zshrc" ]] && grep -q "tacmux-completions.zsh" "$HOME/.zshrc" 2>/dev/null; then
        echo "  ${_tx_green}[ok]${_tx_reset} zsh completions"
        ((ok++))
    else
        echo "  ${_tx_yellow}[warn]${_tx_reset} zsh completions not configured"
        ((warn++))
    fi
    if [[ -f "$HOME/.bashrc" ]] && grep -q "tacmux-completions.bash" "$HOME/.bashrc" 2>/dev/null; then
        echo "  ${_tx_green}[ok]${_tx_reset} bash completions"
        ((ok++))
    else
        echo "  ${_tx_dim}[--]${_tx_reset} bash  (not configured)"
    fi

    echo

    # Tmux integration
    echo "${_tx_bold}Tmux Integration:${_tx_reset}"
    if [[ -f "$HOME/.tmux.conf" ]] && grep -q "tacmux" "$HOME/.tmux.conf" 2>/dev/null; then
        echo "  ${_tx_green}[ok]${_tx_reset} tmux config references tacmux"
        ((ok++))
    else
        echo "  ${_tx_yellow}[warn]${_tx_reset} tmux config does not reference tacmux"
        ((warn++))
    fi

    echo

    # Companion tools
    echo "${_tx_bold}Companion Tools:${_tx_reset}"
    if command -v cap &>/dev/null; then
        echo "  ${_tx_green}[ok]${_tx_reset} nocap (cap)  NOCAP_WORKSPACE=$NOCAP_WORKSPACE"
        ((ok++))
    else
        echo "  ${_tx_dim}[--]${_tx_reset} nocap (cap)  not installed"
    fi
    if command -v sitrep &>/dev/null; then
        echo "  ${_tx_green}[ok]${_tx_reset} sitrep"
        ((ok++))
    else
        echo "  ${_tx_dim}[--]${_tx_reset} sitrep  not installed"
    fi

    echo
    echo "${_tx_bold}Summary:${_tx_reset} ${_tx_green}$ok ok${_tx_reset}, ${_tx_yellow}$warn warnings${_tx_reset}, ${_tx_red}$fail failures${_tx_reset}"

    [[ $fail -gt 0 ]] && return 1
    return 0
}

# ─── Config Display ──────────────────────────────────────────────────────────

_tacmux_show_config() {
    echo "${_tx_bold}TACMUX Effective Configuration${_tx_reset}"
    echo "================================="
    echo "  TACMUX_VERSION       = $TACMUX_VERSION"
    echo "  TACMUX_HOME          = $TACMUX_HOME"
    echo "  TACMUX_CONFIG        = $TACMUX_CONFIG"
    echo "  TACMUX_WORKSPACE     = $TACMUX_WORKSPACE"
    echo "  TACMUX_ARCHIVE_DIR   = $TACMUX_ARCHIVE_DIR"
    echo "  TACMUX_LOG_DIR       = $TACMUX_LOG_DIR"
    echo "  TACMUX_AUTOLOG       = $TACMUX_AUTOLOG"
    echo "  TACMUX_TARGET_DIRS   = $TACMUX_TARGET_DIRS"
    echo "  TACMUX_NOCAP_INTEGRATION = $TACMUX_NOCAP_INTEGRATION"
    echo "  TACMUX_COLOR         = $TACMUX_COLOR"
    echo "  TACMUX_UMASK         = $TACMUX_UMASK"
    echo
    if [[ -f "$TACMUX_CONFIG" ]]; then
        echo "${_tx_dim}Config loaded from: $TACMUX_CONFIG${_tx_reset}"
    else
        echo "${_tx_dim}No config file found; using defaults${_tx_reset}"
    fi
}

# ─── Help ────────────────────────────────────────────────────────────────────

_tacmux_help() {
    cat << EOF
${_tx_bold}TACMUX${_tx_reset} — tactical engagement workspaces for tmux  v$TACMUX_VERSION

${_tx_bold}Usage:${_tx_reset} tacmux <command> [arguments]

  engagement [name|clear]      Show or select the workspace mode
  start [-n] [-a] <target>     Create and attach to a logged session
  pause|resume|status <target> Manage a target session
  stop <target> [archive]      Stop it, optionally archive it
  archive <target>             Create a tar.gz and SHA-256 manifest
  rename <old> <new>           Rename a target workspace and session
  list | pick                  List or interactively select sessions
  mkop <directory>             Create only the target directory tree
  logs [directory...]          Browse logs with fzf
  log <action>                 start, force, stop, toggle, capture, status
  clip                         Copy stdin through tmux/GUI/OSC 52
  health | config | version    Diagnose or inspect TACMUX

${_tx_bold}Examples:${_tx_reset}
  tacmux engagement clear
  tacmux start 10.10.10.5

  tacmux engagement acme
  tacmux start -a 10.10.10.5:445

Flat targets live at \$TACMUX_WORKSPACE/<target>. Engagement targets live at
\$TACMUX_WORKSPACE/<engagement>/targets/<target>.
EOF
}

# Rename engagement workspace (directory + tmux session + env state)
_tacmux_rename() {
    local old_target="${1:-}" new_name="${2:-}"

    if [[ -z "$old_target" || -z "$new_name" ]]; then
        echo "Usage: tacmux rename <old_target> <new_name>"
        return 1
    fi

    local old_ws=$(_normalize_target "$old_target")
    local new_ws=$(_normalize_target "$new_name")
    local -a reply old_context new_context
    _tacmux_resolve "$old_ws" || return 1
    old_context=("${reply[@]}")
    _tacmux_resolve "$new_ws" || return 1
    new_context=("${reply[@]}")
    local old_rel="$old_context[1]" old_session="$old_context[2]" old_dir="$old_context[3]"
    local new_rel="$new_context[1]" new_session="$new_context[2]" new_dir="$new_context[3]"

    if [[ ! -d "$old_dir" ]]; then
        echo "${_tx_red}Error:${_tx_reset} No workspace directory: $old_dir"
        return 1
    fi

    if [[ -d "$new_dir" ]]; then
        echo "${_tx_red}Error:${_tx_reset} Workspace already exists: $new_dir"
        return 1
    fi
    if [[ "$old_session" != "$new_session" ]] && tmux has-session -t "=$new_session" 2>/dev/null; then
        echo "${_tx_red}Error:${_tx_reset} Tmux session already exists: $new_session"
        return 1
    fi

    # Rename workspace directory
    if ! mv "$old_dir" "$new_dir"; then
        echo "${_tx_red}Error:${_tx_reset} Failed to rename workspace directory"
        return 1
    fi
    echo "  ${_tx_bold}Directory:${_tx_reset} $old_ws → $new_ws"

    # Rename tmux session if live
    if tmux has-session -t "=$old_session" 2>/dev/null; then
        if ! tmux rename-session -t "=$old_session" "$new_session"; then
            mv "$new_dir" "$old_dir" 2>/dev/null
            echo "${_tx_red}Error:${_tx_reset} Failed to rename tmux session; directory rename rolled back"
            return 1
        fi
        tmux set-environment -t "=$new_session" TARGET "$new_ws"
        tmux set-environment -t "=$new_session" TACMUX_TARGET "$new_rel"

        # Re-pipe logging to new directory
        if [[ "$(tmux show-environment -t "=$new_session" TACMUX_NO_AUTOLOG 2>/dev/null)" != "TACMUX_NO_AUTOLOG=1" ]]; then
            local old_log=$(ls -t "$new_dir/logs"/*/*.log 2>/dev/null | head -1)
            [[ -n "$old_log" ]] && echo "=== Renamed: $old_ws → $new_ws at $(_tx_ts) ===" >> "$old_log"
            zsh "$TACMUX_HOME/lib/tacmux-logging.sh" stop "=$new_session:" >/dev/null
            zsh "$TACMUX_HOME/lib/tacmux-logging.sh" force "=$new_session:" renamed
        fi

        echo "  ${_tx_bold}Session:${_tx_reset}   $old_session → $new_session"
        echo "  ${_tx_yellow}Note:${_tx_reset}      Existing pane shells retain old target variables; new panes inherit the rename."
    else
        echo "  ${_tx_bold}Session:${_tx_reset}   ${_tx_dim}not running${_tx_reset}"
    fi

    echo
    echo "${_tx_green}Renamed:${_tx_reset} $old_ws → $new_ws"
}
