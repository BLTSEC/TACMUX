#!/usr/bin/env bash

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="$HOME/.local/share/tacmux"
APP_DIR="$INSTALL_DIR/app"
BIN_DIR="$HOME/.local/bin"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/tacmux"
CONFIG_FILE="$CONFIG_DIR/config.toml"
STATE_FILE="$CONFIG_DIR/install-state"
WORKSPACE_OVERRIDE=""
TMUX_MODE="auto"
TMUX_MODE_EXPLICIT=0

BOLD=$'\e[1m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; RED=$'\e[31m'; RESET=$'\e[0m'
info() { printf '%s[+]%s %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '%s[!]%s %s\n' "$YELLOW" "$RESET" "$*"; }
die()  { printf '%s[!]%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }
step() { printf '\n%s==> %s%s\n' "$BOLD" "$*" "$RESET"; }

usage() {
    cat <<'EOF'
Usage: ./install.sh [options]

  --workspace PATH  Set the workspace directory on first install
  --full-tmux       Source TACMUX's opinionated complete tmux configuration
  --skip-tmux       Do not change ~/.tmux.conf
  --unattended      Accepted for provisioning compatibility; never prompts
  -h, --help        Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --workspace) [[ $# -ge 2 ]] || die "--workspace requires a path"; WORKSPACE_OVERRIDE="$2"; shift 2 ;;
        --workspace=*) WORKSPACE_OVERRIDE="${1#*=}"; shift ;;
        --full-tmux) TMUX_MODE="full"; TMUX_MODE_EXPLICIT=1; shift ;;
        --skip-tmux) TMUX_MODE="skip"; TMUX_MODE_EXPLICIT=1; shift ;;
        --unattended) shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "Unknown option: $1" ;;
    esac
done

[[ -z "${TACMUX_HOME:-}" ]] || die "TACMUX_HOME is not supported; TACMUX installs in $INSTALL_DIR"
if [[ -e "$INSTALL_DIR" ]] && {
    [[ ! -f "$INSTALL_DIR/.tacmux-install" ]] ||
    [[ "$(<"$INSTALL_DIR/.tacmux-install")" != tacmux-v2 ]];
}; then
    die "Refusing to overwrite unmarked install directory: $INSTALL_DIR"
fi
INSTALL_DIR_EXISTED=0
[[ ! -e "$INSTALL_DIR" ]] || INSTALL_DIR_EXISTED=1
MANAGED_COMMAND="$APP_DIR/.venv/bin/tacmux"
if [[ -e "$BIN_DIR/tacmux" || -L "$BIN_DIR/tacmux" ]]; then
    if [[ ! -L "$BIN_DIR/tacmux" ]] || [[ "$(readlink "$BIN_DIR/tacmux")" != "$MANAGED_COMMAND" ]]; then
        die "Refusing to replace unrelated command: $BIN_DIR/tacmux"
    fi
fi

for command_name in tmux python3 uv; do
    command -v "$command_name" >/dev/null 2>&1 || die "Required command not found: $command_name"
done
python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 11, 4))' || \
    die "TACMUX requires Python 3.11.4 or newer"

if [[ "$TMUX_MODE_EXPLICIT" == 0 && -f "$STATE_FILE" ]]; then
    previous_state=$(<"$STATE_FILE")
    case "$previous_state" in
        TMUX_MODE=skip) TMUX_MODE=skip ;;
        TMUX_MODE=full) TMUX_MODE=full ;;
        TMUX_MODE=integration) TMUX_MODE=integration ;;
        *) warn "Ignoring invalid install state: $STATE_FILE" ;;
    esac
fi

if [[ -f "$CONFIG_FILE" ]]; then
    CONFIG_PATHS_FILE=$(mktemp)
    if ! PYTHONPATH="$SCRIPT_DIR/src" TACMUX_CONFIG="$CONFIG_FILE" python3 -c \
        'from tacmux.config import load_settings; value=load_settings(); print(value.workspace); print(value.archive_dir); print(value.log_dir)' \
        > "$CONFIG_PATHS_FILE"; then
        rm -f "$CONFIG_PATHS_FILE"
        die "Cannot read existing TACMUX paths from $CONFIG_FILE"
    fi
    mapfile -t CONFIG_PATHS < "$CONFIG_PATHS_FILE"
    rm -f "$CONFIG_PATHS_FILE"
    [[ "${#CONFIG_PATHS[@]}" == 3 ]] || die "Existing TACMUX config returned invalid paths"
    WORKSPACE="${CONFIG_PATHS[0]}"
    ARCHIVE_DIR="${CONFIG_PATHS[1]}"
    LOG_DIR="${CONFIG_PATHS[2]}"
    if [[ -n "$WORKSPACE_OVERRIDE" ]]; then
        WORKSPACE_OVERRIDE_RESOLVED=$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).expanduser().resolve())' "$WORKSPACE_OVERRIDE")
        [[ "$WORKSPACE_OVERRIDE_RESOLVED" == "$WORKSPACE" ]] || \
            die "--workspace disagrees with existing config ($WORKSPACE); edit $CONFIG_FILE instead"
    fi
else
    if [[ -n "$WORKSPACE_OVERRIDE" ]]; then
        WORKSPACE="$WORKSPACE_OVERRIDE"
    elif [[ -d /workspace && -w /workspace ]]; then
        WORKSPACE=/workspace
    else
        WORKSPACE="$HOME/workspace"
    fi
    ARCHIVE_DIR="$HOME/archives"
    [[ "$WORKSPACE" == /workspace ]] && ARCHIVE_DIR=/workspace/.tacmux/archives
    LOG_DIR="$HOME/logs"
fi

validate_block() {
    local file="$1" start="$2" end="$3"
    [[ -f "$file" ]] || return 0
    awk -v start="$start" -v end="$end" '
        $0 == start { if (inside) invalid=1; inside=1; next }
        $0 == end   { if (!inside) invalid=1; inside=0; next }
        END { exit(invalid || inside) }
    ' "$file" || die "Refusing to edit $file: malformed TACMUX markers"
}

remove_block() {
    local file="$1" start="$2" end="$3" temporary
    [[ -f "$file" ]] || return 0
    validate_block "$file" "$start" "$end"
    temporary=$(mktemp "${file}.XXXXXX")
    awk -v start="$start" -v end="$end" '
        $0 == start { skip=1; next }
        $0 == end   { skip=0; next }
        !skip       { print }
    ' "$file" > "$temporary"
    cp "$temporary" "$file"
    rm -f "$temporary"
}

install_block() {
    local file="$1" start="$2" end="$3" body="$4"
    mkdir -p "$(dirname "$file")"
    touch "$file"
    remove_block "$file" "$start" "$end"
    [[ ! -s "$file" || "$(tail -c 1 "$file" 2>/dev/null)" == $'\n' ]] || printf '\n' >> "$file"
    printf '\n%s\n%s\n%s\n' "$start" "$body" "$end" >> "$file"
}

managed_tmux_mode() {
    local file="$1"
    [[ -f "$file" ]] || return 1
    awk '
        $0 == "# >>> TACMUX >>>" { inside=1; next }
        $0 == "# <<< TACMUX <<<" { inside=0; next }
        inside && $0 ~ /\/tmux\/tacmux-integration\.conf"?[[:space:]]*$/ {
            mode="integration"
        }
        inside && $0 ~ /\/tmux\/tacmux\.conf"?[[:space:]]*$/ {
            mode="full"
        }
        END {
            if (!mode) exit 1
            print mode
        }
    ' "$file"
}

if [[ "$TMUX_MODE" != skip ]]; then
    validate_block "$HOME/.tmux.conf" '# >>> TACMUX >>>' '# <<< TACMUX <<<'
fi

step "Installing locked TACMUX application"
mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/tmux" "$INSTALL_DIR/lib" "$BIN_DIR" "$CONFIG_DIR"
APP_STAGE=$(mktemp -d "$INSTALL_DIR/.app-stage.XXXXXX")
APP_BACKUP="$INSTALL_DIR/.app-backup.$$"
APP_SWAPPED=0
cleanup_stage() {
    if [[ "$APP_SWAPPED" == 1 ]]; then
        rm -rf -- "$APP_DIR"
        [[ ! -d "$APP_BACKUP" ]] || mv "$APP_BACKUP" "$APP_DIR"
    fi
    rm -rf -- "$APP_STAGE" "$APP_BACKUP"
    if [[ "$INSTALL_DIR_EXISTED" == 0 && ! -f "$INSTALL_DIR/.tacmux-install" ]]; then
        rm -rf -- "$INSTALL_DIR"
    fi
}
trap cleanup_stage EXIT
cp "$SCRIPT_DIR/pyproject.toml" "$SCRIPT_DIR/uv.lock" "$SCRIPT_DIR/README.md" "$SCRIPT_DIR/LICENSE" "$APP_STAGE/"
cp -R "$SCRIPT_DIR/src" "$APP_STAGE/src"
find "$APP_STAGE/src" -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
find "$APP_STAGE/src" -depth -type d -name __pycache__ -empty -delete
[[ ! -d "$APP_DIR" ]] || mv "$APP_DIR" "$APP_BACKUP"
mv "$APP_STAGE" "$APP_DIR"
APP_SWAPPED=1
uv sync --project "$APP_DIR" --frozen --no-dev --no-editable
rm -rf -- "$APP_BACKUP"
APP_SWAPPED=0
printf 'tacmux-v2\n' > "$INSTALL_DIR/.tacmux-install"
chmod 600 "$INSTALL_DIR/.tacmux-install"
cp "$SCRIPT_DIR/tmux/"* "$INSTALL_DIR/tmux/"
cp "$SCRIPT_DIR/lib/tacmux-pane-guard.sh" "$INSTALL_DIR/lib/"
chmod +x "$INSTALL_DIR/lib/tacmux-pane-guard.sh"
ln -sfn "$APP_DIR/.venv/bin/tacmux" "$BIN_DIR/tacmux"
info "Installed application in $APP_DIR"
info "Installed command at $BIN_DIR/tacmux"

step "Configuring private workspace"
if [[ ! -f "$CONFIG_FILE" ]]; then
    python3 -c 'import json, pathlib, sys; source, destination, workspace, archive = sys.argv[1:]; text = pathlib.Path(source).read_text(); text = text.replace("workspace = \"~/workspace\"", "workspace = " + json.dumps(workspace)).replace("archive_dir = \"~/archives\"", "archive_dir = " + json.dumps(archive)); pathlib.Path(destination).write_text(text)' \
        "$SCRIPT_DIR/config/tacmux.toml.default" "$CONFIG_FILE" "$WORKSPACE" "$ARCHIVE_DIR"
    chmod 600 "$CONFIG_FILE"
    info "Created $CONFIG_FILE"
else
    info "Preserved $CONFIG_FILE"
fi
mkdir -p "$WORKSPACE" "$ARCHIVE_DIR" "$LOG_DIR"
chmod 700 "$CONFIG_DIR" "$WORKSPACE" "$ARCHIVE_DIR" "$LOG_DIR"

step "Installing tmux integration"
if [[ "$TMUX_MODE" == skip ]]; then
    warn "Skipped ~/.tmux.conf"
else
    if [[ "$TMUX_MODE" == auto ]]; then
        # A TACMUX-created ~/.tmux.conf exists after the first install. Preserve
        # the managed source choice instead of treating its existence as proof
        # that the operator supplied a custom configuration.
        previous_tmux_mode=$(managed_tmux_mode "$HOME/.tmux.conf" || true)
        if [[ -n "$previous_tmux_mode" ]]; then
            TMUX_MODE="$previous_tmux_mode"
        elif [[ -f "$HOME/.tmux.conf" ]]; then
            TMUX_MODE=integration
        else
            TMUX_MODE=full
        fi
    fi
    if [[ "$TMUX_MODE" == full ]]; then
        tmux_source="source-file \"$INSTALL_DIR/tmux/tacmux.conf\""
    else
        tmux_source="source-file \"$INSTALL_DIR/tmux/tacmux-integration.conf\""
    fi
    install_block "$HOME/.tmux.conf" '# >>> TACMUX >>>' '# <<< TACMUX <<<' "$tmux_source"
    info "Configured tmux mode: $TMUX_MODE"
fi
printf 'TMUX_MODE=%q\n' "$TMUX_MODE" > "$STATE_FILE"
chmod 600 "$STATE_FILE"

if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    warn "$BIN_DIR is not in PATH"
fi

step "Verifying"
TACMUX_CONFIG="$CONFIG_FILE" "$BIN_DIR/tacmux" health
printf '\n%s[+]%s TACMUX v2 installed. Run: tacmux\n' "$GREEN" "$RESET"
