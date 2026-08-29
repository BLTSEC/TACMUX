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

BOLD=$'\e[1m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; RED=$'\e[31m'; RESET=$'\e[0m'
info() { printf '%s[+]%s %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '%s[!]%s %s\n' "$YELLOW" "$RESET" "$*"; }
die()  { printf '%s[!]%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }
step() { printf '\n%s==> %s%s\n' "$BOLD" "$*" "$RESET"; }

usage() {
    cat <<'EOF'
Usage: ./install.sh [options]

  --workspace PATH  Set the v2 workspace directory
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
        --full-tmux) TMUX_MODE="full"; shift ;;
        --skip-tmux) TMUX_MODE="skip"; shift ;;
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

for command_name in tmux python3 uv; do
    command -v "$command_name" >/dev/null 2>&1 || die "Required command not found: $command_name"
done
python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 11))' || \
    die "TACMUX requires Python 3.11 or newer"

if [[ -n "$WORKSPACE_OVERRIDE" ]]; then
    WORKSPACE="$WORKSPACE_OVERRIDE"
elif [[ -d /workspace && -w /workspace ]]; then
    WORKSPACE=/workspace
else
    WORKSPACE="$HOME/workspace"
fi
ARCHIVE_DIR="$HOME/archives"
[[ "$WORKSPACE" == /workspace ]] && ARCHIVE_DIR=/workspace/.tacmux/archives

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

validate_block "$HOME/.zshrc" '# >>> TACMUX >>>' '# <<< TACMUX <<<'
validate_block "$HOME/.bashrc" '# >>> TACMUX >>>' '# <<< TACMUX <<<'
if [[ "$TMUX_MODE" != skip ]]; then
    validate_block "$HOME/.tmux.conf" '# >>> TACMUX >>>' '# <<< TACMUX <<<'
fi

step "Installing locked TACMUX v2 application"
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
mkdir -p "$WORKSPACE" "$ARCHIVE_DIR" "$HOME/logs"
chmod 700 "$CONFIG_DIR" "$WORKSPACE" "$ARCHIVE_DIR" "$HOME/logs"

# v2 has no shell-sourced core or completion dependency. Remove only TACMUX's
# marked legacy blocks and preserve all unrelated shell content.
remove_block "$HOME/.zshrc" '# >>> TACMUX >>>' '# <<< TACMUX <<<'
remove_block "$HOME/.bashrc" '# >>> TACMUX >>>' '# <<< TACMUX <<<'

step "Installing tmux integration"
if [[ "$TMUX_MODE" == skip ]]; then
    warn "Skipped ~/.tmux.conf"
else
    if [[ "$TMUX_MODE" == auto ]]; then
        [[ -f "$HOME/.tmux.conf" ]] && TMUX_MODE=integration || TMUX_MODE=full
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
