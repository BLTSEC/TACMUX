#!/usr/bin/env bash

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="$HOME/.local/share/tacmux"
APP_DIR="$INSTALL_DIR/app"
COMPLETION_DIR="$INSTALL_DIR/completions"
BIN_DIR="$HOME/.local/bin"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/tacmux"
CONFIG_FILE="$CONFIG_DIR/config.toml"
STATE_FILE="$CONFIG_DIR/install-state"
WORKSPACE_OVERRIDE=""
TMUX_MODE="auto"

info() { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*"; }
die() { printf '[!] %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage: ./install.sh [options]

  --workspace PATH  Set the engagement parent directory on first install
  --skip-tmux       Do not change ~/.tmux.conf
  --unattended      Accepted for provisioning compatibility
  -h, --help        Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --workspace) [[ $# -ge 2 ]] || die "--workspace requires a path"; WORKSPACE_OVERRIDE="$2"; shift 2 ;;
        --workspace=*) WORKSPACE_OVERRIDE="${1#*=}"; shift ;;
        --skip-tmux) TMUX_MODE="skip"; shift ;;
        --unattended) shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "Unknown option: $1" ;;
    esac
done

for command_name in tmux fzf python3 uv; do
    command -v "$command_name" >/dev/null 2>&1 || die "Required command not found: $command_name"
done
python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 11))' || \
    die "TACMUX requires Python 3.11 or newer"

if [[ -e "$INSTALL_DIR" ]]; then
    [[ -f "$INSTALL_DIR/.tacmux-install" ]] || \
        die "Refusing to overwrite unmarked install directory: $INSTALL_DIR"
    marker=$(<"$INSTALL_DIR/.tacmux-install")
    [[ "$marker" == "tacmux-v3" ]] || \
        die "Refusing unknown TACMUX install marker: $marker"
fi

MANAGED_COMMAND="$APP_DIR/.venv/bin/tacmux"
if [[ -e "$BIN_DIR/tacmux" || -L "$BIN_DIR/tacmux" ]]; then
    if [[ ! -L "$BIN_DIR/tacmux" ]] || [[ "$(readlink "$BIN_DIR/tacmux")" != "$MANAGED_COMMAND" ]]; then
        die "Refusing to replace unrelated command: $BIN_DIR/tacmux"
    fi
fi
if [[ -f "$CONFIG_FILE" && -n "$WORKSPACE_OVERRIDE" ]]; then
    die "--workspace is first-install only; edit $CONFIG_FILE instead"
fi
if [[ "$TMUX_MODE" == auto && -f "$STATE_FILE" ]] && grep -qx 'TMUX_MODE=skip' "$STATE_FILE"; then
    TMUX_MODE=skip
fi
if [[ "$TMUX_MODE" == auto && -L "$HOME/.tmux.conf" ]]; then
    die "Refusing to edit linked tmux config; rerun with --skip-tmux"
fi

validate_block() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    awk '
        $0 == "# >>> TACMUX >>>" { if (inside) invalid=1; inside=1; next }
        $0 == "# <<< TACMUX <<<" { if (!inside) invalid=1; inside=0; next }
        END { exit(invalid || inside) }
    ' "$file" || die "Refusing to edit $file: malformed TACMUX markers"
}

remove_block() {
    local file="$1" temporary
    [[ -f "$file" ]] || return 0
    validate_block "$file"
    temporary=$(mktemp "${file}.XXXXXX")
    awk '
        $0 == "# >>> TACMUX >>>" { skip=1; next }
        $0 == "# <<< TACMUX <<<" { skip=0; next }
        !skip { print }
    ' "$file" > "$temporary"
    cp "$temporary" "$file"
    rm -f "$temporary"
}

install_block() {
    local file="$1" body="$2"
    mkdir -p "$(dirname "$file")"
    touch "$file"
    remove_block "$file"
    [[ ! -s "$file" || "$(tail -c 1 "$file" 2>/dev/null)" == $'\n' ]] || printf '\n' >> "$file"
    printf '\n# >>> TACMUX >>>\n%s\n# <<< TACMUX <<<\n' "$body" >> "$file"
}

mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/tmux" "$COMPLETION_DIR" "$BIN_DIR" "$CONFIG_DIR"
stage=$(mktemp -d "$INSTALL_DIR/.app-stage.XXXXXX")
backup="$INSTALL_DIR/.app-backup.$$"
swapped=0
cleanup() {
    if [[ "$swapped" == 1 ]]; then
        rm -rf -- "$APP_DIR"
        [[ ! -d "$backup" ]] || mv "$backup" "$APP_DIR"
    fi
    rm -rf -- "$stage" "$backup"
}
trap cleanup EXIT

cp "$SCRIPT_DIR/pyproject.toml" "$SCRIPT_DIR/uv.lock" "$SCRIPT_DIR/README.md" "$SCRIPT_DIR/LICENSE" "$stage/"
cp -R "$SCRIPT_DIR/src" "$stage/src"
find "$stage/src" -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
find "$stage/src" -depth -type d -name __pycache__ -empty -delete
[[ ! -d "$APP_DIR" ]] || mv "$APP_DIR" "$backup"
mv "$stage" "$APP_DIR"
swapped=1
uv sync --project "$APP_DIR" --frozen --no-dev --no-editable
rm -rf -- "$backup"
swapped=0
printf 'tacmux-v3\n' > "$INSTALL_DIR/.tacmux-install"
chmod 600 "$INSTALL_DIR/.tacmux-install"
rm -f "$INSTALL_DIR/tmux/tacmux.conf"
cp "$SCRIPT_DIR/tmux/tacmux-integration.conf" "$INSTALL_DIR/tmux/"
cp "$SCRIPT_DIR/completions/_tacmux" "$COMPLETION_DIR/"
ln -sfn "$MANAGED_COMMAND" "$BIN_DIR/tacmux"

if [[ ! -f "$CONFIG_FILE" ]]; then
    workspace=${WORKSPACE_OVERRIDE:-$HOME/workspace}
    python3 -c 'import json, pathlib, sys; source, destination, workspace = sys.argv[1:]; text = pathlib.Path(source).read_text(); text = text.replace("workspace = \"~/workspace\"", "workspace = " + json.dumps(workspace)); pathlib.Path(destination).write_text(text)' \
        "$SCRIPT_DIR/config/tacmux.toml.default" "$CONFIG_FILE" "$workspace"
    chmod 600 "$CONFIG_FILE"
    info "Created $CONFIG_FILE"
else
    info "Preserved $CONFIG_FILE"
fi

workspace=$(TACMUX_CONFIG="$CONFIG_FILE" PYTHONPATH="$SCRIPT_DIR/src" python3 -c 'from tacmux.config import load_settings; print(load_settings().workspace)')
mkdir -p "$workspace"

if [[ "$TMUX_MODE" == skip ]]; then
    warn "Skipped ~/.tmux.conf"
else
    install_block "$HOME/.tmux.conf" "source-file \"$INSTALL_DIR/tmux/tacmux-integration.conf\""
    info "Installed tmux integration"
fi

if command -v zsh >/dev/null 2>&1; then
    if [[ -L "$HOME/.zshrc" ]]; then
        warn "Skipped linked ~/.zshrc; add $COMPLETION_DIR to fpath manually"
    else
        ZSH_COMPLETION_BLOCK='fpath=("$HOME/.local/share/tacmux/completions" $fpath)
autoload -Uz compinit
(( $+functions[compdef] )) || compinit
autoload -Uz _tacmux
compdef _tacmux tacmux tm'
        install_block "$HOME/.zshrc" "$ZSH_COMPLETION_BLOCK"
        info "Installed Zsh completion for tacmux and tm"
    fi
fi
printf 'TMUX_MODE=%s\n' "$TMUX_MODE" > "$STATE_FILE"
chmod 600 "$STATE_FILE"

TACMUX_CONFIG="$CONFIG_FILE" "$BIN_DIR/tacmux" health
info "TACMUX v3 installed. Run: tacmux init NAME"
