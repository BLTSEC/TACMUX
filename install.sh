#!/usr/bin/env bash

set -euo pipefail

# Installation state and newly created workspaces may lead directly to client
# evidence. Do not let the caller's permissive shell umask make them public.
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${TACMUX_HOME:-$HOME/.local/share/tacmux}"
BIN_DIR="$HOME/.local/bin"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/tacmux"
CONFIG_FILE="$CONFIG_DIR/tacmux.conf"
STATE_FILE="$CONFIG_DIR/install-state"
WORKSPACE_OVERRIDE=""
TMUX_MODE="auto"
UNATTENDED=0

BOLD=$'\e[1m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; RED=$'\e[31m'; RESET=$'\e[0m'
info() { printf '%s[+]%s %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '%s[!]%s %s\n' "$YELLOW" "$RESET" "$*"; }
die()  { printf '%s[!]%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }
step() { printf '\n%s==> %s%s\n' "$BOLD" "$*" "$RESET"; }

usage() {
    cat <<'EOF'
Usage: ./install.sh [options]

  --workspace PATH  Set TACMUX_WORKSPACE
  --full-tmux       Source TACMUX's complete tmux configuration
  --skip-tmux       Do not change ~/.tmux.conf
  --unattended      Accepted for provisioning scripts; never prompts
  -h, --help        Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --workspace) [[ $# -ge 2 ]] || die "--workspace requires a path"; WORKSPACE_OVERRIDE="$2"; shift 2 ;;
        --workspace=*) WORKSPACE_OVERRIDE="${1#*=}"; shift ;;
        --full-tmux) TMUX_MODE="full"; shift ;;
        --skip-tmux) TMUX_MODE="skip"; shift ;;
        --unattended) UNATTENDED=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "Unknown option: $1" ;;
    esac
done

for command_name in tmux zsh python3; do
    command -v "$command_name" >/dev/null 2>&1 || die "Required command not found: $command_name"
done

if [[ -n "$WORKSPACE_OVERRIDE" ]]; then
    WORKSPACE="$WORKSPACE_OVERRIDE"
elif [[ -d /workspace && -w /workspace ]]; then
    WORKSPACE=/workspace
else
    WORKSPACE="$HOME/workspace"
fi

remove_block() {
    local file="$1" start="$2" end="$3" temporary
    [[ -f "$file" ]] || return 0
    temporary=$(mktemp "${file}.XXXXXX")
    awk -v start="$start" -v end="$end" '
        $0 == start { skip=1; next }
        $0 == end   { skip=0; next }
        !skip       { print }
    ' "$file" > "$temporary"
    cat "$temporary" > "$file"
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

step "Installing TACMUX"
mkdir -p "$INSTALL_DIR"/{bin,lib,tmux} "$BIN_DIR" "$CONFIG_DIR"
cp "$SCRIPT_DIR"/bin/{tacmux,tacmux-clip,logview,logrender} "$INSTALL_DIR/bin/"
for library_file in "$SCRIPT_DIR"/lib/*; do
    [[ -f "$library_file" ]] && cp "$library_file" "$INSTALL_DIR/lib/"
done
cp "$SCRIPT_DIR"/tmux/* "$INSTALL_DIR/tmux/"
chmod +x "$INSTALL_DIR"/bin/* "$INSTALL_DIR"/lib/tacmux-{logging,pane-guard,status}.sh
cp "$INSTALL_DIR/bin/tacmux" "$BIN_DIR/tacmux"
chmod +x "$BIN_DIR/tacmux"
info "Installed files in $INSTALL_DIR"
info "Installed command at $BIN_DIR/tacmux"

step "Configuring workspace"
if [[ ! -f "$CONFIG_FILE" ]]; then
    archive_dir='${HOME}/archives'
    [[ "$WORKSPACE" == /workspace ]] && archive_dir='/workspace/.tacmux/archives'
    sed \
        -e "s|^#TACMUX_WORKSPACE=.*|TACMUX_WORKSPACE=\"$WORKSPACE\"|" \
        -e "s|^#TACMUX_ARCHIVE_DIR=.*|TACMUX_ARCHIVE_DIR=\"$archive_dir\"|" \
        "$SCRIPT_DIR/config/tacmux.conf.default" > "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"
    info "Created $CONFIG_FILE"
else
    info "Preserved $CONFIG_FILE"
fi
mkdir -p "$WORKSPACE"

step "Installing shell completions"
zsh_body='[[ -f "$HOME/.local/share/tacmux/lib/tacmux-completions.zsh" ]] && source "$HOME/.local/share/tacmux/lib/tacmux-completions.zsh"'
bash_body='[[ -f "$HOME/.local/share/tacmux/lib/tacmux-completions.bash" ]] && source "$HOME/.local/share/tacmux/lib/tacmux-completions.bash"'
[[ -f "$HOME/.zshrc" ]] && install_block "$HOME/.zshrc" '# >>> TACMUX >>>' '# <<< TACMUX <<<' "$zsh_body"
[[ -f "$HOME/.bashrc" ]] && install_block "$HOME/.bashrc" '# >>> TACMUX >>>' '# <<< TACMUX <<<' "$bash_body"

step "Installing tmux integration"
if [[ "$TMUX_MODE" == skip ]]; then
    warn "Skipped ~/.tmux.conf"
else
    if [[ "$TMUX_MODE" == auto ]]; then
        [[ -f "$HOME/.tmux.conf" ]] && TMUX_MODE=integration || TMUX_MODE=full
    fi
    if [[ "$TMUX_MODE" == full ]]; then
        tmux_source='source-file ~/.local/share/tacmux/tmux/tacmux.conf'
    else
        tmux_source='source-file ~/.local/share/tacmux/tmux/tacmux-integration.conf'
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
TACMUX_HOME="$INSTALL_DIR" TACMUX_CONFIG="$CONFIG_FILE" "$BIN_DIR/tacmux" health || true
printf '\n%s[+]%s TACMUX installed. Open a new shell, then run: tacmux start <target>\n' "$GREEN" "$RESET"
