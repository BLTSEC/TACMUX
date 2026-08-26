#!/usr/bin/env bash

set -euo pipefail

INSTALL_DIR="${TACMUX_HOME:-$HOME/.local/share/tacmux}"
BIN="$HOME/.local/bin/tacmux"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/tacmux"

remove_block() {
    local file="$1" temporary
    [[ -f "$file" ]] || return 0
    temporary=$(mktemp "${file}.XXXXXX")
    awk '
        $0 == "# >>> TACMUX >>>" { skip=1; next }
        $0 == "# <<< TACMUX <<<" { skip=0; next }
        !skip { print }
    ' "$file" > "$temporary"
    cat "$temporary" > "$file"
    rm -f "$temporary"
}

remove_block "$HOME/.zshrc"
remove_block "$HOME/.bashrc"
remove_block "$HOME/.tmux.conf"

[[ -f "$BIN" ]] && rm -f "$BIN"
if [[ -d "$INSTALL_DIR" ]]; then
    rm -rf -- "$INSTALL_DIR"
fi

echo "TACMUX removed. Configuration and workspace data were preserved."
[[ -d "$CONFIG_DIR" ]] && echo "Preserved: $CONFIG_DIR"
