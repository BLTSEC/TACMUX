#!/usr/bin/env bash

set -euo pipefail

INSTALL_DIR="$HOME/.local/share/tacmux"
BIN="$HOME/.local/bin/tacmux"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/tacmux"

[[ -z "${TACMUX_HOME:-}" ]] || {
    printf 'TACMUX_HOME is not supported; TACMUX installs in %s\n' "$INSTALL_DIR" >&2
    exit 1
}

if [[ ! -f "$INSTALL_DIR/.tacmux-install" ]] || \
   [[ "$(<"$INSTALL_DIR/.tacmux-install")" != tacmux-v2 ]]; then
    [[ ! -e "$INSTALL_DIR" ]] || printf 'Skipped unmarked install directory: %s\n' "$INSTALL_DIR" >&2
    exit 0
fi

validate_block() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    if ! awk '
        $0 == "# >>> TACMUX >>>" { if (inside) invalid=1; inside=1; next }
        $0 == "# <<< TACMUX <<<" { if (!inside) invalid=1; inside=0; next }
        END { exit(invalid || inside) }
    ' "$file"; then
        printf 'Refusing to edit %s: malformed TACMUX markers\n' "$file" >&2
        return 1
    fi
}

remove_block() {
    local file="$1" temporary
    [[ -f "$file" ]] || return 0
    temporary=$(mktemp "${file}.XXXXXX")
    awk '
        $0 == "# >>> TACMUX >>>" { skip=1; next }
        $0 == "# <<< TACMUX <<<" { skip=0; next }
        !skip { print }
    ' "$file" > "$temporary"
    cp "$temporary" "$file"
    rm -f "$temporary"
}

validate_block "$HOME/.tmux.conf"
remove_block "$HOME/.tmux.conf"

if [[ -L "$BIN" ]] && \
   [[ "$(readlink -f "$BIN")" == "$INSTALL_DIR/app/.venv/bin/tacmux" ]]; then
    rm -f "$BIN"
elif [[ -e "$BIN" || -L "$BIN" ]]; then
    printf 'Preserved unrelated command: %s\n' "$BIN" >&2
fi
rm -rf -- "$INSTALL_DIR"

echo "TACMUX removed. Configuration, archives, and workspace evidence were preserved."
[[ -d "$CONFIG_DIR" ]] && echo "Preserved: $CONFIG_DIR"
exit 0
