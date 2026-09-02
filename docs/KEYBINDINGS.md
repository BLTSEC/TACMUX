# TACMUX keybindings

TACMUX ships an integration fragment, not a complete tmux configuration. Your existing prefix, navigation, splits, status line, mouse behavior, and styling remain yours.

After pressing your tmux prefix:

| Key | Action |
|---|---|
| `E` | Open the engagement/target switcher in a popup |
| `T` | Toggle logging for the current TACMUX pane |
| `S` | Save current-pane scrollback into the engagement log directory |

Vi copy-mode `y` and mouse-drag copy use TACMUX's explicit clipboard path. TACMUX does not set copy mode or mouse behavior itself.

The `fzf` switcher uses standard fzf controls:

| Key | Action |
|---|---|
| Type | Filter sessions and targets |
| `Enter` | Start/switch to selection |
| `Ctrl+C` / `Escape` | Cancel |

General tmux shortcuts belong in an operator loadout or personal `~/.tmux.conf`.
