# TACMUX keybindings

TACMUX ships an integration fragment, not a complete tmux configuration. Your existing prefix, navigation, splits, status line, mouse behavior, and styling remain yours.

After pressing your tmux prefix:

| Key | Action |
|---|---|
| `M` | Open the action palette in a popup for the current pane's target |
| `E` | Open the engagement/target switcher in a popup |
| `T` | Toggle logging for the current TACMUX pane |
| `S` | Save an exact capture of the current pane (`scrollback_*.log`) into the engagement log directory; `tm snap`/`stop`/`close` write readable `.txt` copies of every pane log automatically |

Vi copy-mode `y` and mouse-drag copy use TACMUX's explicit clipboard path. TACMUX does not set copy mode or mouse behavior itself.

Prefix+`M` replaces tmux's default "clear marked pane" binding. The popup
receives the invoking pane and client explicitly, so actions apply to that
pane's engagement and target.

The `fzf` palette and switcher use standard fzf controls:

| Key | Action |
|---|---|
| Type | Filter sessions and targets |
| `Enter` | Start/switch to selection |
| `Ctrl+C` / `Escape` | Cancel |

General tmux shortcuts belong in an operator loadout or personal `~/.tmux.conf`.
