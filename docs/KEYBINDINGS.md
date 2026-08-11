# TACMUX keybindings

The complete configuration uses `Ctrl+Space` as its prefix. If the installer detects an existing `~/.tmux.conf`, it keeps that file’s prefix and adds only the TACMUX-specific bindings and hooks.

## Logging and evidence

Press the tmux prefix, release it, then press:

| Key | Action |
|---|---|
| `T` | Toggle context-aware logging on the current pane |
| `S` | Save up to 50,000 lines of current-pane scrollback |
| `L` | Display logging state and the active file |
| `H` | Force logging to the fallback log directory |
| `q` | Stop logging on the current pane |
| `P` | Prompt for a pinned pane title; empty input unpins it |

## Layout and navigation

These keys come from the optional complete TACMUX configuration:

| Key | Action |
|---|---|
| `x` | Split below |
| `y` | Split right |
| `h` `j` `k` `l` | Select left, down, up, right pane |
| `W` | Create a named window |
| `t` | Rename the current window |
| `1`–`9` | Select window by number |
| `r` | Reload `~/.tmux.conf` |
| `d` | Detach the client (tmux default) |

## Copy mode

The complete config uses vi copy mode:

| Input | Action |
|---|---|
| `y` | Copy selection through `tacmux clip` and exit copy mode |
| Mouse drag | Copy selection through `tacmux clip` |

The copy command uses tmux’s trusted `load-buffer -w` path, which supports OSC 52 forwarding through SSH while `set-clipboard external` prevents arbitrary pane applications from writing the clipboard.

## Use only the integration fragment

Source this from an existing tmux config to keep your prefix, style, split keys, and navigation:

```tmux
source-file ~/.local/share/tacmux/tmux/tacmux-integration.conf
```

Or rerun `./install.sh`; the automatic mode chooses this fragment whenever `~/.tmux.conf` already exists.

Optional status segment:

```tmux
set -g status-right '#(~/.local/share/tacmux/lib/tacmux-status.sh) %H:%M '
```
