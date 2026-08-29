# TACMUX keybindings

## Open the cockpit

Press the tmux prefix, release it, then press `E`. The complete TACMUX tmux configuration uses `Ctrl+Space` as its prefix. The integration fragment keeps the prefix already configured by the operator.

## TUI

| Key | Action |
|---|---|
| `Enter` | Open/attach a target, edit Markdown, edit scope, or manage a discovery job |
| `a` | Contextual actions for the active tab |
| `n` | Add a target |
| `d` | Host discovery actions |
| `g` | Return to the engagement picker |
| `/` | Filter targets or engagements |
| `r` | Refresh sessions, jobs, topology, and SITREP |
| `1`–`4` | Targets, Scope & Discovery, Situation, Documents |
| `Ctrl+P` | Fuzzy command palette |
| `Escape` | Close a modal/cancel an entry |
| `q` | Quit the cockpit; detached sessions continue |

Discovery review:

| Key | Action |
|---|---|
| `Space` | Cycle Add / Merge / Ignore where valid |
| `m` | Choose the existing target for a merge |
| `Ctrl+S` | Commit reviewed decisions |

Attack-path builder:

| Key | Action |
|---|---|
| `Enter` | Add the highlighted confirmed record |
| `Delete` | Remove the highlighted chosen step |
| `Ctrl+Up` / `Ctrl+Down` | Reorder the chosen step |

## tmux logging and evidence

Press the tmux prefix, then:

| Key | Action |
|---|---|
| `T` | Toggle logging for the current pane |
| `S` | Capture full current-pane scrollback |
| `L` | Display logging state and active file |
| `H` | Force a fallback log under the configured log directory |
| `q` | Stop current-pane logging |
| `P` | Pin the pane title; empty input unpins it |

Logging hooks use target context when a pane belongs to TACMUX and the fallback directory otherwise. Raw logs remain authoritative.

## Complete tmux configuration

These additional keys come only from the optional complete configuration:

| Key | Action |
|---|---|
| `x` / `y` | Split below / right |
| `h` `j` `k` `l` | Move between panes |
| `W` / `t` | Create / rename a window |
| `1`–`9` | Select a window |
| `r` | Reload `~/.tmux.conf` |

It uses vi copy mode. `y` and mouse-drag copies pass through TACMUX's explicit trusted clipboard path. `set-clipboard external` prevents arbitrary pane applications from writing the host clipboard merely by emitting clipboard escape sequences.

To keep all existing tmux style, prefix, and navigation choices, source only:

```tmux
source-file ~/.local/share/tacmux/tmux/tacmux-integration.conf
```
