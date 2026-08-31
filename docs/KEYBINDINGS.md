# TACMUX keybindings

## Open the cockpit

Press the tmux prefix, release it, then press `E`. The complete TACMUX tmux configuration uses `Ctrl+Space` as its prefix. The integration fragment keeps the prefix already configured by the operator.

## TUI

| Key | Action |
|---|---|
| `Enter` | Open/attach a target, edit Markdown, page read-only text, edit scope, or manage a discovery job |
| `a` | Actions for the selected engagement or active cockpit tab |
| `n` | Add a target |
| `d` | Host discovery actions |
| `e` | Return to the engagement picker (`g` remains a hidden alias) |
| `/` | Filter the active Targets, Records, or Documents table |
| `r` | Refresh sessions, jobs, topology, and SITREP |
| `1`–`5` | Targets, Scope, Records, Situation, Documents |
| `Ctrl+P` | Command Palette (fuzzy command search) |
| `Escape` | Close a modal/cancel an entry |
| `q` | Quit the cockpit; detached sessions continue |

The TACMUX cockpit uses its dedicated BLTSEC palette. A Nerd Font renders the
interface icons as intended.

From the engagement picker, `a` opens the engagement menu: open, edit details,
close/reopen, archive, or guarded delete. The Command Palette is the global
searchable command launcher; contextual Actions menus remain the primary flow.
Press `r` in the picker to choose a verified engagement archive to restore; the
same key works when no live engagements remain.

Discovery review:

| Key | Action |
|---|---|
| `Space` | Cycle Add / Merge / Ignore where valid |
| `m` | Choose the existing target for a merge |
| `Ctrl+S` | Commit reviewed decisions |

On the Documents tab, `a` offers **Create engagement handoff**, **View full file
in pager**, and, for editable Markdown, **Edit with `$VISUAL` or `$EDITOR`**.
TACMUX uses `$PAGER`, then `less -SR`, then `more` without adding an application
dependency.

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
| `H` | Force a fallback log under the configured log directory |
| `P` | Pin the pane title; empty input unpins it |

Automatic logging hooks ignore non-TACMUX sessions by default. `T`, `S`, and
`H` are explicit operator actions and remain available. Set
`behavior.log_outside_tacmux = true` to restore automatic logging for all tmux
sessions. Raw logs remain authoritative.

## Complete tmux configuration

These additional keys come only from the optional complete configuration:

| Key | Action |
|---|---|
| `x` / `y` | Split below / right |
| `h` `j` `k` `l` | Move between panes |
| `W` / `t` | Create / rename a window |
| `1`–`9` | Select a window |
| `r` | Reload `~/.tmux.conf` |
| `q` | Stop logging for the current pane |
| `L` | Show current-pane logging state and the last log path |

It uses vi copy mode. The `q` and `L` logging shortcuts intentionally replace
tmux's stock display-panes and last-client bindings only in this opinionated
mode. `y` and mouse-drag copies pass through TACMUX's explicit trusted clipboard
path. `set-clipboard external` prevents arbitrary pane applications from
writing the host clipboard merely by emitting clipboard escape sequences.

To keep all existing tmux style, prefix, and navigation choices, source only:

```tmux
source-file ~/.local/share/tacmux/tmux/tacmux-integration.conf
```
