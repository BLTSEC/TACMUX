# TACMUX

<p align="center">
  <img src="assets/TACMUX.jpg" alt="TACMUX — tactical engagement workspaces for tmux" width="100%">
</p>
<p align="center"><sub><a href="https://grok.com/imagine">Created with Grok</a></sub></p>

<p align="center">
  <a href="https://github.com/BLTSEC/TACMUX/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/BLTSEC/TACMUX/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/BLTSEC/TACMUX/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/BLTSEC/TACMUX"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-2ea44f"></a>
</p>

TACMUX turns tmux into a repeatable assessment workspace: one command creates the target tree, starts a session, exports routing context, and logs every pane. It uses native tmux features—no plugin manager or runtime plugin dependency.

> Use TACMUX only on systems and engagements you are authorized to assess. Review scope, logging, evidence handling, and retention requirements before testing.

## Install

Requires Linux, tmux 3.2+, zsh, and Python 3. `fzf` and `autorecon` are optional.

```bash
git clone https://github.com/BLTSEC/TACMUX.git
cd TACMUX
./install.sh
exec "$SHELL" -l
```

The installer uses the full TACMUX tmux configuration when `~/.tmux.conf` does not exist. If one already exists, it adds only the bindings and hooks in `tacmux-integration.conf`. Existing configuration and workspace data are preserved.

## Start in 60 seconds

Flat mode is the default and fits labs, CTFs, and one-off targets:

```bash
tacmux start 10.10.10.5
# workspace/10.10.10.5/{recon,exploitation,loot,screenshots,reports,logs}
```

Select an engagement for multi-target work:

```bash
tacmux engagement acme-internal
tacmux start 10.10.10.5
tacmux start -a 10.10.10.6:445
# workspace/acme-internal/targets/<target>/...

tacmux engagement clear       # return future commands to flat mode
```

Inside each session, `TARGET`, `RPORT`, and `TACMUX_TARGET` identify the host and workspace route. `tacmux start -n <target>` is the explicit opt-out from automatic logging.

## What you get

- Context-aware pane logs under the active target; ordinary tmux sessions fall back to `~/logs`.
- Secure remote copy paths through tmux `load-buffer -w`, with Wayland, X11, macOS, and OSC 52 fallbacks.
- A minimal engagement root for authorization, scope, activity, payloads, attack path, and findings.
- Target lifecycle commands for pause, resume, status, rename, archive, and interactive selection.
- Optional AutoRecon launch with `-a`, and shared workspace routing when [NOCAP](https://github.com/BLTSEC/NOCAP) is installed.

## Commands

```text
tacmux engagement [name|clear]      Show or select workspace mode
tacmux start [-n] [-a] <target>     Create and attach to a target session
tacmux pause|resume|status <target> Manage a target session
tacmux stop <target> [archive]      Stop it, optionally archive it
tacmux archive <target>             Create a timestamped tar.gz
tacmux rename <old> <new>           Rename workspace and live session
tacmux list | tacmux pick           Find active target sessions
tacmux mkop <directory>             Create only the target directory tree
tacmux logs [directory...]          Browse logs with fzf
tacmux log <action>                 start|force|stop|toggle|capture|status
tacmux clip                         Copy stdin to the trusted clipboard path
tacmux health | config | help       Diagnose or inspect TACMUX
```

## Default keys

Prefix: `Ctrl+Space`

| Key | Action |
|---|---|
| `T` | Toggle logging for the current pane |
| `S` | Capture the full pane scrollback |
| `L` | Show current logging state and file |
| `H` | Force a fallback log under `TACMUX_LOG_DIR` |
| `q` | Stop logging for the current pane |
| `P` | Pin or unpin the pane title |
| `x` / `y` | Split below / right |
| `h j k l` | Move between panes |
| `W` / `t` | Create / rename a window |
| `y` in copy mode | Copy through the trusted clipboard path |

See [KEYBINDINGS.md](docs/KEYBINDINGS.md) for the complete map.

## Engagement layout

```text
$TACMUX_WORKSPACE/acme-internal/
├── ENGAGEMENT.md
├── notes/
│   ├── activity.md
│   ├── attack-path.md
│   └── payloads.md
├── findings/
└── targets/
    └── 10.10.10.5/
        ├── recon/
        ├── exploitation/
        ├── loot/
        ├── screenshots/
        ├── reports/
        └── logs/YYYYMMDD/
```

This is intentionally smaller than a full consulting delivery tree. Add client-specific `Admin`, `Deliverables`, `Retest`, or specialist evidence directories only when the engagement requires them.

## Configure

Edit `~/.config/tacmux/tacmux.conf`:

```bash
TACMUX_WORKSPACE="$HOME/workspace"
TACMUX_ARCHIVE_DIR="$HOME/archives"
TACMUX_LOG_DIR="$HOME/logs"
TACMUX_AUTOLOG="true"
TACMUX_TARGET_DIRS="recon exploitation loot screenshots reports logs"
```

Useful installer modes:

```bash
./install.sh --full-tmux                  # install the opinionated tmux defaults
./install.sh --skip-tmux                  # install CLI only; do not edit tmux config
./install.sh --workspace /workspace       # persistent Exegol-style workspace
./install.sh --unattended --workspace /workspace
```

Upgrade by pulling a trusted release and rerunning `./install.sh`; local config is preserved. Remove the installed program with `./uninstall.sh`; config, archives, and workspace data remain in place.

More detail: [usage guide](docs/USAGE.md) · [keybindings](docs/KEYBINDINGS.md) · [security policy](SECURITY.md)

## License

[MIT](LICENSE)
