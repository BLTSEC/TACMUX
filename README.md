# TACMUX

<p align="center">
  <img src="assets/TACMUX.jpg" alt="TACMUX — tactical engagement workspaces for tmux" width="100%">
</p>

<p align="center">
  <a href="https://github.com/BLTSEC/TACMUX/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/BLTSEC/TACMUX/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/BLTSEC/TACMUX/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/BLTSEC/TACMUX"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-2ea44f"></a>
</p>

TACMUX is the target-aware execution and evidence layer for terminal-based security assessments. One command creates the target tree, starts tmux, exports routing context, and logs every pane to the correct evidence directory.

> **Start a target once. Every pane inherits its context, logs to the right place, and is ready to archive.**

It uses native tmux features—no plugin manager, database, daemon, cloud account, or runtime plugin dependency.

> Use TACMUX only on systems and engagements you are authorized to assess. Review scope, logging, evidence handling, and retention requirements before testing.

## Before you install

TACMUX is ready to clone and install as an unprivileged user. It requires Linux, Git, tmux 3.2+, zsh, and Python 3. `fzf` and `autorecon` are optional.

The installer writes under `~/.local`, `~/.config/tacmux`, and your shell configuration. If `~/.tmux.conf` already exists, TACMUX adds only its integration block; otherwise it installs the complete default tmux configuration. Existing configuration and workspace data are preserved.

New workspaces, logs, archives, and manifests are owner-only by default (`umask 077`). Existing data is not recursively re-permissioned. Filesystems that ignore Unix modes—including some VM shared folders, FAT volumes, and network mounts—cannot enforce this protection; keep sensitive assessment evidence on a local encrypted Linux filesystem or an approved protected volume.

## Install

```bash
git clone https://github.com/BLTSEC/TACMUX.git
cd TACMUX
./install.sh
exec "$SHELL" -l
```

Confirm the installation with `tacmux health`. No root privileges are required by TACMUX itself.

## Start in 60 seconds

Flat mode is the default and fits labs, CTFs, and one-off targets:

```bash
tacmux start 10.10.10.5
# workspace/10.10.10.5/{recon,exploitation,loot,screenshots,reports,logs}
```

Select one engagement for an authorized operation, even when it crosses more
than one network boundary:

```bash
tacmux engagement acme
tacmux start 203.0.113.0/28
tacmux start vpn.acme.example
tacmux start 10.20.0.0/24
# workspace/acme/targets/<target>/...

tacmux engagement clear       # return future commands to flat mode
```

Inside each session, `TARGET`, `RPORT`, and `TACMUX_TARGET` identify the host and workspace route. `tacmux start -n <target>` is the explicit opt-out from automatic logging.

## What you get

- Context-aware pane logs under the active target; ordinary tmux sessions fall back to `~/logs`. Raw logs remain authoritative. The default rendered view is non-compacting and preserves repeated and sparse rendered lines; compact mode explicitly removes prompt redraw, padding, animation, and repeated-output artifacts.
- Secure remote copy paths through tmux `load-buffer -w`, with Wayland, X11, macOS, and OSC 52 fallbacks.
- A minimal engagement root for authorization, scope, activity, payloads, attack path, and findings.
- Target lifecycle commands for pause, resume, status, rename, and archive. Every archive receives a JSON sidecar manifest with context, counts, and SHA-256 hashes for the tarball and each archived file.
- Optional AutoRecon launch with `-a`, and shared workspace routing when [NOCAP](https://github.com/BLTSEC/NOCAP) is installed.

## Commands

```text
tacmux engagement [name|clear]      Show or select workspace mode
tacmux start [-n] [-a] <target>     Create and attach to a target session
tacmux pause|resume|status <target> Manage a target session
tacmux stop <target> [archive]      Stop it, optionally archive it
tacmux archive <target>             Create a tar.gz and SHA-256 manifest
tacmux rename <old> <new>           Rename workspace and live session
tacmux list | tacmux pick           Find active target sessions
tacmux mkop <directory>             Create only the target directory tree
tacmux logs [directory...]          Browse logs; Alt-k enables compact preview
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

The target directories are operational phases:

| Directory | Use |
|---|---|
| `recon` | Discovery, enumeration, and read-only validation |
| `exploitation` | Credential attacks, payloads, relays, coercion, execution, and pivots |
| `loot` | Credential or data acquisition, dumps, and offline cracking |
| `screenshots` | Visual evidence |
| `reports` | Report-ready transformations and exports |
| `logs` | Continuous TACMUX pane logs |

NOCAP uses the first five routes for selected command captures; TACMUX owns
`logs`. The tree is intentionally smaller than a full consulting delivery tree.
Add client-specific `Admin`, `Deliverables`, `Retest`, or specialist evidence
directories only when the engagement requires them.

### One engagement, multiple networks

Use the engagement as the authorization, evidence, and reporting boundary. Keep
external ranges, internal ranges, and individual hosts as targets beneath it:

```bash
tacmux engagement acme

# Directly reachable external range and initial-access host
tacmux start 203.0.113.0/28
tacmux start vpn.acme.example

# Internal discovery through an approved route
tacmux start 10.20.0.0/24
cap -a proxychains nmap -Pn -sT "$TARGET"

# Give important systems their own sessions as the path develops
tacmux start dc01.corp.acme.example
tacmux start 10.20.0.25
tacmux list
```

A range session holds broad discovery work. Start a dedicated host session when
a system becomes part of the access path, needs deeper enumeration, or produces
evidence worth keeping separate. TACMUX records the target and evidence route;
your VPN, SOCKS proxy, or Ligolo route still provides network access.
The `cap` line uses the optional NOCAP integration; run Nmap directly when NOCAP
is not installed.

Record each target's boundary and access path in `ENGAGEMENT.md`. TACMUX 1.2 has
no separate scope hierarchy: every target remains under `acme/targets/`. When
two networks reuse the same RFC1918 address, use unique DNS or `/etc/hosts`
aliases that resolve through the correct route. Use separate engagement roots
only when authorization, reporting, retention, or an unavoidable address
collision requires a real separation.

`tacmux rename` changes `TARGET` for panes created after the rename, so rename an
IP only to a hostname or alias your tools can resolve. Existing pane shells keep
their original environment; open a new pane before relying on the new value.

## Configure

Edit `~/.config/tacmux/tacmux.conf`:

```bash
TACMUX_WORKSPACE="$HOME/workspace"
TACMUX_ARCHIVE_DIR="$HOME/archives"
TACMUX_LOG_DIR="$HOME/logs"
TACMUX_AUTOLOG="true"
TACMUX_UMASK="077"
TACMUX_TARGET_DIRS="recon exploitation loot screenshots reports logs"
```

Use `TACMUX_UMASK="027"` only when an approved local group must share newly created data. TACMUX does not change permissions on pre-existing workspace content.

Useful installer modes:

```bash
./install.sh --full-tmux                  # install the opinionated tmux defaults
./install.sh --skip-tmux                  # install CLI only; do not edit tmux config
./install.sh --workspace /workspace       # persistent Exegol-style workspace
./install.sh --unattended --workspace /workspace
```

Upgrade by pulling a trusted release and rerunning `./install.sh`; local config is preserved. Remove the installed program with `./uninstall.sh`; config, archives, and workspace data remain in place.

More detail: [usage guide](docs/USAGE.md) · [field workflow](https://bltsec.com/blog/tacmux/) · [keybindings](docs/KEYBINDINGS.md) · [security policy](SECURITY.md)

## License

[MIT](LICENSE)
