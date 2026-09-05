# TACMUX

<p align="center">
  <img src="assets/TACMUX.jpg" alt="TACMUX — tactical engagement workspaces for tmux" width="100%">
</p>

<p align="center">
  <a href="https://github.com/BLTSEC/TACMUX/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/BLTSEC/TACMUX/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-2ea44f"></a>
</p>

TACMUX is a lean tmux-native workspace helper for authorized penetration tests and red-team operations. It keeps you in your shells while handling target sessions, pane logs, credentials, ports, tasks, cleanup, and a single editable situation report.

Target directories are inventory, `SITREP.md` holds the working notes and current state, `fzf` switches sessions, and `$EDITOR` handles longer edits.

> Use TACMUX only with explicit authorization. You remain responsible for scope, rules of engagement, testing windows, evidence handling, and retention.

## Requirements

- Linux and Python 3.11+
- tmux and [fzf](https://github.com/junegunn/fzf)
- [uv](https://docs.astral.sh/uv/) for installation
- `$VISUAL`, `$EDITOR`, or `vi`
- Optional: Zsh; the installer enables completion for `tacmux` and `tm`
- Optional: Nmap for foreground host identification
- Optional: [NOCAP](https://github.com/BLTSEC/NOCAP) 2.3+ for engagement-wide captures

## Install

```bash
git clone --branch v3.0.0 --depth 1 https://github.com/BLTSEC/TACMUX.git
cd TACMUX
./install.sh --workspace ~/workspace
exec "$SHELL" -l
tacmux health
```

The installer places TACMUX under `~/.local/share/tacmux`, links the command into `~/.local/bin`, enables Zsh completion, and adds only the TACMUX integration fragment to an existing `~/.tmux.conf`. General tmux preferences belong to the operator or system loadout. Start a new shell after installation so completion is active.

On reinstall, omit `--workspace` to preserve the existing configuration. For the shorthand used below, add `alias tm='tacmux'` to your shell configuration and reload it.

## Start working

```bash
tacmux init ACME
cd ~/workspace/ACME
tacmux target add WEB01 192.0.2.10
tacmux switch
```

Inside the target session:

```bash
tm log "Nginx and SSH identified"
tm todo add "Enumerate the web application"
tm creds add
nmap -sV "$TARGET" | tm ports add
tm log "Service enumeration complete; web testing still pending"
tm status
```

Run scans only against authorized endpoints. `ports add` accepts a matching single-host Nmap report; host identification through `tm discover` is a separate, reviewed import. TACMUX installs the `tacmux` executable, not a separate `tm` command.

After a real validation run captured with NOCAP, record the demonstrated result with `tm done -c "Completed step"`. A local `cap id` proves the identity of the local process, not access to the target.

## Core commands

```text
tacmux                         fzf session/target switcher
tacmux init [NAME]             create or open an engagement
tacmux target add|update|export|rename|delete
tacmux stop [TARGET]           stop a target or ops session
tacmux status [TARGET]         concise operational status
tacmux sitrep [SECTION]        edit SITREP at an optional heading
tacmux sitrep sync             upgrade, validate, and repair scaffolding
tacmux log [OUTCOME] [-c] [-i IMAGE] TEXT
tacmux done [-c] [-i IMAGE] TEXT
tacmux history [TARGET]        show Operations Log history
tacmux log edit [EVENT_ID]     jump to a recorded step for editing
tacmux creds [view|add|confirm] credentials and confirmed access
tacmux ports [TARGET]          normalized port inventory
tacmux ports add [TARGET]      ingest Nmap normal output
tacmux todo [add|done|reopen]  planned and completed work
tacmux cleanup [add|done|reopen]
tacmux discover               reviewed host identification
```

Missing values open short prompts or an `fzf` picker. Inline commands infer the engagement and target from the current directory or tmux session.

## Workspace

```text
~/workspace/ACME/
├── .tacmux/
├── SITREP.md                 # file or validated external-notes link
├── targets.txt               # generated endpoint list when requested
├── credentials/
│   ├── keys/
│   ├── creds.txt
│   ├── users.txt
│   ├── passwords.txt
│   └── hashes.txt
├── captures/
│   ├── .nocap/
│   ├── ops/
│   └── WEB01/
├── logs/YYYYMMDD/
└── targets/
    └── WEB01/
        ├── scans/
        ├── payloads/
        ├── loot/
        ├── screenshots/
        └── working/
```

`SITREP.md` keeps current state first—Targets, Credentials, TODO, and Cleanup—then a chronological Operations Log. TODO and Cleanup use native Markdown checkboxes, so an item checked in Obsidian or `$EDITOR` is immediately understood by TACMUX. Log entry prose remains operator-editable between its markers.

Target headings are inventory identities rather than display-only labels. Use `tm target rename OLD NEW`; if a heading was changed manually first, the same command safely completes an unambiguous rename while `tm sitrep sync` refuses to create duplicate target sections.

The Operations Log replaces separate note, activity, and attack-path systems:

```bash
tm log "SMB signing is disabled"                    # info
tm log failed "Recovered password was rejected"
tm log partial "Relay reached LDAP but no write"
tm done "Obtained shell as svc_web"                 # success
tm done -c "Established the approved internal pivot" # attach latest NOCAP capture
tm done -c -i proof.png "Obtained domain access"      # capture plus screenshot
tm log                                                 # interactive
tm log edit                                            # jump to Operations Log
```

Capture-assisted entries include evidence and command details, an editable screenshot caption, Draft findings, and Notes. When `-i` is omitted, the entry explicitly says that no screenshot is attached instead of implying that evidence exists.

Use `tm done --capture-id ID "Completed step"` to attach an earlier capture from
the same target route, `tm log edit E001` to update that event, and
`tm creds view C001` to display a full credential without table truncation.
NOCAP's latest capture is engagement-wide in TACMUX sessions; check `cap timeline`
after switching hosts and use the intended ID. Displaying credentials can put
secrets into pane logs even when their original entry used a hidden prompt.

To keep the canonical SITREP in any external Markdown notes directory, set one optional path:

```toml
[paths]
workspace = "~/workspace"
sitrep_root = "~/notes/engagements"
```

New engagements then store the physical note at `<sitrep_root>/<engagement>/SITREP.md` and expose it through the usual workspace path. There is no Obsidian API or synchronization process; TACMUX, Obsidian, and `$EDITOR` operate on the same file. Because the SITREP can contain raw secrets, use only an approved protected notes location.

See the [operator guide](docs/USAGE.md), [keybindings](docs/KEYBINDINGS.md), and [security policy](SECURITY.md).

## Deliberate boundaries

TACMUX does not enforce scope or authorization windows, maintain a formal findings or attack-path registry, generate reports, create engagement archives, exploit targets, or call AI. Draft findings and the demonstrated sequence belong in the Operations Log; use the client RoE and reporting platform for formal assessment management.

TACMUX stores raw credential material when you ask it to. Treat the entire engagement directory as sensitive evidence. Shared folders and cloud-synced paths may not enforce Unix permissions.
Back up the workspace and, when using `sitrep_root`, the physical note and its sibling `images/` directory. A backup containing only the workspace symlink is incomplete.

## Remove

```bash
./uninstall.sh
```

Configuration and engagement workspaces are preserved.

## License

[MIT](LICENSE)
