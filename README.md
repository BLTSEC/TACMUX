# TACMUX

<p align="center">
  <img src="assets/TACMUX.jpg" alt="TACMUX — tactical engagement workspaces for tmux" width="100%">
</p>

<p align="center">
  <a href="https://github.com/BLTSEC/TACMUX/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/BLTSEC/TACMUX/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/BLTSEC/TACMUX/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/BLTSEC/TACMUX"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-2ea44f"></a>
</p>

TACMUX is a terminal cockpit for authorized penetration tests and red-team engagements. It keeps authorization, declared scope, targets, services, tmux sessions, activity, findings, attack paths, cleanup obligations, evidence, and a current situation report in one private engagement workspace.

Run `tacmux`, choose the engagement and target, and work from menus. The public CLI intentionally has almost no flag surface.

> Use TACMUX only where you have explicit authorization. Confirm scope, rules of engagement, logging, evidence handling, and retention before testing.

## What TACMUX does

- Provides a keyboard-driven Textual cockpit with a persistent choice of curated themes.
- Keeps authorization, lifecycle, scope, exclusions, pivots, and overlapping network identities in one readable engagement manifest.
- Gives engagements and targets stable IDs so renaming never moves evidence or changes session identity.
- Runs detached target, operations, and scope-constrained Nmap discovery sessions with engagement-wide stop controls.
- Reconciles every discovered host through Add/Merge/Ignore review and retains XML provenance for observed services.
- Records activity, access, findings, cleanup, and confirmed attack paths without treating authentication as compromise.
- Renders terminal topology, SITREP, Markdown and log previews, pager/editor handoff, and compact or evidence-rich single-file exports.
- Creates hash-verified archives and optionally reads NOCAP timelines without merging the two tools.

TACMUX does not require fzf, AutoRecon, Obsidian, or shell completions.

## Requirements

- Linux
- Python 3.11 or newer
- tmux 3.2 or newer
- [uv](https://docs.astral.sh/uv/) for installation
- An editor (`$VISUAL`, then `$EDITOR`, then `vi`)
- Optional: Nmap for launching discovery jobs; existing XML and pasted-host import work without it
- Optional: `cap` when NOCAP integration is enabled

## Install

```bash
git clone https://github.com/BLTSEC/TACMUX.git
cd TACMUX
./install.sh
exec "$SHELL" -l
tacmux health
```

The installer uses the committed `uv.lock`, installs under `~/.local/share/tacmux`, and links `tacmux` into `~/.local/bin`. Upgrades preserve configuration and evidence and refuse an unmarked install directory or malformed TACMUX configuration block.

Useful modes:

```bash
./install.sh --workspace /approved/evidence
./install.sh --full-tmux
./install.sh --skip-tmux
```

On the first install, an existing `~/.tmux.conf` receives only the TACMUX
integration fragment; without one, TACMUX installs its complete configuration.
Reinstalls preserve the TACMUX-managed mode instead of changing it merely
because `~/.tmux.conf` now exists. Prefix + `E` opens TACMUX in a tmux popup.

## First engagement

```bash
tacmux
```

1. Press `n` and enter the client/lab, engagement name, assessment type, and any scope known before testing.
2. Open **Scope** to add or update network/domain scope and exclusions. Internal scope may begin unavailable and later become ready through a selected pivot target.
3. Press `d` to run detached host-only or TCP-service discovery, or import existing Nmap XML/pasted hosts or hostnames.
4. Review every result as **Add**, **Merge**, or **Ignore**. Detached target sessions are created by default for accepted hosts.
5. Select a target and press Enter to attach. Press `a` for target actions.
6. Use **Records** for access, activity, findings, attack paths, and cleanup. Use **Situation** for terminal-readable topology and confirmed attack paths.
7. Use **Documents** to preview Markdown, terminal logs, and evidence. Enter edits
   editable Markdown or pages a read-only text file; `a` offers explicit View/Edit
   actions. Generated documents remain read-only.

The `Ctrl+P` Command Palette provides fuzzy command search without an fzf
dependency. Press `a` for the shorter contextual Actions menu, including
engagement open/archive/delete choices from the picker.
Press `t` from the cockpit or engagement picker to choose BLTSEC, Textual Dark,
Nord, Dracula, Catppuccin Mocha, Tokyo Night, Gruvbox, Rose Pine Moon, or
Solarized Dark. The choice applies only to TACMUX and is remembered across launches.

## Workspace

```text
~/workspace/E-<stable-id>-<name>/
├── .tacmux/
│   ├── engagement.json
│   ├── imports/
│   └── jobs/
├── ENGAGEMENT.md
├── SITREP.md
├── findings/
├── exports/
├── notes/
│   ├── activity.md
│   └── attack-path.md
└── targets/
    └── T0001-<initial-name>/
        ├── NOTES.md
        ├── recon/
        ├── exploitation/
        ├── loot/
        ├── screenshots/
        ├── reports/
        └── logs/YYYYMMDD/
```

`ENGAGEMENT.md`, target notes, and finding narratives are operator-edited. `SITREP.md`, activity, and attack-path Markdown are regenerated from structured records. Existing legacy `payloads.md` files remain visible; new cleanup entries live in the manifest and Records tab.

## Minimal CLI

```text
tacmux                         Open the cockpit
tacmux health                  Check configuration and tools
tacmux note TEXT...            Append a note in the current target/ops session
tacmux activity RESULT [--evidence PATH] TEXT...
                               Record activity in the current session
tacmux sitrep                  Print the current engagement SITREP
tacmux export [compact|evidence]
                               Create a single-file Markdown handoff
tacmux clip                    Copy stdin through the trusted clipboard path
tacmux archive verify FILE     Verify the archive and every file hash
tacmux version                 Print the version
```

`tacmux clip` is useful over SSH when ordinary clipboard tools are unavailable.
Fast logging and status hooks used by tmux remain behind a private `_internal`
interface; they are not an operator workflow to memorize.

## Configuration

Edit `~/.config/tacmux/config.toml`:

```toml
[paths]
workspace = "~/workspace"
archive_dir = "~/archives"
log_dir = "~/logs"

[behavior]
auto_log = true
log_outside_tacmux = false     # automatic hooks stay in TACMUX sessions
startup = "resume_last"       # or "picker"
include_mermaid = true

[nocap]
enabled = false
```

No Markdown is moved or symlinked into another application. Set `$VISUAL` or `$EDITOR` to any terminal editor you prefer.

## Safety boundaries

- New TACMUX data is owner-only by default (`0700` directories, `0600` files).
- Archives have a JSON sidecar with the tarball SHA-256 and every regular member hash. Restore is staged and rejects collisions, unsafe paths, unsafe links, invalid engagement manifests, and mismatched metadata.
- Archiving creates a verified copy; it does not silently delete the live workspace.
- Permanent target deletion is only for mistaken targets. It requires exact typed confirmation, refuses running sessions, and refuses structured references. The Records workflow can correct or remove mistaken records first.
- Attack paths accept only confirmed activity, confirmed/closed findings, and recorded access. **Authenticated** is deliberately distinct from command execution or privilege.
- Access metadata that resembles credential material triggers a warning before it is saved; TACMUX does not reject or rewrite authorized evidence.
- Exclusions are enforced by validation, import review, and Nmap `--exclude`. Overlapping scope entries must be discovered in separate jobs.
- Hostname-only targets must match declared domain scope when domain entries exist. `*.acme.test` excludes the apex; declare `acme.test` separately.
- Starting sessions or discovery outside a configured authorization window requires confirmation. Closed engagements block operational changes until reopened.
- Automatic logging is limited to TACMUX-owned tmux sessions unless explicitly widened in config.

See the [operator guide](docs/USAGE.md), [keybindings](docs/KEYBINDINGS.md), and [security policy](SECURITY.md).

## Remove

```bash
./uninstall.sh
```

Only the marked installation and its matching command link are removed. Configuration, archives, workspace evidence, unrelated commands, and malformed configuration blocks are preserved.

## License

[MIT](LICENSE)
