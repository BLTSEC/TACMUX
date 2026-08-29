# TACMUX

<p align="center">
  <img src="assets/TACMUX.jpg" alt="TACMUX — tactical engagement workspaces for tmux" width="100%">
</p>

<p align="center">
  <a href="https://github.com/BLTSEC/TACMUX/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/BLTSEC/TACMUX/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/BLTSEC/TACMUX/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/BLTSEC/TACMUX"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-2ea44f"></a>
</p>

TACMUX is a terminal cockpit for authorized penetration tests and red-team engagements. It keeps declared scope, identified hosts, tmux sessions, curated activity, findings, attack paths, evidence, and a current situation report in one private engagement workspace.

Run `tacmux`, choose the engagement and target, and work from menus. The public CLI intentionally has almost no flag surface.

> Use TACMUX only where you have explicit authorization. Confirm scope, rules of engagement, logging, evidence handling, and retention before testing.

## v2 design

- Python 3.11+ and Textual for a responsive terminal UI.
- One readable JSON manifest per engagement.
- Human-facing **Client or Lab** and **Engagement Name** fields instead of provider/slug terminology.
- External and internal scope groups, including IPs, CIDRs, unavailable internal networks, pivot relationships, dual-homed systems, and overlapping addresses qualified by scope.
- Stable target IDs and directories. Renaming a display name never moves evidence.
- Detached target, operations, and discovery sessions with engagement-wide stop controls.
- Fixed host-identification scans using `nmap -sn --reason -oX`, followed by mandatory Add/Merge/Ignore review.
- Terminal-native topology and confirmed attack-path views. Optional Mermaid source is generated in `SITREP.md`.
- Markdown preview in the TUI and editing through `$VISUAL`, `$EDITOR`, or `vi`.
- Optional, read-only NOCAP timeline integration. NOCAP remains a separate tool.

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

If `~/.tmux.conf` exists, the default installer adds only the TACMUX integration fragment. Otherwise it installs the optional complete configuration. Prefix + `E` opens TACMUX in a tmux popup.

## First engagement

```bash
tacmux
```

1. Press `n` and enter the client/lab, engagement name, assessment type, and any scope known before testing.
2. Open **Scope & Discovery** to add or update scope. Internal scope may begin unavailable and later become ready through a selected pivot target.
3. Press `d` to run detached host identification or import existing Nmap XML/pasted hosts.
4. Review every result as **Add**, **Merge**, or **Ignore**. Detached target sessions are created by default for accepted hosts.
5. Select a target and press Enter to attach. Press `a` for target work or to manage structured records.
6. Use **Situation** for the network topology and separately curated, confirmed attack paths.
7. Use **Documents** to preview Markdown, ANSI logs, and evidence. Enter opens editable Markdown in your editor; generated documents remain read-only.

The command palette provides fuzzy access to the same actions without an fzf dependency.

## Workspace

```text
~/workspace/E-<stable-id>-<name>/
├── .tacmux/
│   ├── engagement.json
│   └── jobs/
├── ENGAGEMENT.md
├── SITREP.md
├── findings/
├── notes/
│   ├── activity.md
│   ├── attack-path.md
│   └── payloads.md
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

`ENGAGEMENT.md`, target notes, payload notes, and finding narratives are operator-edited. `SITREP.md`, activity, and attack-path Markdown are regenerated from structured records.

## Minimal CLI

```text
tacmux                         Open the cockpit
tacmux health                  Check configuration and tools
tacmux archive verify FILE     Verify the archive and every file hash
tacmux version                 Print the version
```

Fast logging, clipboard, and status commands used by tmux live behind a private `_internal` interface; they are not an operator workflow to memorize.

## Configuration

Edit `~/.config/tacmux/config.toml`:

```toml
[paths]
workspace = "~/workspace"
archive_dir = "~/archives"
log_dir = "~/logs"

[behavior]
auto_log = true
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
- Host discovery never guesses across ambiguous overlapping scope entries.

See the [operator guide](docs/USAGE.md), [keybindings](docs/KEYBINDINGS.md), and [security policy](SECURITY.md).

## Remove

```bash
./uninstall.sh
```

Only the marked installation and its matching command link are removed. Configuration, archives, workspace evidence, unrelated commands, and malformed configuration blocks are preserved.

## License

[MIT](LICENSE)
