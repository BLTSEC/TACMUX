# TACMUX

<p align="center">
  <img src="assets/TACMUX.jpg" alt="TACMUX — tactical engagement workspaces for tmux" width="100%">
</p>

<p align="center">
  <a href="https://github.com/BLTSEC/TACMUX/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/BLTSEC/TACMUX/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/BLTSEC/TACMUX/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/BLTSEC/TACMUX"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-2ea44f"></a>
</p>

TACMUX is a terminal cockpit for authorized penetration tests and red-team
engagements. It keeps scope, targets, tmux sessions, records, evidence, and the
current situation in one private workspace.

<p align="center">
  <img src="assets/tacmux-v2-tour.gif" alt="BLTSEC-themed TACMUX tour using the synthetic Northstar engagement" width="100%">
</p>

The recording uses only the repository's public synthetic fixture.

> Use TACMUX only with explicit authorization. Confirm scope, rules of
> engagement, logging, evidence handling, and retention before testing.

## Cockpit

Run `tacmux` and work from five views:

| Key | View | Purpose |
|---|---|---|
| `1` | Targets | Identity, addresses, services, access, sessions, and target actions |
| `2` | Scope | Networks, domains, exclusions, pivots, and discovery jobs |
| `3` | Records | Access, activity, findings, attack paths, and cleanup |
| `4` | Situation | Authorization, topology, and confirmed attack paths |
| `5` | Documents | Notes, SITREP, findings, exports, logs, and evidence |

Press `a` for actions, `Enter` for the selected item's default action, `/` to
filter, `?` for keys, or `Ctrl+P` for command search. Prefix + `E` opens the
cockpit from tmux.

## Requirements

- Linux, Python 3.11.4+, tmux 3.2+, and [uv](https://docs.astral.sh/uv/)
- A Nerd Font-enabled terminal and a terminal editor
- Optional: Nmap for discovery jobs and `cap` for NOCAP timelines

## Install

```bash
git clone --branch v2.5.1 --depth 1 https://github.com/BLTSEC/TACMUX.git
cd TACMUX
./install.sh
exec "$SHELL" -l
tacmux health
```

The installer keeps its files under `~/.local/share/tacmux`, links the command
into `~/.local/bin`, and preserves configured workspace paths during upgrades.
Use `./install.sh --workspace /approved/evidence` to select the workspace on a
first install. `--full-tmux` installs the complete tmux configuration;
`--skip-tmux` leaves tmux unchanged. Remove it with `./uninstall.sh`, which
preserves configuration, archives, and workspaces.

To rebuild the tour above, see [`scripts/demo/README.md`](scripts/demo/README.md).

## Safety

- New data is owner-only by default: `0700` directories and `0600` files.
- Scope exclusions apply to validation, import review, and TACMUX-launched Nmap.
- Exports are not redacted and archives are not exports. Review a handoff before
  sharing it, and use [DECON](https://bltsec.com/blog/decon/) when a derived copy
  must be sanitized.

## Learn it

- [Field guide](https://bltsec.com/blog/tacmux/) — one engagement end to end
- [Operator guide](docs/USAGE.md) — forms, discovery, records, exports, archives
- [Keybindings](docs/KEYBINDINGS.md) — cockpit and tmux keys
- [Security policy](SECURITY.md) — trust boundaries and vulnerability reporting

## License

[MIT](LICENSE)
