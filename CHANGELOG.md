# Changelog

## 2.2.0 — 2026-08-31

### Added

- A complete, contrast-checked BLTSEC operator palette and Nerd Font navigation
  and lifecycle symbols paired with text labels.

### Changed

- The engagement picker, cockpit banner, tabs, tables, split panes, forms,
  modals, and footer now share a responsive BLTSEC-inspired visual system.
- Critical lifecycle and authorization state occupies a dedicated banner line
  so it remains visible at the 80-column minimum.

## 2.1.0 — 2026-08-31

### Added

- Compact and evidence-rich single-file Markdown handoffs for report drafting,
  human transfer, or use in an external notes system.
- Opt-in detached full-TCP discovery followed by `-sV` only for ports found
  open, with careful/fast pacing, IPv4/IPv6 separation, and partial-result import.

### Changed

- Manifest commits and generated Markdown rendering now happen once per operator
  action, with only affected cockpit panes refreshed afterward.
- Structured access fields warn on likely credential material without blocking
  authorized evidence capture.
- Full tmux installs retain the v1 operator keymap, including logging shortcuts,
  and reinstalling preserves the previously selected tmux mode.
- Critical lifecycle state now leads the cockpit banner, narrow footer labels are
  shorter, and closed engagements hide active-only shortcuts and commands.

### Fixed

- Enhanced discovery job specifications no longer advertise a nonexistent
  single `results.xml` artifact.

## 2.0.0 — 2026-08-31

TACMUX v2 replaces the v1 Zsh command suite with a Python/Textual operator
cockpit. It is a deliberate workflow reset, not an in-place manifest upgrade.

### Added

- Keyboard-driven engagement picker and five-tab cockpit for targets, scope,
  records, situation, and documents.
- Stable engagement and target identities independent of display names,
  directories, addresses, and tmux session names.
- Network and domain scope, per-entry exclusions, pivot relationships, and
  guarded Add/Merge/Ignore discovery reconciliation.
- Authorization windows, active/closed lifecycle, cleanup ledger, structured
  access/activity/findings, and confirmed attack paths.
- Detached target, operations, and fixed-profile Nmap discovery sessions.
- Import-only observed service inventory with retained XML provenance.
- Terminal topology, generated SITREP, evidence preview/paging, and verified
  target or engagement archives with guarded restore and deletion.
- In-pane `note`, `activity`, `sitrep`, and trusted `clip` commands.
- A dedicated BLTSEC cockpit theme.
- Optional read-only NOCAP timeline integration.

### Changed

- Installation uses `uv` and Python 3.11 or newer.
- The TUI and contextual action menus replace v1's flag-heavy and fzf flows;
  fzf is no longer required.
- Automatic pane logging is limited to TACMUX-owned sessions by default.
- Markdown stays in the engagement workspace and opens through `$VISUAL`,
  `$EDITOR`, or `vi`; there is no Obsidian integration.

### Removed

- AutoRecon integration, shell completions, and the v1 Zsh core.
- The v1 `logview` and `logrender` commands. v2 provides cleaned previews and
  full-file pager handoff inside the Documents tab.
- Course or academy lesson management. Training exercises remain ordinary,
  separate engagements.

### Migration

Use **Import v1 workspace** from the engagement picker. Import is copy-only and
preserves the original workspace. Review imported targets and add structured
scope and records manually; TACMUX does not infer security facts from notes.
