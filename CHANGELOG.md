# Changelog

## Unreleased

## 3.1.0 — 2026-11-03

### Upgrade notes

Behavior that differs from 3.0. No command was removed; every 3.0 command and
direct form still works.

- Bare `tm` inside a TACMUX session opens the action palette instead of the
  switcher. Sessions are listed in the palette, and `tm switch` and Prefix+`E`
  still open the switcher directly. Outside TACMUX sessions bare `tm` is
  unchanged.
- Prefix+`M` now opens the palette, replacing tmux's default "clear marked
  pane" binding.
- Interactive `tm log` in a target session records to that target without the
  "Record for>" prompt; the operations session still asks.
- Arguments starting with `-` that are not options of that command are refused
  (for example `tm todo add --x`); put `--` before such text.
- `tm log s|p|f TEXT` treats the first word as the outcome success, partial,
  or failed; 3.0 recorded it as text.
- Without a terminal (pipes, scripts, agents) or with
  `TACMUX_NONINTERACTIVE=1`, TACMUX no longer reads prompt answers from stdin,
  opens fzf, or launches an editor; it fails and names the missing argument.
  Target deletion requires an interactive exact-name confirmation.
- An interactive `tm creds add` ends with "Works somewhere now? [Y/n]"; answer
  `n` to keep the 3.0 behavior.
- `tm creds confirm` from the operations session without a target opens a
  multi-select target picker instead of a single choice.
- Starting a session for a `new` target sets its Status to `active` (written
  to SITREP, folded into the latest undo step).
- SITREP changes also write an undo journal under `.tacmux/undo/` (25 entries,
  owner-only; it holds earlier SITREP copies, including credentials).
- The status-line segment shows Access: `[WEB01 · user · LOG]` instead of
  `[WEB01 LOG]`.
- `tacmux clip` is no longer listed in usage or completion; it still works.

### Added

- Action palette: bare `tm` inside a TACMUX session, `tm menu` anywhere, and
  Prefix+`M` as a popup. One fuzzy list holds plain-English actions (failed,
  step worked, found credential, credential works, TODO, cleanup, Nmap import,
  hostname, field edits, log edits, undo, status) and every session, with a
  preview showing the equivalent direct command. The popup binding passes the
  invoking pane, client, and directory shell-quoted, so directory names are
  never executed.
- `tm undo` reverts the most recent TACMUX change to SITREP from a 25-entry
  journal. It refuses when SITREP changed outside TACMUX afterwards, masks
  credential rows in its preview, and applies only the entry it previewed
  (a concurrent change refuses instead). Target add/rename/delete start a new
  undo history because directory changes cannot be undone; later SITREP-only
  changes remain undoable. A failed commit leaves no journal entry. `--yes`
  serves scripts and agents.
- `tm fail TEXT` for dead ends and `tm history --outcome OUTCOME` filtering.
- Per-command help: `tm COMMAND --help`, `tm COMMAND help`, and
  `tm help COMMAND` print forms, accepted words, and examples without touching
  SITREP.
- Non-interactive mode: with no terminal, or `TACMUX_NONINTERACTIVE=1`,
  TACMUX never prompts, opens fzf, or launches an editor and names the missing
  argument instead. Target deletion always requires an interactive exact-name
  confirmation; piped input cannot authorize it.
- Credential confirmation across several targets at once, with the service
  chosen from the targets' Ports table (`445`, `tcp:8000`, or a picker), and an
  optional "Works somewhere now?" step after an interactive `creds add`.
- The status-line segment shows the target's Access (`[WEB01 · user · LOG]`,
  `none` highlighted) using an mtime-keyed cache rather than parsing SITREP on
  every refresh.

### Changed

- Every positional argument may be omitted and is asked for, e.g.
  `tm target update access` opens the Access picker for the current target.
- Vocabulary words accept unique prefixes and aliases (`acc`, `st`, `as`,
  `via`; `root`→admin, `shell`→user, `auth`→authenticated; outcomes `f`/`p`/`s`
  as the first word of `tm log`). Ambiguous words open a pre-filtered picker.
- Inside a target session, log entries belong to that target without asking;
  the operations session still asks, defaulting to the most recently used
  target.
- Text prompts support line editing; editable values are prefilled in place.
- Starting a session for a `new` target marks it `active`. This bookkeeping is
  folded into the latest undo step rather than becoming one, so `tm undo` still
  reverts the operator's last change.
- Usage text leads with the palette and groups commands by purpose.

### Fixed

- `tm log --help` and other help requests no longer become Operations Log
  entries; unknown options such as a mistyped `-x` are refused, and `--`
  records literal text that starts with a dash.
- Installer tests no longer read the host's XDG or TACMUX configuration.

## 3.0.0 — 2026-09-05

### Added

- Full credential detail with `tm creds view ID`, direct event editing with
  `tm log edit ID`, and earlier capture selection with `--capture-id ID`.
- Optional external Markdown storage for the canonical SITREP, with a validated
  workspace link and no editor-specific dependency or synchronization service.
- Capture- and screenshot-assisted Operations Log entries through `tm done` and
  `tm log`, including evidence metadata, editable captions, and draft-finding
  space.
- Native Markdown TODO and Cleanup checklists with completion and reopen helpers.
- Owner-only `credentials/keys/` storage for engagement SSH keys, including
  automatic repair for existing v3 engagement layouts.
- Native Zsh completion for `tacmux` and the recommended `tm` alias, with
  contextual engagement, target, record-ID, status, and file suggestions.
- Interactive and direct `target update` helpers for durable target details.
- Endpoint-only `targets.txt` generation with All, None, and fzf multi-select
  modes for direct use by assessment tools.

### Changed

- Current state now leads into one chronological Operations Log; the former
  Narrative and separate Completed tables no longer split the walkthrough.
- Credentials now keep confirmed target, service, access, and timestamp on the
  credential row instead of maintaining a separate check ledger.
- Auto-log hooks are session-local and are repaired whenever a TACMUX session
  is opened, covering new windows and splits without touching unrelated tmux
  sessions.

### Fixed

- Credential-export failures no longer undo target or image changes after the
  corresponding SITREP update has committed.
- Manual table edits preserve literal domain and password backslashes.
- Single-target port imports reject multi-host or mismatched Nmap reports.
- Damaged notes are reported without blocking unrelated sessions, and health
  includes marked engagements with missing or invalid SITREP links.
- Unchanged credential files are no longer rewritten after unrelated actions.
- Release automation validates the complete main-branch tree before publishing.
- Managed tables, checklists, and Operations Log events now have blank lines
  inside their TACMUX markers so Obsidian recognizes the enclosed Markdown.
- Screenshot links retain literal filenames inside angle brackets so Obsidian
  resolves images whose names contain spaces or `@` characters.
- Zsh completion initialization ignores insecure third-party completion paths
  instead of prompting or aborting during non-interactive shell startup.
- Manual target-heading changes are detected before SITREP repair; an

unambiguous change can be completed through the normal target rename command.

### Changed

- Rebuilt TACMUX around tmux, fzf, `$EDITOR`, target directories, and one
  operator-editable `SITREP.md`; Textual and the engagement-management model
  are no longer part of the runtime.
- Engagements now use human-readable parent and target directories, central
  pane logs, engagement-wide NOCAP captures, and full per-target working trees.
- Narrative, notes, and completed operational steps are one lightweight
  timeline driven by `tacmux log`, `tacmux done`, and `tacmux history`.

### Added

- Focused helpers for credentials and hashes, credential checks, normalized
  Nmap port ingestion, TODO/Completed work, cleanup obligations, target status,
  guarded target deletion, and foreground reviewed host identification.
- A unified fzf switcher that starts stopped target/operations sessions and
  switches to live ones from inside or outside tmux.

### Removed

- Scope, authorization windows, lifecycle state, findings, attack paths,
  archives, exports, detached discovery jobs, themes, and legacy imports.

- TACMUX's complete tmux preset; v3 ships integration bindings only.

### Added

- Refreshed the banner with real TACMUX CLI commands and synthetic documentation-only targets.

## 2.5.1 — 2026-09-01

### Added

- A reproducible cockpit tour: a VHS tape and renderer build the animated tour
  and the Targets still from the repository's public synthetic fixture, so the
  README shows the current interface without any engagement data.

### Changed

- The operator guide calls the cockpit's five surfaces views, matching the
  release notes and the downstream operator documentation.

## 2.5.0 — 2026-09-01

### Changed

- Single-file exports now use purpose-led Handoff and Full context profiles,
  render authored Markdown inline without duplicating SITREP tables, and place
  exact manifest JSON before any evidence excerpts.
- Full-context exports prioritize cited evidence, normalize the local engagement
  root, report evidence coverage, and limit excerpts to 128 KiB per file and
  1 MiB total. The former profile names remain accepted as CLI aliases.

## 2.4.1 — 2026-08-31

### Changed

- Engagement creation can front-load authorization metadata and optional UTC
  testing windows alongside known scope.
- New findings default to Draft so an incomplete narrative is never presented
  as confirmed by the creation form.
- The offline external-to-internal acceptance example is now independently
  synthetic and uses new reserved-address identities and narratives.

### Fixed

- Generated documents, manifest updates, discovery artifacts, deletion staging,
  evidence inspection, and handoff exports consistently refuse linked parent
  paths that leave the engagement boundary.
- All persisted engagement, target, service, activity, access, finding,
  attack-path, and cleanup timestamps are validated when present.
- Evidence paths containing Markdown table delimiters no longer corrupt
  generated activity or SITREP tables.

## 2.4.0 — 2026-08-31

### Added

- Recent-first Records with a visible kind filter, creation timestamps for
  findings and attack paths, Scope/Jobs search, contextual empty states, and
  trusted copy actions for target endpoints and document paths.
- Invalid engagement workspaces remain visible in the picker with diagnostics
  while open, archive, and deletion actions stay unavailable.
- Ruff linting for Python source and tests in CI.
- Cockpit access to engagement authorization details and selected-step notes in
  the attack-path builder.

### Changed

- Repeated pasted addresses retain all unique hostnames, and later service
  observations no longer erase richer existing product or version details with
  blank fields.
- The picker and cockpit now live in focused screen modules while the Textual
  application entry point remains a small application shell.
- Records use bounded display columns, evidence references are prioritized
  deterministically, and authorization-window banner text describes partial
  windows explicitly.

### Fixed

- Data-entry and discovery dialogs remain keyboard-scrollable at 80x24.
- Unsafe linked documents no longer crash Documents or escape engagement
  editor/pager containment, and pane-provided log directories cannot leave the
  configured workspace.

## 2.3.0 — 2026-08-31

### Added

- In-cockpit keyboard reference, keyboard-scrollable read panes, readable job
  scope/profile labels, job-log paging, and originating-target selection.
- Regression coverage for mixed IPv4/IPv6 discovery, closed lifecycle guards,
  literal operator text, refresh selection, contextual tmux identity, and
  installer ownership.

### Changed

- Closed engagements are review-only until explicitly reopened.
- Discovery job JSON is portable and contains neither executable command lines
  nor TACMUX-generated absolute paths. Commands remain rebuilt from current
  ready scope at execution time.
- Discovery imports accepting more than ten targets default detached-session
  creation off.
- Generated Markdown is written only when its content changes, and cockpit
  refreshes retain the highlighted object.
- Reinstalls honor configured data paths, preserve skip-tmux mode, and refuse
  unrelated command links before replacing the application; ignored developer
  bytecode is excluded from the staged install.
- The Python requirement is now 3.11.4 or newer.

### Fixed

- Mixed IPv4/IPv6 scope handling is explicitly family-safe, and authored files
  referenced as evidence no longer collide in the Documents table.
- Submitting a cockpit filter no longer opens or attaches the highlighted row.
- Operator strings containing Rich markup characters remain literal.
- Editor suspension failures, target cleanup failures, and invalid CLI activity
  results now surface as operator-facing errors.
- Contextual CLI commands reject stale inherited session identity.

### Removed

- The obsolete workspace import and migration surface.

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
- Full tmux installs retain the complete operator keymap, including logging shortcuts,
  and reinstalling preserves the previously selected tmux mode.
- Critical lifecycle state now leads the cockpit banner, narrow footer labels are
  shorter, and closed engagements hide active-only shortcuts and commands.

### Fixed

- Enhanced discovery job specifications no longer advertise a nonexistent
  single `results.xml` artifact.

## 2.0.0 — 2026-08-31

TACMUX v2 replaces the original Zsh command suite with a Python/Textual operator
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
- The TUI and contextual action menus replace the original flag-heavy and fzf flows;
  fzf is no longer required.
- Automatic pane logging is limited to TACMUX-owned sessions by default.
- Markdown stays in the engagement workspace and opens through `$VISUAL`,
  `$EDITOR`, or `vi`; there is no Obsidian integration.

### Removed

- AutoRecon integration, shell completions, and the original Zsh core.
- The former `logview` and `logrender` commands. v2 provides cleaned previews and
  full-file pager handoff inside the Documents tab.
- Course or academy lesson management. Training exercises remain ordinary,
  separate engagements.
