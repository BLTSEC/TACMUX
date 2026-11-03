# TACMUX operator guide

## Operating model

An engagement is an ordinary parent directory marked by `.tacmux/version`. Its target directories define inventory and its single `SITREP.md` holds operational state. TACMUX does not create hidden target records or maintain a second database.

Use one engagement for one authorized body of work. Keep unrelated client, lab, and training activity in separate parents.

## Action palette

Inside any TACMUX session, bare `tm` (or Prefix+`M` as a popup, or `tm menu`
anywhere) opens one fuzzy list of actions and sessions. Type a few letters and
press Enter. The header shows the current target, endpoint, Access, and Status;
the preview shows what the action does and its direct command.

| Palette entry | Direct command |
|---|---|
| ✗ Failed / dead end | `tm fail "summary"` |
| ✓ Step worked | `tm done "summary"` · `tm done -s "summary"` (screenshot) |
| ★ Got access | `tm access [LEVEL] [PRINCIPAL] [HOW…] [--via S] [--cred CID]` |
| ⚑ Proof / flag | `tm proof [user\|root] [VALUE] [PATH]` (alias `tm flag`) |
| 📎 Attach latest capture | `tm done -c "…"` · `tm done --capture-id ID "…"` |
| 📷 Screenshot → entry | `tm done -s "…"` · `tm done -i proof.png "…"` |
| • Note (choose outcome) | `tm log [info\|partial\|success\|failed] "summary"` |
| 🔑 Found credential | `tm creds add [password\|hash] [USER:SECRET]` |
| 🔑 Credential works | `tm creds confirm [ID] [TARGET…] [ACCESS] [SERVICE]` |
| ☐ / ☑ TODO | `tm todo add "task"` · `tm todo done [ID]` |
| 🧹 Cleanup | `tm cleanup add "item"` · `tm cleanup done [ID]` |
| ⇣ Import Nmap output | `tm ports add [TARGET] FILE` (picker of files in the target folder) |
| 🏷 Add hostname / vhost (the palette also copies the `/etc/hosts` line) | `tm target update hostnames "a.example b.example"` |
| ✎ Edit a target field | `tm target update [TARGET] [FIELD] [VALUE]` |
| ✎ Edit a log entry | `tm log edit [EVENT_ID]` |
| ↶ Undo last change | `tm undo` |
| ⓘ Status · History · SITREP · Context | `tm status` · `tm history` · `tm sitrep` · `tm sitrep context` |
| ➕ Add target · 🔎 Discover hosts | `tm target add NAME IP` · `tm discover` |
| 📸 Snapshot panes now | `tm snap [TARGET]` |
| ⏹ Close out | `tm close [TARGET\|--engagement] [--yes] [--no-stop]` |
| ⇄ Session entries | `tm switch` (Prefix+`E`) |

Outside TACMUX sessions, bare `tm` still opens the switcher.

### Prompts, shortcuts, and help

- Every argument shown in brackets may be omitted; TACMUX asks only for what is
  missing. Inside a target session the target is implied.
- Fixed words accept unique prefixes and aliases: fields `acc`, `st`, `as`
  (principal), `via` (method), `host`; access `auth`, `shell`, `root` (admin),
  `dom`; status `done` (complete); outcomes `f`, `p`, `s` as the first word of
  `tm log`. An ambiguous word such as `a` opens a picker filtered by it.
- `tm COMMAND --help`, `tm COMMAND help`, and `tm help COMMAND` print forms,
  accepted words, and examples. Help never writes to SITREP; unknown options
  are refused, and `--` logs text that begins with a dash.
- With no terminal (pipes, scripts, agents) or `TACMUX_NONINTERACTIVE=1`,
  TACMUX never prompts, opens fzf, or launches an editor. It fails and names
  the missing argument. Target deletion always requires an interactive,
  exact-name confirmation; piped input cannot authorize it.
- `tm undo` reverts the most recent TACMUX change to SITREP (25 are kept under
  `.tacmux/undo/`). It refuses after SITREP was edited elsewhere, so manual
  Obsidian or `$EDITOR` work is never overwritten. `tm undo --yes` skips the
  confirmation for scripts. A concurrent TACMUX change during confirmation
  also refuses undo; run it again to preview the latest change. Target
  add/rename/delete start a new undo history because document-only undo
  cannot safely reverse directory changes. Subsequent SITREP-only changes
  remain undoable; undo never deletes evidence or recreates deleted targets.

## Access, proof, and evidence

`tm access` records the access you gained as one undoable step: a success
entry, the target's Access/Principal/Method raised (never lowered), and
optionally the credential that was used. The credential's own access defaults
to `authenticated` (a web login that enabled an exploit); write `--cred C001:user`
when the credential itself gave the shell, such as an SSH login.

```bash
tm access user app "CVE-2021-43857 RCE" --via "http :8000" --cred C001
tm access root root "python3.10 cap_setuid"
tm access                      # pickers: level, principal, via (Ports), credential
```

`tm proof` (alias `tm flag`) records a flag or proof file. The path is
suggested from the target OS and Principal. Reading a flag is not a shell, so
proof never raises Access on its own: the interactive flow asks, and scripts
get a hint. `--show` types `hostname; whoami; ip a; cat <path>` into the
invoking pane first, so the screenshot carries the proof the way OSCP expects.

```bash
tm proof user 9a1d4ff1… /home/<user>/local.txt
tm flag root 49d89584…         # path defaults to /root/proof.txt
```

Screenshots use flameshot. `tm done -s`, the proof flow, and the palette's
📷 entry start a region capture after any popup has closed; the PNG is saved
under `targets/<T>/screenshots/` and attached to the entry. Interactive success
entries also offer the latest unattached NOCAP capture (from `cap …` or
`cap grab`), and 📎 attaches one to any earlier entry.

## Snapshots, shell logs, and closing out

`tm snap` saves the rendered text of every logging pane (wrapped lines joined)
to `logs/YYYYMMDD/scrollback_*`. Panes whose logging you turned off with
prefix+`T` are skipped and reported, so output you kept off disk stays off disk;
prefix+`S` still saves one explicitly. It also copies matching shell-handler sessions into
`captures/<target>/shells/`. Penelope names sessions `host~IP-OS-arch` (or
`IP-OS-arch`); sessions for the target's Endpoint are copied with their
`downloads/`, skipping symlinks and files over 100 MiB, with a README noting the
local-time UTC offset. `tm stop` snapshots first.

```toml
[behavior]
snapshot_on_stop = true

[integrations]
shell_log_dirs = ["~/.penelope/sessions"]   # [] disables the copy
```

`tm close` walks a checklist: Access, open TODO, the cleanup release gate,
proof, and a confirmed credential. Enter on a line fixes it inline. It then
sets Status (default `complete`), takes an optional final summary, snapshots,
and stops the session. Sessions whose panes still run programs (penelope,
`nc`, an agent) need confirmation. In the operations session, `tm close`
(or `--engagement`) shows every target, the engagement-wide cleanup gate, and
snapshots and stops all sessions: other targets, then OPS, then the session
running the command. `--yes` skips every prompt; `--no-stop` keeps sessions.

## Engagement and target workflow

Create an engagement and targets:

```bash
tacmux init ACME
cd ~/workspace/ACME
tacmux target add EDGE01 198.51.100.20
tacmux target add DC01 10.20.30.10
tacmux target update EDGE01 os Linux
```

Every target receives `scans`, `payloads`, `loot`, `screenshots`, and `working`. Target creation adds its Details and Ports tables to SITREP but does not start a session.

Run `tacmux` or `tacmux switch` to select any engagement's operations session, live target, or stopped target. Selecting a stopped entry creates the tmux session; selecting a live entry switches or attaches. `tacmux stop [TARGET]` stops a session.

Rename and delete require a stopped target session:

```bash
tacmux target rename EDGE01 WEB01
tacmux target delete MISTAKE
```

Target headings in SITREP are inventory identities, not display-only labels. Rename them with `tacmux target rename`, including after a heading was changed manually in an editor. An unambiguous manual change can be completed by the normal rename command; ambiguous heading/directory mismatches are refused without modifying the document.

Deletion requires typing the exact target name. It refuses targets referenced by the Operations Log, ports, confirmed credentials, TODO, Cleanup, or NOCAP captures. Clear mistaken records explicitly; TACMUX never cascade-deletes operational history.

Generate an endpoint-only tool input file from the current target inventory:

```bash
tm target export             # choose All, Select, or None
tm target export --all
tm target export WEB01 DC01
tm target export --none      # write an empty file
nmap -iL targets.txt
```

Interactive Select uses fzf multi-selection; `Ctrl+A` selects all visible rows and `Ctrl+D` deselects them. TACMUX atomically replaces owner-only `targets.txt` in the engagement root. It contains one Endpoint per line with no headings, names, or annotations. `SITREP.md` remains the source of truth, so rerun the export after inventory or selection changes.

## SITREP

Open the whole file or jump directly to a section or target:

```bash
tacmux sitrep
tacmux sitrep context
tacmux sitrep log
tacmux sitrep notes              # alias for the Operations Log
tacmux sitrep cleanup
tacmux sitrep WEB01
tm log edit E012                 # jump to one recorded operation
```

Neovim, Vim, and Vi open at the resolved heading line. Other editors open the file normally. When the editor closes, TACMUX validates the managed tables, refreshes credential derivative files, and restores the SITREP to owner-only permissions.

Targets and Credentials retain exact Markdown tables. TODO and Cleanup are native Markdown checklists, and each Operations Log event has stable boundary markers with operator-owned prose inside it. Values added through helpers must be one line; use the event's Notes area for longer material.

`tacmux sitrep sync` offers a one-time, backed-up conversion from the original Narrative/TODO/Completed tables. It then restores absent empty managed structures, normalizes checklists with open work first, adds a section for a manually created target directory after requesting its endpoint, regenerates credential derivative files, and reports bad IDs or references. It refuses malformed or partial markers, target-heading mismatches, and ambiguous manual renames without changing the document; it never rewrites event prose.

### Optional external notes location

TACMUX does not require Obsidian. To store each physical SITREP in Obsidian or another Markdown tree, configure its parent directory before creating an engagement:

```toml
[paths]
workspace = "~/workspace"
sitrep_root = "~/notes/engagements"
```

For `ACME`, TACMUX creates `<sitrep_root>/ACME/SITREP.md` and a validated `~/workspace/ACME/SITREP.md` link. Both editors operate on that one file; there is no synchronization daemon or second copy. Existing engagements are not moved automatically. The notes root must already exist, be writable, and not be a symlink. Do not use a cloud-synced location unless its handling of the raw credentials in SITREP is approved.

## Operations Log and tasks

Use the Operations Log for the chronological walkthrough:

```bash
tm log "Identified IIS on the external host"
tm log failed "Password spray produced no valid login"
tm log partial "Responder captured a challenge but it did not crack"
tm log success "Validated command execution as svc_web"
tm done "Established the approved internal pivot"
```

Inline logging uses the current target, or `ENGAGEMENT` from the operations session. `tm log` with no arguments prompts for the outcome, summary, and Notes; inside a target session the entry belongs to that target, while the operations session asks which target (or ENGAGEMENT) it is for, defaulting to the most recently used target. `tm fail TEXT` records a dead end, and `tm history --outcome failed` lists them. `tm history` shows the newest engagement events first; pass a target to filter it. The Markdown reads oldest-to-newest as a walkthrough.

Attach the most recent NOCAP record and optional screenshots to the same event:

```bash
cap -n internal-hosts nxc smb 10.20.30.0/24
tm done -c "Identified hosts through the internal pivot"
tm done -c -i ~/proof/pivot.png "Established the internal pivot"
tm log failed -c "The captured service-account hash did not crack"
```

`-c`/`--capture` calls `cap inspect --json`, requires a finished retained capture on the current target's route, and records its ID, tool, path, and command. `-i`/`--image` may be repeated; supported images are copied under the SITREP's sibling `images/` directory and embedded in the event. Capture-assisted entries without an image retain an explicit “Not attached” placeholder and editable caption. Draft-finding text and supporting Notes belong inside the event so the evidence and reasoning remain together.

After switching targets, NOCAP's latest capture may belong to another route.
Use `cap timeline` to find the intended ID, then run
`tm done --capture-id ID "Completed step"`. The same route and retained-evidence
checks apply. Use `tm log edit E012` to jump directly to an event's captions,
draft findings, or supporting prose.

Images may be PNG, JPEG, GIF, or WebP and must not exceed 25 MiB. Spaces and `@` are preserved in filenames; TACMUX rejects filename characters that would be interpreted as Markdown or URL syntax.

TODO is a persistent Markdown checklist, not a second history:

```bash
tm todo add "Enumerate SMB shares"
tm todo
tm todo done                 # choose with fzf
tm todo reopen               # restore a checked item
```

Completing a TODO changes `[ ]` to `[x]`, records its completion time, and keeps it below open work. Checking an item in Obsidian or `$EDITOR` has the same effect for TACMUX; a manual check may have no completion timestamp. A successful action worth remembering should also be logged with `tm done`; task completion alone does not invent an operational claim.

Cleanup remains separate because it is a release gate:

```bash
tm cleanup add "Remove /tmp/update.sh"
tm cleanup
tm cleanup done              # choose only after verification
tm cleanup reopen
```

## Target status

Target Details contain only Endpoint, Network, Status, Hostnames, Role, OS, Access, Principal, Method/Path, and Capture Route. Status is `new`, `active`, `blocked`, or `complete`. Use `tm target update` for an interactive target/field selector, or update a field directly:

```bash
tm target update WEB01 status active
tm target update WEB01 os Linux
tm target update WEB01 role "mail server"
tm target update WEB01 principal --clear
```

The field keys are `endpoint`, `network`, `status`, `hostnames`, `role`, `os`, `access`, `principal`, `method`, and `route`. Endpoint and Capture Route updates require the target session to be stopped because they define new-session and capture behavior. Direct Access updates may deliberately raise or lower the recorded level; credential confirmation only raises it. Use `tm sitrep TARGET` for Notes or unusual manual corrections.

`tm status` inside a target shows Details, ports, confirmed credentials without secrets, tasks, cleanup, and recent Operations Log events. In the operations session it shows OS and access across the engagement. Pass a target name for its detailed view.

## Credentials

Run `tm creds add` and choose Password or Hash. Interactive entry avoids putting the secret in shell history; bulk or deliberate direct entry also accepts:

```bash
tm creds add password 'alice:correct horse battery staple'
tm creds add hash 'alice:aad3b435b51404ee:31d6cfe0d16ae931'
```

Input splits on the first colon. SITREP is the source of truth. TACMUX generates deduplicated `creds.txt`, `users.txt`, `passwords.txt`, and `hashes.txt` under `credentials/`.

Store SSH private keys centrally under `credentials/keys/`; TACMUX creates that
owner-only directory for new engagements and repairs it on the next mutation
or `tm sitrep sync`. Read-only commands leave the directory tree untouched.
Keep the corresponding passphrase in Credentials
and set its Source to the relative key path. For example:

```bash
install -m 600 recovered.key credentials/keys/svc-web.key
tm creds add password
```

Zsh completion is installed for both `tacmux` and the recommended `tm` alias.
It completes commands, actions, capture/image flags, engagements, targets, target fields, SITREP sections, credential IDs, open or completed task IDs, cleanup IDs, access values, and input files.
It never emits credential values.

`tm creds` and `tm creds view` display raw values but abbreviate long fields.
Use `tm creds view C001` for the
complete principal, password or hash, confirmations, and notes without clipping.

Once a credential works, record its target, service, and access on the same row:

```bash
tm creds confirm                                  # pickers for every part
tm creds confirm C001 WEB01 user SSH "interactive shell"
tm creds confirm C001 WEB01 DC01 auth 445         # several targets at once
```

Inside a target session the target is implied. Without a service, TACMUX offers
the open services from the selected targets' Ports table (`http :8000`,
`microsoft-ds :445`); a port number, `tcp:8000`, or service name typed directly
maps to the same label. An interactive `tm creds add` ends by offering to record
where the credential works.

Confirmed Access uses `TARGET · SERVICE · ACCESS`; confirming the same target/service updates that entry, while another target or service is appended to the same credential. Only confirmed successes belong here. Put useful failures in the Operations Log. Confirmation can raise a target's Access, Principal, and Method/Path but never silently lower stronger access already recorded. Access means the capability actually demonstrated: authentication alone is `authenticated`, not code execution.

## Ports

Run custom service enumeration from the target shell and ingest Nmap's normal port rows:

```bash
nmap -sV "$TARGET" | tm ports add
```

With saved Nmap output:

```bash
tm ports add WEB01 targets/WEB01/scans/manual-nmap.txt
```

The raw input is copied into the target's `scans/` directory. TCP, UDP, and SCTP rows merge on `(port, protocol)`; new observations update state, service, and version while preserving Notes. Input containing no valid port rows makes no change.

A full Nmap report must contain exactly one host matching the selected target's
Endpoint or Hostnames. Multi-host and mismatched reports are refused before any
files change. Pasted port rows without a report header apply to the selected target.

## Host identification

`tm discover` offers three foreground inputs:

- `nmap`: fixed `nmap -sn --reason -oG - IP_OR_CIDR` after confirmation
- `hosts`: pasted or piped `NAME IP`, `IP`, or Nmap report lines
- `netexec`: pasted or piped NetExec SMB output

Candidates open in `$EDITOR` as `TARGET_NAME<TAB>IP`. Delete gateways or unwanted entries and rename targets as needed. Save and close to stage the review; quit without saving to cancel. After a save, TACMUX shows the accepted count and requires a final default-No confirmation before creating any target trees. Existing names or endpoints are skipped, and sessions never auto-start. If Nmap reports implausibly broad liveness through a pivot, cancel and use the `netexec` or `hosts` input instead.

TACMUX has no formal scope engine. Supplying an active discovery destination is an operator authorization decision.

## NOCAP and pane logs

Target sessions export:

```text
TARGET=<endpoint>
NOCAP_WORKSPACE=<engagement>
TACMUX_TARGET=captures
NOCAP_ROUTE_PREFIX=<stable capture route>
```

This keeps one NOCAP metadata root at `captures/.nocap` while routing files beneath `captures/<target>/`. Consequently `cap timeline` and `cap browse` can review the complete engagement. `tm done -c` reads but never modifies that metadata. After a target has captures, renaming it retains the old Capture Route rather than rewriting evidence metadata.

This route-prefix behavior requires NOCAP 2.3 or newer. `tacmux health` rejects an installed older version while continuing to treat an absent NOCAP installation as optional.

Pane logs are centralized under `logs/YYYYMMDD/`. TACMUX installs logging hooks only on TACMUX-owned sessions, so new windows and splits start logging automatically. Reopening an existing session repairs missing hooks without re-enabling panes you deliberately toggled off. Prefix+`T` toggles current-pane logging and Prefix+`S` captures rendered
scrollback (wrapped lines joined).
