# TACMUX operator guide

## Operating model

An engagement is an ordinary parent directory marked by `.tacmux/version`. Its target directories define inventory and its single `SITREP.md` holds operational state. TACMUX does not create hidden target records or maintain a second database.

Use one engagement for one authorized body of work. Keep unrelated client, lab, and training activity in separate parents.

## Start a box

```bash
tm init Fractal 192.168.120.5   # engagement Fractal + target FRACTAL, then offers its session
tm target                       # targets table, then add/update/rename/delete/export
tm stop ops                     # OPS is the operations session (also: tm status ops, tm snap ops)
```

Without an endpoint, `tm init NAME` asks for the first target with the name
prefilled. Esc in any picker cancels quietly (exit 0, nothing recorded).

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
| 🏷 Add hostname / vhost (the palette also copies an `/etc/hosts` command that updates only those names, preserving other aliases and comments) | `tm target update hostnames "a.example b.example"` |
| ✎ Edit a target field | `tm target update [TARGET] [FIELD] [VALUE]` |
| ✎ Edit a log entry | `tm log edit [EVENT_ID]` |
| ↶ Undo last change | `tm undo` |
| ⓘ Status · History · SITREP · Context | `tm status` · `tm history` · `tm sitrep` · `tm sitrep context` |
| ➕ Add target · 🔎 Discover hosts | `tm target add NAME IP` · `tm discover` |
| 🗂 Evidence & logs | `tm evidence [TARGET]` (`tm snap` refreshes without the view) |
| 📁 Notes folder (SITREP root) | `tm notes [NAME\|PATH\|none]` · `tm notes move [ENG] [FOLDER]` |
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
get a hint. When you record the shell there, it also asks how you got it, so
Method/Path isn't left blank (Enter skips). `--show` lets you pick the pane
holding the target shell (penelope, `nc`, `ssh`, evil-winrm; never a plain
local shell) and types `hostname; whoami; ip a; cat <path>` there first, or
`cmd /c "hostname & whoami & ipconfig & type <path>"` on Windows, which works
in both cmd and PowerShell. The screenshot then carries the proof the way OSCP
expects. Each pane is listed by its on-screen `window.pane` number, the title
pinned in `@pinned_title` (operator-loadout sets it with Prefix+P), and its
last line (usually the remote prompt, such as `root@host:~#`), with the pane's
recent output in the preview. The pane you came from is first, so Enter usually
picks it, and the pane running `tm proof` itself is never offered. At a
terminal the proof screenshot is offered by default; scripts and agents never
get one. After a root proof, TACMUX offers `tm close` (default no). From the
Prefix+M popup, the close-out opens in a new popup once the screenshot is
taken, so the popup never ends up in the proof screenshot. In a normal
terminal pane, capture finishes before the close-out checklist opens. If
queuing the screenshot fails, TACMUX reports the error and runs close-out
inline instead of waiting for a nonexistent background job.

```bash
tm proof user 9a1d4ff1… /home/<user>/local.txt
tm flag root 49d89584…         # path defaults to /root/proof.txt (HTB: /root/root.txt)
```

Screenshots use flameshot. `tm done -s`, the proof flow, and the palette's
📷 entry start a region capture after any popup has closed; the PNG is saved
under `targets/<T>/screenshots/` and attached to the entry. Interactive success
entries also offer the latest unattached NOCAP capture (from `cap …` or
`cap grab`), and 📎 attaches one to any earlier entry.

## Logs, evidence, and closing out

Everything records on its own; `tm evidence` shows it in one place.

| Layer | Written by | When | Where |
|---|---|---|---|
| SITREP entries and screenshots | you (`tm log/fail/done/access/proof`, `-s`) | when you record | SITREP, `images/` |
| Command journal | zsh hook (`tacmux shell-init zsh`) | every command in TACMUX shells | `logs/commands.tsv` |
| Raw pane log | `pipe-pane` | always (Prefix+`T` toggles) | `logs/YYYYMMDD/*.log` |
| Readable pane log | renderer | `tm snap`/`stop`/`close`/`evidence` | same name, `.txt` |
| Exact capture | Prefix+`S` | on request | `logs/YYYYMMDD/scrollback_*.log` |
| NOCAP | `cap …` / `cap grab` | when you use it | `captures/<target>/…` |
| Penelope | penelope | each session; copied at `access`/`proof`/`snap`/`stop`/`close` | `captures/<target>/shells/penelope/` |

**Readable pane logs.** `tm snap` renders each raw pane log into
`<same name>.txt`: progress bars collapse to their final state, line-editor
redraws resolve, colour codes and window titles disappear, and full-screen
programs (vim, less) become one `[full-screen program]` line. Closed panes get a
readable copy too. Only bytes from the raw log are used, so output from a
period when you turned logging off never appears; Prefix+`S` still saves an
exact capture of one pane.

**Command journal.** `eval "$(tacmux shell-init zsh)"` (the installer adds it)
records `epoch, seconds, exit, target, pane, cwd, command` for each command in
a TACMUX session. A leading space skips one command; `TACMUX_NO_AUTOLOG=1`
disables it. The pane column matches the `Pane:` header of the pane logs.

**Shell handlers.** Matching sessions are copied into
`captures/<target>/shells/`. Penelope names sessions `host~IP-OS-arch` (or
`IP-OS-arch`); sessions for the target's Endpoint are copied with their
`downloads/`, skipping symlinks and files over 100 MiB, with a README listing
the local-time UTC offsets in effect when the logs were written.

**`tm evidence [TARGET]`** refreshes readable logs and shell logs, prints
counts (entries, failed commands, logs, Prefix+S exact captures, captures,
screenshots), and at a terminal lets you open any of them in `$PAGER`.

```toml
[behavior]
snapshot_on_stop = true

[integrations]
shell_log_dirs = ["~/.penelope/sessions"]   # [] disables the copy
```

`tm close` walks a checklist: Access, open TODO, the cleanup release gate,
proof, and a confirmed credential. Enter on a line fixes it inline. It then
sets Status (default `complete`), takes an optional final summary, writes
readable logs and copies shell logs, and stops the session. If the target is
complete and has Hostnames, it offers an `/etc/hosts` command that removes them
(default no). Sessions whose panes still run programs (penelope,
`nc`, an agent) need confirmation. In the operations session, `tm close`
(or `--engagement`) shows every target, the engagement-wide cleanup gate, and
writes readable logs and stops all sessions: other targets, then OPS, then the session
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

### Notes folders (external SITREP)

TACMUX does not require Obsidian. To store each physical SITREP in Obsidian or another Markdown tree, pick a notes folder:

```bash
tm notes ~/notes/engagements/PG   # path, or a listed folder name: tm notes PG
tm notes                          # show the current folder and pick another
tm notes none                     # back to SITREP inside each engagement
```

This sets `[paths] sitrep_root` in `config.toml` (other lines and comments are kept). For `Fractal`, TACMUX then creates `<folder>/Fractal/SITREP.md` and a validated `~/workspace/Fractal/SITREP.md` link, and records the folder in `.tacmux/notes_root`. Each engagement is validated against its own recorded folder, so switching folders per course never hides or moves existing engagements; engagements created before 3.4 are pinned on their next change or by `tm notes`. `tm notes move ENG FOLDER` relocates a note folder with its `images/` (same filesystem; rolled back on failure).

A notes folder must exist, be writable, not be a symlink, and sit outside the workspace. Do not use a cloud-synced location unless its handling of the raw credentials in SITREP is approved.

## Operations Log and tasks

Use the Operations Log for the chronological walkthrough:

```bash
tm log "Identified IIS on the external host"
tm log failed "Password spray produced no valid login"
tm log partial "Responder captured a challenge but it did not crack"
tm log success "Validated command execution as svc_web"
tm done "Established the approved internal pivot"
```

Each entry has a title, an optional code block, and details. Type them as `Title :: details`; any ```` ```cmd``` ```` span becomes a code block, and `-l`/`--last` adds the last command you ran in this pane (from the command journal). Use single quotes when the text contains backticks: inside double quotes zsh would run the code.

```bash
tm fail 'EDB 50640 broken :: ```python3 50640.py -t $T``` needs an existing project'
tm done "Root via python3.10 cap_setuid :: proof.txt captured" -l
```

In SITREP each entry is an Obsidian callout colored by outcome (`success` green, `failure` red, `warning` for partial, `note` for info):

```markdown
> [!success] Root via python3.10 cap_setuid
> `E008` · `2026-11-03 05:52:10Z` · `LEVRAM`
>
> ```bash
> /usr/bin/python3.10 -c 'import os; os.setuid(0); os.system("/bin/bash")'
> ```
>
> proof.txt captured.
```

Edit the title and details freely in Obsidian or `$EDITOR`; keep the chip line (`ID` · `time` · `target`). Entries written by TACMUX 3.3 and earlier are read as before and rewritten in this form on the next change, keeping all text (a long old summary gets a short title).

Inline logging uses the current target, or `ENGAGEMENT` from the operations session. `tm log` with no text prompts for the outcome, Title, Command (prefilled with your last command), and Details; inside a target session the entry belongs to that target, while the operations session asks which target (or ENGAGEMENT) it is for, defaulting to the most recently used target. `tm fail TEXT` records a dead end, and `tm history --outcome failed` lists them. `tm history` shows the newest engagement events first; pass a target to filter it. The Markdown reads oldest-to-newest as a walkthrough.

Attach the most recent NOCAP record and optional screenshots to the same event:

```bash
cap -n internal-hosts nxc smb 10.20.30.0/24
tm done -c "Identified hosts through the internal pivot"
tm done -c -i ~/proof/pivot.png "Established the internal pivot"
tm log failed -c "The captured service-account hash did not crack"
```

`-c`/`--capture` calls `cap inspect --json`, requires a finished retained capture on the current target's route, and records its ID, tool, path, and command. `-i`/`--image` may be repeated; supported images are copied under the SITREP's sibling `images/` directory and embedded in the event. Screenshots attached later add a Screenshots section. Draft-finding text and supporting notes belong inside the event so the evidence and reasoning remain together.

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

The field keys are `endpoint`, `network`, `status`, `hostnames`, `role`, `os`, `access`, `principal`, `method`, and `route`. Endpoint and Capture Route updates require the target session to be stopped because they define new-session and capture behavior. After a box revert gives a new IP, run `tm target update TARGET endpoint IP` from OPS: TACMUX offers to save its logs (readable copies and shell logs), restart it with the new `TARGET`, and copy the `/etc/hosts` line for its hostnames to the clipboard. Direct Access updates may deliberately raise or lower the recorded level; credential confirmation only raises it. Use `tm sitrep TARGET` for Notes or unusual manual corrections.

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
tm ports add          # at a terminal: pick from *.nmap and scans/*, or "Paste output…"
```

The raw input is copied into the target's `scans/` directory. TCP, UDP, and SCTP rows merge on `(port, protocol)`; new observations update state, service, and version while preserving Notes. Input containing no valid port rows makes no change. When the target's OS is empty, the same change fills it from the report: the `smb-os-discovery` OS for Windows (e.g. `Windows Server 2016 Standard 14393`), otherwise the `Service Info: OS:` value. A recorded OS is never overwritten; Samba's fake "Windows 6.1 (Samba …)" and conflicting Service Info values leave it empty.

A full Nmap report must contain exactly one host matching the selected target's
Endpoint or Hostnames. Multi-host and mismatched reports are refused before any
files change. Pasted port rows without a report header apply to the selected target.

## Host identification

`tm discover` offers three foreground inputs:

- `nmap`: fixed `nmap -sn --reason -oG - IP_OR_CIDR` after confirmation
- `hosts`: `NAME IP`, `IP`, or Nmap report lines, pasted into `$EDITOR` or read
  from a file (`tm discover hosts FILE`)
- `netexec`: NetExec SMB output, pasted or read from a file

Every source ends in a review in `$EDITOR` and a final confirmation, so run
`tm discover` from a terminal. Piping input into it is not supported; TACMUX
says so before reading anything or offering to scan.

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

Pane logs are centralized under `logs/YYYYMMDD/`. TACMUX installs logging hooks only on TACMUX-owned sessions, so new windows and splits start logging automatically. Reopening an existing session repairs missing hooks without re-enabling panes you deliberately toggled off. Prefix+`T` toggles current-pane logging and Prefix+`S` saves an exact capture
of the pane (wrapped lines joined). Readable `.txt` copies of every raw log are
written by `tm snap`, `tm stop`, `tm close`, and `tm evidence`.
