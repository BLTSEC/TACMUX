# TACMUX

<p align="center">
  <img src="assets/TACMUX.jpg?v=4" alt="TACMUX — military-green operator illustration with a distressed stencil title and a realistic tmux workspace" width="100%">
</p>

<p align="center">
  <a href="https://github.com/BLTSEC/TACMUX/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/BLTSEC/TACMUX/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-2ea44f"></a>
</p>

TACMUX is a lean tmux workspace for authorized penetration tests and red-team
operations. Each engagement gets one tmux session per target, central pane logs,
and a single editable `SITREP.md` that holds targets, ports, credentials, tasks,
cleanup, and a chronological Operations Log. You stay in your shells; TACMUX
records what happened.

> Use TACMUX only with explicit authorization. You remain responsible for scope,
> rules of engagement, testing windows, evidence handling, and retention.

## Requirements

- Linux, Python 3.11+, tmux, [fzf](https://github.com/junegunn/fzf), and
  [uv](https://docs.astral.sh/uv/) (installer)
- `$VISUAL`, `$EDITOR`, or `vi`
- Optional: Zsh (completion), Nmap (`tm discover nmap`),
  [NOCAP](https://github.com/BLTSEC/NOCAP) 2.3+ (command captures as evidence),
  flameshot (screenshots), and penelope (shell logs copied into captures)

## Install

```bash
git clone --branch v3.4.1 --depth 1 https://github.com/BLTSEC/TACMUX.git
cd TACMUX
./install.sh --workspace ~/workspace   # omit --workspace on reinstall
exec "$SHELL" -l
tacmux health
alias tm='tacmux'                      # add to your shell rc; docs use tm
```

The installer puts TACMUX under `~/.local/share/tacmux`, links `tacmux` into
`~/.local/bin`, enables Zsh completion for `tacmux` and `tm`, and adds only its
integration fragment to `~/.tmux.conf`. Reload tmux (`tmux source ~/.tmux.conf`)
to pick up the key bindings.

## Quick start

```bash
tm init ACME          # creates the engagement, then offers to add the first
                      # target and open its session: one command per box
tm target add WEB01 192.0.2.10        # more targets; inside tmux it offers to open one
tm switch                             # pick any session (Prefix+E)
```

Box reverted with a new IP? `tm target update WEB01 endpoint 192.0.2.11` from
OPS saves its logs, restarts the session, and copies the new `/etc/hosts` line.

Inside a target session, press **Prefix+`M`** (or type `tm`) and pick what
happened. Each entry previews the direct command it runs:

```text
╭ TACMUX> ─ ACME / WEB01 · 192.0.2.10 · Access: none · Status: active ─────────╮
│ ✗  Failed / dead end          │ Record what did not work. AARs and reports   │
│ ✓  Step worked                │ are mostly about the detours.                │
│ 🔑 Found credential            │                                              │
│ 🔑 Credential works            │ Direct command:                              │
│ 🧹 Add cleanup item            │   tm fail "EDB 50640 broken"                 │
│ ↶  Undo last change           │                                              │
│ ⇄  LIVE  ACME / DC01 …        │                                              │
╰──────────────────────────────────────────────────────────────────────────────╯
```

The same flow from the shell:

```bash
nmap -sV "$TARGET" | tm ports add          # merge ports into SITREP
tm fail 'Default creds :: admin:admin rejected'   # Title :: details
tm done 'Shell as app :: ```python3 exploit.py``` RCE works'   # code block
tm creds add password 'admin:admin'        # store a credential (C001)
tm creds confirm C001 auth 8000            # works on WEB01, service from Ports
tm target update access                    # missing value → picker
tm access user svc_web "file upload" --via "http :80"   # Access raised, one step
tm proof root 49d8… /root/proof.txt        # flag + screenshot (alias tm flag)
tm undo                                    # revert the last TACMUX change
tm evidence                                # pane logs, commands, shells, captures
tm close                                   # checklist, readable logs, stop
```

## How input works

- **Any bracketed argument can be omitted**; TACMUX asks for only what is
  missing. Inside a target session the target is implied.
- **Words accept prefixes and aliases.** Fields: `acc`, `st`, `as` (principal),
  `via` (method), `host`. Access: `auth`, `shell`, `root` (admin), `dom`.
  Status: `done` (complete). `tm log f|p|s TEXT` sets the outcome. An ambiguous
  word such as `a` opens a filtered picker.
- **`tm COMMAND --help`** shows exact forms, accepted words, and examples. It
  never writes to SITREP. Unknown options are refused; put `--` before text that
  starts with `-`.
- **Scripts and agents** set `TACMUX_NONINTERACTIVE=1` (or run without a
  terminal): a missing argument then fails with its name instead of prompting.
- **Entries are `Title :: details`.** ```` ```cmd``` ```` anywhere becomes a
  code block and `-l` adds your last command. Use single quotes when the text
  has backticks (zsh runs them inside double quotes). With no text, the prompts
  are Title, Command (prefilled with your last command), and Details.
- **`tm undo`** reverts the last TACMUX change to SITREP. It refuses after
  SITREP was edited outside TACMUX, and target add/rename/delete start a new
  undo history. `tm undo --yes` skips the confirmation.

## Commands

```text
Record      tm log [OUTCOME] [-c] [-l] [-i IMAGE] TEXT  'Title :: details'; outcomes:
                                                     info success partial failed
            tm fail TEXT · tm done [-s] TEXT         shorthands for failed / success
            tm access [LEVEL] [AS] [HOW…]            access gained, one undoable step
            tm proof|flag [user|root] [VALUE] [PATH] flag/proof with a screenshot
            tm creds [view [ID] | add | confirm]     credentials and where they work
            tm ports add [TARGET] [FILE]             Nmap normal output (or stdin)
            tm todo | tm cleanup [add|done|reopen]   checklists in SITREP
            tm undo [--yes]
Inspect     tm status [TARGET] · tm history [TARGET] [--outcome O] · tm ports [TARGET]
            tm sitrep [SECTION|TARGET] · tm log edit [EVENT_ID]
            tm evidence [TARGET]                     everything recorded, opens any
Targets     tm init [NAME] · tm target add|update|export|rename|delete
            tm notes [FOLDER|none|move]              notes folder for new engagements
            tm discover [nmap|hosts|netexec]         reviewed host import
Sessions    tm (palette in a session, switcher elsewhere) · tm menu · tm switch
            tm snap [TARGET] · tm close [TARGET|--engagement] · tm stop [TARGET]
Maintain    tm sitrep sync · tm health · tm help [COMMAND] · tm version
            eval "$(tacmux shell-init zsh)"          command journal (installer adds it)
```

**Keys** (after your tmux prefix): `M` palette · `E` switcher · `T` toggle pane
logging · `S` save an exact pane capture. The status line shows `[WEB01 · user · LOG]`
so an unrecorded `none` stands out.

## Workspace and SITREP

```text
~/workspace/ACME/
├── SITREP.md            # the record (file, or link to sitrep_root)
├── targets.txt          # tm target export: one endpoint per line
├── credentials/         # creds, users, passwords, hashes .txt (from SITREP); keys/
├── captures/            # NOCAP evidence, one folder per target
├── logs/YYYYMMDD/       # raw pane logs (.log) + readable copies (.txt)
├── logs/commands.tsv    # command journal: time, duration, exit, target, pane
├── targets/WEB01/       # scans/ payloads/ loot/ screenshots/ working/
└── .tacmux/             # engagement marker, lock, undo journal
```

`SITREP.md` keeps current state first (Targets, Credentials, TODO, Cleanup),
then the Operations Log, where each entry is a callout colored by outcome:

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
 It is plain Markdown: edit it in Obsidian or
`$EDITOR`; checked boxes and prose between markers are understood. Rename
targets with `tm target rename`, not by editing headings alone.

**Evidence:**
- `tm done -c "…"` attaches the latest NOCAP capture on this target's route.
  Use `--capture-id ID` for an earlier one (`cap timeline` lists them).
- `-i proof.png` attaches screenshots.
- `tm creds view C001` shows a full credential. Displaying secrets puts them
  in pane logs.
- `tm done -s`, `tm proof`, and the palette take flameshot region screenshots
  and attach them.

**Logging** is automatic; `tm evidence` shows all of it:

| Layer | When | Where |
|---|---|---|
| Raw pane log | always (Prefix+T toggles) | `logs/YYYYMMDD/*.log` |
| Readable pane log | `tm snap`/`stop`/`close`/`evidence` | same name, `.txt` (rendered from the raw log; closed panes too) |
| Command journal | every command (zsh hook) | `logs/commands.tsv` |
| Penelope sessions | `tm access`/`proof`/`snap`/`stop`/`close` | `captures/<target>/shells/penelope/` |
| Exact capture | Prefix+S | `logs/YYYYMMDD/scrollback_*.log` |

NOCAP users: `cap grab` reads the last command from your history file, so set
`setopt INC_APPEND_HISTORY_TIME` in `~/.zshrc`.

**External notes:** keep each SITREP in Obsidian or another notes tree, one
folder per course or client if you like:

```bash
tm notes ~/notes/engagements/PG    # or tm notes PG once the folder is listed
tm init Fractal                    # → ~/notes/engagements/PG/Fractal/SITREP.md
tm notes HTB                       # next course; PG engagements keep working
tm notes move Fractal OSCP         # optional: relocate a note folder (+ images)
```

`tm notes` sets `[paths] sitrep_root` in `~/.config/tacmux/config.toml`. Each
engagement remembers its own folder, so switching never hides or moves existing
work. TACMUX, Obsidian, and `$EDITOR` edit the same file; there is no sync
process or API.

## Boundaries and safety

TACMUX does not do any of the following:
- enforce scope or testing windows
- exploit targets
- call AI
- generate reports
- keep a formal findings registry

Draft findings belong in Operations Log entries; formal assessment management
belongs to your RoE and reporting platform.

The engagement directory holds raw secrets: SITREP, `credentials/`, pane logs,
and the undo journal in `.tacmux/undo/`. Treat all of it as sensitive evidence.
Shared and cloud-synced folders may not enforce Unix permissions. With
`sitrep_root`, back up the physical note and its sibling `images/` directory as
well as the workspace.

More: [operator guide](docs/USAGE.md) · [keybindings](docs/KEYBINDINGS.md) ·
[changelog](CHANGELOG.md) · [security policy](SECURITY.md)

## Remove

```bash
./uninstall.sh   # configuration and engagement workspaces are preserved
```

## License

[MIT](LICENSE)
