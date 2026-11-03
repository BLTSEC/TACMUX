"""Per-command help generated from the same vocabularies the CLI accepts."""

from __future__ import annotations

from .workspace import ACCESS_LEVELS, OUTCOMES, TARGET_STATUSES

HELP_FLAGS = frozenset({"-h", "--help"})

# Field keys mirror cli.TARGET_DETAIL_FIELDS; kept here to avoid an import cycle.
FIELD_KEYS = (
    "status",
    "access",
    "principal",
    "method",
    "os",
    "hostnames",
    "role",
    "network",
    "endpoint",
    "route",
)

USAGE = """TACMUX — lean tmux-native engagement workspaces

Start here:
  tm                             Action palette inside a session (switcher outside)
  Prefix+M                       Same palette as a tmux popup
  tm COMMAND --help              Exact forms, accepted words, and examples

Record:
  tm log [OUTCOME] TEXT          Operations Log entry: 'Title :: details'
                                 (```code``` becomes a code block; -l adds
                                 your last command; default outcome: info)
  tm fail TEXT                   Dead end or failed attempt (log failed)
  tm done TEXT                   Completed step (log success; -s screenshot)
  tm access [LEVEL] [AS] [HOW]   Access gained: entry + Access + credential used
  tm proof [user|root] [VALUE]   Flag/proof with screenshot (alias: tm flag)
  tm creds [add|confirm|view]    Credentials and where they work
  tm todo [add|done|reopen]      Planned work
  tm cleanup [add|done|reopen]   End-of-engagement obligations
  tm ports add [TARGET] [FILE]   Import Nmap normal output
  tm undo                        Revert the last TACMUX change to SITREP

Inspect:
  tm status [TARGET]             Target or engagement status
  tm history [TARGET] [--outcome O]
  tm sitrep [SECTION|sync]       Edit or repair SITREP
  tm evidence [TARGET]           Everything recorded: pane logs, commands,
                                 shell logs, captures (opens any in less)

Targets and sessions:
  tm init [NAME]                 Create or open an engagement
  tm notes [FOLDER|move]         Notes folder (SITREP root) for new engagements
  tm target add|update|export|rename|delete
  tm discover [nmap|hosts|netexec]
  tm switch                      Session switcher (Prefix+E)
  tm snap [TARGET]               Write readable pane logs and copy shell logs now
  tm close [TARGET|--engagement] Guided close-out, then stop
  tm stop [TARGET]               Stop a session (writes readable logs first)

Maintenance:
  tm health · tm version · tm help COMMAND
  eval "$(tacmux shell-init zsh)"  Command journal hook (installer adds it)

Every argument shown in [brackets] may be omitted: TACMUX asks for it.
Scripts and agents: set TACMUX_NONINTERACTIVE=1 to fail instead of prompting.
"""


def _words(values: tuple[str, ...] | list[str]) -> str:
    return " · ".join(values)


def _sections() -> dict[str, str]:
    outcomes = _words(OUTCOMES)
    access = _words(ACCESS_LEVELS)
    statuses = _words(TARGET_STATUSES)
    fields = _words(FIELD_KEYS)
    return {
        "log": f"""tm log — record a step in the Operations Log

Easiest:  tm → ✗ Failed / ✓ Step worked
Forms:    tm log [OUTCOME] TEXT…
          tm log [OUTCOME] -c TEXT…            attach the latest NOCAP capture
          tm log [OUTCOME] --capture-id ID TEXT…
          tm log [OUTCOME] -i IMAGE TEXT…      attach a screenshot (repeatable)
          tm log [OUTCOME] -l TEXT…            add your last command as code
          tm log edit [EVENT_ID]               open SITREP at an entry
          tm log [OUTCOME] -- -TEXT            log text that starts with '-'
Text:     'Title :: details' — the title heads the entry, details follow.
          ```cmd``` anywhere becomes a code block. Use SINGLE quotes when the
          text has backticks: inside double quotes zsh would run the code.
          At a terminal with no text: Title, Command (prefilled with your
          last command in this pane), Details.
Outcomes: {outcomes}   (shortcuts: f p s; default info)
Examples: tm log "SMB signing disabled"
          tm log f 'EDB 50640 broken :: ```python3 50640.py``` needs a project'
          tm done "Root via cap_setuid :: proof.txt captured" -l
          tm log p "hash captured, did not crack"
""",
        "done": """tm done — record a completed step (outcome success)

Easiest:  tm → ✓ Step worked
Forms:    tm done TEXT…   ·   tm done -c TEXT…   ·   tm done -i IMAGE TEXT…
          tm done -s TEXT…   (flameshot region capture, attached to the entry)
          tm done -l TEXT…   (your last command becomes the code block)
Text:     'Title :: details' (see tm log --help)
Example:  tm done "Shell as app via CVE-2021-43857"
""",
        "fail": """tm fail — record a dead end or failed attempt (outcome failed)

Easiest:  tm → ✗ Failed
Forms:    tm fail TEXT…   ·   tm fail -c TEXT…   ·   tm fail -l TEXT…
Why:      AARs and reports are mostly about the detours; log them as you go.
Example:  tm fail "feroxbuster on Vue SPA: only static chunks"
""",
        "access": f"""tm access — record access you gained, in one undoable step

Easiest:  tm → ★ Got access
Forms:    tm access [LEVEL] [PRINCIPAL] [HOW…] [--via SERVICE] [--cred CID[:LEVEL]] [-c] [-s]
Levels:   {_words([value for value in ACCESS_LEVELS if value != "none"])}
          (shortcuts: auth, shell → user, root → admin, sys, dom)
Effect:   success entry "Access: LEVEL as PRINCIPAL via SERVICE (HOW)"; raises
          Access/Principal/Method (never lowers); --cred records the credential
          used (its own access defaults to authenticated, e.g. C001:user for an
          SSH login); -c attaches the latest capture; -s screenshot.
Examples: tm access user app "CVE-2021-43857 RCE" --via "http :8000" --cred C001
          tm access root root "python3.10 cap_setuid"
""",
        "proof": """tm proof — record a flag / proof file (alias: tm flag)

Easiest:  tm → ⚑ Proof / flag
Forms:    tm proof [user|root] [VALUE] [PATH] [--show] [-s | --no-screenshot]
Path:     suggested from OS and Principal (local.txt / proof.txt, Windows Desktop)
Access:   never raised automatically — reading a flag is not a shell; the
          interactive flow asks, scripts get a hint (tm access …)
--show:   types hostname/whoami/ip/cat into a target-shell pane you pick
          (penelope, nc, ssh, evil-winrm…; never a local shell) before the shot
Shot:     offered (default yes) whenever you are at a terminal; -s forces it,
          --no-screenshot skips it; scripts and agents never get one
Examples: tm proof user 9a1d4ff1… /home/<user>/local.txt
          tm flag root 49d89584…            (path defaults to /root/proof.txt)
""",
        "snap": """tm snap — write readable pane logs and copy shell logs now

Forms:    tm snap [TARGET]
Writes:   logs/YYYYMMDD/<pane log>.txt next to each raw pane log, rendered
          from the raw log (progress bars and redraws resolved), including
          panes already closed. Copies matching penelope sessions into
          captures/<target>/shells/ ([integrations] shell_log_dirs).
          Only logged output is used; prefix+S saves an exact capture of one
          pane. tm stop, tm close, and tm evidence do this too.
""",
        "evidence": """tm evidence — everything recorded for a target, in one place

Easiest:  tm → 🗂 Evidence & logs
Forms:    tm evidence [TARGET]   (in the operations session: all targets)
Shows:    SITREP events, the command journal (logs/commands.tsv), readable
          pane logs, penelope logs, NOCAP captures, and screenshots, after
          refreshing readable logs and shell logs. At a terminal, pick any
          item to open it in $PAGER (less -R).
""",
        "notes": """tm notes — choose the notes folder (SITREP root) for new engagements

Easiest:  tm → 📁 Notes folder
Forms:    tm notes                 show the folder and pick another
          tm notes NAME            a folder by name, e.g. tm notes PG
          tm notes PATH            any folder, e.g. tm notes ~/notes/OSCP
          tm notes none            keep SITREP inside each engagement
          tm notes move [ENG] [FOLDER]   relocate an engagement's notes
How:      sets [paths] sitrep_root in config.toml. Each engagement remembers
          its own folder, so switching never hides or moves existing work.
Example:  tm notes PG   then   tm init Fractal
          → …/Engagements/PG/Fractal/SITREP.md
""",
        "shell-init": """tacmux shell-init zsh — the command journal hook

Add to ~/.zshrc:   eval "$(tacmux shell-init zsh)"
Records each command in TACMUX sessions to <engagement>/logs/commands.tsv:
epoch, seconds, exit, target, pane, cwd, command. A command typed with a
leading space is skipped; TACMUX_NO_AUTOLOG=1 disables it. zsh only.
""",
        "close": """tm close — guided close-out, then stop

Easiest:  tm → ⏹ Close out
Forms:    tm close [TARGET | --engagement] [--yes] [--no-stop]
Target:   checklist (Access, open TODO, cleanup release gate, proof, confirmed
          credential — Enter fixes a line), Status, optional final summary,
          snapshots + shell logs, then stop. Panes still running programs
          (penelope, nc, claude) need confirmation.
Engagement: overview, cleanup gate, snapshot every live session, stop other
          targets, then OPS, then the session running the command.
--yes:    no prompts (status complete, stops even busy sessions and says so)
""",
        "history": f"""tm history — show Operations Log entries, newest first

Forms:    tm history [TARGET] [--outcome OUTCOME]
Outcomes: {outcomes}
Example:  tm history --outcome failed
""",
        "undo": """tm undo — revert the most recent TACMUX change to SITREP

Shows what will be reverted and asks first. Refuses when SITREP was edited
outside TACMUX afterwards (Obsidian or $EDITOR), so manual work is never lost.
Refuses if another TACMUX command changes undo history during confirmation.
Target add/rename/delete start a new undo history; directory changes cannot
be undone. Only subsequent SITREP-only changes are undoable.
Images copied for an undone entry stay on disk; their paths are printed.
Forms:    tm undo   ·   tm undo --yes   (scripts and agents; no prompt)
Example:  tm done "root shell"   (logged on the wrong target)  →  tm undo
""",
        "creds": f"""tm creds — credentials and confirmed access

Easiest:  tm → 🔑 Found credential / 🔑 Credential works
Forms:    tm creds                              list (secrets shown)
          tm creds view [ID]                    full record
          tm creds add [password|hash] [USER:SECRET]
          tm creds confirm [ID] [TARGET…] [ACCESS] [SERVICE] [NOTES…]
Access:   {_words([value for value in ACCESS_LEVELS if value != "none"])}
          (shortcuts: auth → authenticated, shell → user, root → admin)
Service:  picked from the target's Ports table, e.g. "http :8000", "smb :445"
Examples: tm creds add password 'admin:admin'
          tm creds confirm C001                 asks targets, access, service
          tm creds confirm C001 WEB01 user "ssh :22"
Interactive add avoids putting the secret in shell history.
""",
        "target": f"""tm target — manage targets

Forms:    tm target add [NAME] [ENDPOINT]           (inside tmux: offers to open it)
          tm target update [TARGET] [FIELD] [VALUE|--clear]
          New IP after a box revert: tm target update TARGET endpoint IP from
          OPS snapshots and restarts the session and copies the /etc/hosts line
          tm target export [--all|--none|TARGET…]
          tm target rename [OLD] [NEW]          (session must be stopped)
          tm target delete [TARGET]             (mistakes only; exact name)
Fields:   {fields}
Status:   {statuses}
Access:   {access}
Examples: tm target update access               asks the value
          tm target update WEB01 status complete
          tm target update hostnames "levram.pg"
""",
        "todo": """tm todo — planned work (Markdown checklist in SITREP)

Forms:    tm todo · tm todo add [TEXT…] · tm todo done [ID] · tm todo reopen [ID]
Example:  tm todo add "Enumerate SMB shares"
""",
        "cleanup": """tm cleanup — end-of-engagement obligations (release gate)

Forms:    tm cleanup · tm cleanup add [TEXT…] · tm cleanup done [ID]
          tm cleanup reopen [ID]
Example:  tm cleanup add "Remove /tmp/linpeas.sh from WEB01"
Mark items done only after verification.
""",
        "ports": """tm ports — normalized port inventory

Forms:    tm ports [TARGET]
          tm ports add [TARGET] [FILE]          or pipe Nmap normal output
Example:  nmap -sCV -p- "$TARGET" | tm ports add
""",
        "status": """tm status — target details, ports, credentials, tasks, recent log

Forms:    tm status [TARGET]   (engagement overview from the ops session)
""",
        "sitrep": """tm sitrep — open SITREP in $EDITOR, optionally at a section

Forms:    tm sitrep [context|targets|credentials|todo|cleanup|log|TARGET]
          tm sitrep sync                        upgrade, validate, repair
""",
        "init": """tm init — create or open an engagement

Forms:    tm init [NAME]
At a terminal it offers to add the first target and, inside tmux, to open
that target's session, so a new box is one command.
""",
        "switch": """tm switch — pick an engagement operations session or target session

Forms:    tm switch   (Prefix+E opens it as a popup)
""",
        "menu": """tm menu — the action palette

Opens a fuzzy list of everything you can record here plus every session.
Type a few letters (fail, cred, cleanup, a target name) and press Enter.
Bare `tm` opens it inside TACMUX sessions; Prefix+M opens it as a popup.
""",
        "stop": """tm stop — stop a target or operations session

Forms:    tm stop [TARGET]
""",
        "discover": """tm discover — reviewed host identification

Forms:    tm discover [nmap|hosts|netexec] [CIDR|FILE]
Candidates open in $EDITOR for review before any target is created, so run it
from a terminal: paste hosts into the editor or pass a FILE (no piping).
""",
        "health": """tm health — check required and optional tools and SITREP health
""",
        "version": """tm version — print the TACMUX version
""",
    }


def command_help(command: str) -> str:
    sections = _sections()
    sections["flag"] = sections["proof"]
    return sections.get(command, USAGE)


def known_help_topics() -> tuple[str, ...]:
    return (*_sections(), "flag")


def wants_help(arguments: list[str] | tuple[str, ...]) -> bool:
    """True for `CMD -h|--help` (before any '--') or exactly `CMD help`."""
    for value in arguments:
        if value == "--":
            return False
        if value in HELP_FLAGS:
            return True
    # A bare "help" asks for help; "help desk …" is ordinary log text.
    return list(arguments) == ["help"]
