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
  tm log [OUTCOME] TEXT          Operations Log entry (default outcome: info)
  tm fail TEXT                   Dead end or failed attempt (log failed)
  tm done TEXT                   Completed step (log success)
  tm creds [add|confirm|view]    Credentials and where they work
  tm todo [add|done|reopen]      Planned work
  tm cleanup [add|done|reopen]   End-of-engagement obligations
  tm ports add [TARGET] [FILE]   Import Nmap normal output
  tm undo                        Revert the last TACMUX change to SITREP

Inspect:
  tm status [TARGET]             Target or engagement status
  tm history [TARGET] [--outcome O]
  tm sitrep [SECTION|sync]       Edit or repair SITREP

Targets and sessions:
  tm init [NAME]                 Create or open an engagement
  tm target add|update|export|rename|delete
  tm discover [nmap|hosts|netexec]
  tm switch                      Session switcher (Prefix+E)
  tm stop [TARGET]               Stop a target or operations session

Maintenance:
  tm health · tm version · tm help COMMAND

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
          tm log edit [EVENT_ID]               open SITREP at an entry
          tm log [OUTCOME] -- -TEXT            log text that starts with '-'
Outcomes: {outcomes}   (shortcuts: f p s; default info)
Examples: tm log "SMB signing disabled"
          tm log f "EDB 50640 broken: needs a project"
          tm log p "hash captured, did not crack"
""",
        "done": """tm done — record a completed step (outcome success)

Easiest:  tm → ✓ Step worked
Forms:    tm done TEXT…   ·   tm done -c TEXT…   ·   tm done -i IMAGE TEXT…
Example:  tm done "Shell as app via CVE-2021-43857"
""",
        "fail": """tm fail — record a dead end or failed attempt (outcome failed)

Easiest:  tm → ✗ Failed
Forms:    tm fail TEXT…   ·   tm fail -c TEXT…
Why:      AARs and reports are mostly about the detours; log them as you go.
Example:  tm fail "feroxbuster on Vue SPA: only static chunks"
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

Forms:    tm target add [NAME] [ENDPOINT]
          tm target update [TARGET] [FIELD] [VALUE|--clear]
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
Then:     tm target add NAME ENDPOINT · tm switch
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
Candidates open in $EDITOR for review before any target is created.
""",
        "health": """tm health — check required and optional tools and SITREP health
""",
        "version": """tm version — print the TACMUX version
""",
    }


def command_help(command: str) -> str:
    sections = _sections()
    return sections.get(command, USAGE)


def known_help_topics() -> tuple[str, ...]:
    return tuple(_sections())


def wants_help(arguments: list[str] | tuple[str, ...]) -> bool:
    """True when arguments after the command ask for help before any '--'."""
    for value in arguments:
        if value == "--":
            return False
        if value in HELP_FLAGS:
            return True
    return bool(arguments) and arguments[0] == "help"
