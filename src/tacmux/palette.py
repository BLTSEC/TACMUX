"""Action palette entries: plain-English choices mapped to direct commands."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Action:
    key: str
    label: str
    description: str
    direct: str
    argv: tuple[str, ...] = ()

    def preview(self) -> str:
        # fzf renders this with printf %b, so "\n" is a literal two-character
        # escape here rather than a newline in the hidden column.
        return f"{self.description}\\n\\nDirect command:\\n  {self.direct}"


ACTIONS: tuple[Action, ...] = (
    Action(
        "fail",
        "✗  Failed / dead end",
        "Record what did not work. AARs and reports are mostly about the "
        "detours, so log them as they happen.",
        "tm fail 'EDB 50640 broken :: needs a project' -l",
        ("fail",),
    ),
    Action(
        "done",
        "✓  Step worked",
        "Record a completed step with outcome success. Prompts: Title, "
        "Command (prefilled with your last command), Details.",
        'tm done "Shell as app :: via CVE-2021-43857" -l',
        ("done",),
    ),
    Action(
        "note",
        "•  Note (choose outcome)",
        "Record an observation; pick info, partial, success, or failed.",
        'tm log "SMB signing disabled"   ·   tm log p "hash did not crack"',
        ("log",),
    ),
    Action(
        "access",
        "★  Got access (shell / login)",
        "Record the access you gained: level, principal, via which service, how, "
        "and the credential used. One undoable entry that raises Access.",
        'tm access user app "CVE-2021-43857 RCE" --via "http :8000"',
        ("access",),
    ),
    Action(
        "proof",
        "⚑  Proof / flag",
        "Record local.txt/proof.txt (or user/root.txt) with a screenshot. Asks "
        "before raising Access: reading a flag is not a shell.",
        "tm proof root <value> /root/proof.txt",
        ("proof",),
    ),
    Action(
        "attach_capture",
        "📎 Attach latest capture to an entry",
        "Attach the latest NOCAP capture on this target's route (from cap … or "
        "cap grab) to an Operations Log entry.",
        'tm done -c "…"   ·   tm done --capture-id ID "…"',
    ),
    Action(
        "screenshot",
        "📷 Screenshot → entry",
        "Select a screen region with flameshot after this menu closes; the PNG "
        "is saved under the target's screenshots/ and attached to the entry.",
        'tm done -s "…"   ·   tm done -i proof.png "…"',
    ),
    Action(
        "cred_add",
        "🔑 Found credential",
        "Store a password or hash (hidden prompt), then optionally record "
        "where it works.",
        "tm creds add password 'user:secret'",
        ("creds", "add"),
    ),
    Action(
        "cred_confirm",
        "🔑 Credential works",
        "Record that a credential works on one or more targets. Services come "
        "from the target's Ports table; access never lowers a stronger level.",
        'tm creds confirm C001 WEB01 user "ssh :22"',
        ("creds", "confirm"),
    ),
    Action(
        "todo_add",
        "☐  Add TODO",
        "Planned work, kept as a Markdown checklist in SITREP.",
        'tm todo add "Enumerate SMB shares"',
        ("todo", "add"),
    ),
    Action(
        "todo_done",
        "☑  Complete TODO",
        "Check off planned work.",
        "tm todo done [ID]",
        ("todo", "done"),
    ),
    Action(
        "cleanup_add",
        "🧹 Add cleanup item",
        "Anything you created on a target: files, accounts, projects, services. "
        "Cleanup is the release gate at the end of the engagement.",
        'tm cleanup add "Remove /tmp/linpeas.sh"',
        ("cleanup", "add"),
    ),
    Action(
        "cleanup_done",
        "🧹 Cleanup done",
        "Mark a cleanup obligation done after verifying it.",
        "tm cleanup done [ID]",
        ("cleanup", "done"),
    ),
    Action(
        "ports",
        "⇣  Import Nmap output",
        "Pick an Nmap normal-output file from the target folder and merge its "
        "ports into SITREP.",
        'nmap -sCV "$TARGET" | tm ports add   ·   tm ports add FILE',
    ),
    Action(
        "hostname",
        "🏷  Add hostname / vhost",
        "Add names to the target's Hostnames and copy the matching "
        "/etc/hosts command to the clipboard.",
        'tm target update hostnames "levram.pg"',
    ),
    Action(
        "field",
        "✎  Edit a target field",
        "Status, Access, Principal, Method/Path, OS, Hostnames, and more.",
        "tm target update [TARGET] [FIELD] [VALUE]",
        ("target", "update"),
    ),
    Action(
        "edit_entry",
        "✎  Edit a log entry",
        "Open SITREP at an Operations Log entry to add notes, captions, or "
        "draft findings.",
        "tm log edit [E001]",
    ),
    Action(
        "undo",
        "↶  Undo last change",
        "Revert the most recent TACMUX change to SITREP. Refuses if SITREP was "
        "edited elsewhere since. Target add/rename/delete start a new undo "
        "history; directory changes cannot be undone.",
        "tm undo",
        ("undo",),
    ),
    Action(
        "evidence",
        "🗂  Evidence & logs",
        "Everything recorded for this target: SITREP entries, the command "
        "journal, readable pane logs (rendered from the raw logs), penelope "
        "logs, captures, screenshots. Refreshes them, then opens any in less.",
        "tm evidence [TARGET]   ·   tm snap (refresh only)",
        ("evidence",),
    ),
    Action(
        "close",
        "⏹  Close out",
        "Checklist (access, TODO, cleanup gate, proof, credentials), status, final "
        "note, snapshots and shell logs, then stop the session. In the operations "
        "session it can close the whole engagement.",
        "tm close [TARGET|--engagement] [--yes] [--no-stop]",
        ("close",),
    ),
    Action(
        "status",
        "ⓘ  Status",
        "Details, ports, confirmed credentials, tasks, and recent entries.",
        "tm status [TARGET]",
        ("status",),
    ),
    Action(
        "history",
        "ⓘ  History",
        "Operations Log, newest first.",
        "tm history [TARGET] [--outcome failed]",
        ("history",),
    ),
    Action(
        "sitrep",
        "ⓘ  Open SITREP",
        "Edit the whole situation report in $EDITOR.",
        "tm sitrep [SECTION]",
        ("sitrep",),
    ),
    Action(
        "context",
        "ⓘ  Engagement context",
        "Scope, rules of engagement, objectives, and reference links.",
        "tm sitrep context",
        ("sitrep", "context"),
    ),
    Action(
        "notes",
        "📁 Notes folder (SITREP root)",
        "Choose where new engagements keep their SITREP, e.g. a course folder "
        "such as Engagements/PG. Existing engagements keep their notes; you "
        "can also move one.",
        "tm notes PG   ·   tm notes move ENG FOLDER",
        ("notes",),
    ),
    Action(
        "target_add",
        "➕ Add target",
        "Create a target folder and its SITREP section.",
        "tm target add NAME ENDPOINT",
        ("target", "add"),
    ),
    Action(
        "discover",
        "🔎 Discover hosts",
        "Reviewed host identification from Nmap, pasted hosts, or NetExec.",
        "tm discover [nmap|hosts|netexec]",
        ("discover",),
    ),
)

ACTION_KEYS = {action.key: action for action in ACTIONS}
SESSION_PREFIX = "session\x1f"
