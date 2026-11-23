# Workspace, SITREP, and evidence

What TACMUX writes, where, and how to attach evidence. Back to the
[README](../README.md) · [operator guide](USAGE.md).

## SITREP

`SITREP.md` keeps current state first (Targets, Credentials, TODO, Cleanup),
then the Operations Log, where each entry is a callout colored by outcome:

```text
> [!success] Shell as svc_build
> `E003` · `2026-11-23 14:14:49Z` · `ORCHID`
>
> ```bash
> curl -s http://192.0.2.10:8080/console/run -d 'job=id'
> ```
>
> Command injection in the job runner; penelope caught the shell.
```

`SITREP.md` is plain Markdown: edit it in Obsidian or `$EDITOR`; checked boxes
and prose between markers are understood. Rename targets with
`tm target rename`, not by editing headings alone.

## Evidence

- `tm done -c "…"` attaches the latest NOCAP capture on this target's route.
  Use `--capture-id ID` for an earlier one (`cap timeline` lists them).
- `-i proof.png` attaches screenshots.
- `tm creds view C001` shows a full credential. Displaying secrets puts them
  in pane logs.
- `tm done -s`, `tm proof`, and the palette take flameshot region screenshots
  and attach them.

## Logging

Logging is automatic; `tm evidence` shows all of it:

| Layer | When | Where |
|---|---|---|
| Raw pane log | always (Prefix+T toggles) | `logs/YYYYMMDD/*.log` |
| Readable pane log | `tm snap`/`stop`/`close`/`evidence` | same name, `.txt` (rendered from the raw log; closed panes too) |
| Command journal | every command (zsh hook) | `logs/commands.tsv` |
| Penelope sessions | `tm access`/`proof`/`snap`/`stop`/`close` | `captures/<target>/shells/penelope/` |
| Exact capture | Prefix+S | `logs/YYYYMMDD/scrollback_*.log` |

NOCAP users: `cap grab` reads the last command from your history file, so set
`setopt INC_APPEND_HISTORY_TIME` in `~/.zshrc`.

## Notes folders (external SITREP)

Keep each SITREP in Obsidian or another notes tree, one folder per course or
client:

```bash
tm notes ~/notes/engagements/Lab    # later, by name: tm notes Lab
tm init Orchid 192.0.2.10           # → ~/notes/engagements/Lab/Orchid/SITREP.md
tm notes ~/notes/engagements/HTB    # next course; Lab engagements keep working
tm notes move Orchid HTB            # optional: relocate a note folder (+ images)
```

`tm notes` sets `[paths] sitrep_root` in `~/.config/tacmux/config.toml`. Each
engagement remembers its own folder, so switching never hides or moves existing
work. TACMUX, Obsidian, and `$EDITOR` edit the same file; there is no sync
process or API.
