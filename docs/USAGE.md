# TACMUX usage

## Workspace modes

TACMUX starts in flat mode. Each target is a direct child of `TACMUX_WORKSPACE`:

```bash
tacmux engagement clear
tacmux start 10.10.10.5
# ~/workspace/10.10.10.5/
```

For a multi-host assessment, select one engagement before starting targets:

```bash
tacmux engagement acme-internal
tacmux engagement                 # prints acme-internal
tacmux start 10.10.10.5
# ~/workspace/acme-internal/targets/10.10.10.5/
```

The selection is persisted in `~/.config/tacmux/engagementrc`. It affects future CLI commands, not already-running sessions. Run `tacmux engagement clear` when you want new operations to use flat mode again.

Selecting an engagement creates:

- `ENGAGEMENT.md` for authorization, scope, rules, objectives, and targets.
- `notes/activity.md`, `notes/attack-path.md`, and `notes/payloads.md`.
- `findings/` and `targets/` containers.

TACMUX deliberately does not create every possible consulting folder. Add `Admin`, `Deliverables`, `Retest`, wireless evidence, or tool-specific scan directories when scope calls for them.

## Start a target

```bash
tacmux start 10.10.10.5              # logged target session
tacmux start -n 10.10.10.5           # no automatic logging
tacmux start -a 10.10.10.5           # launch AutoRecon
tacmux start -a 10.10.10.0/24        # CIDR workspace: 10.10.10.0-24
tacmux start -a targets.txt           # AutoRecon targets file
tacmux start -a 10.10.10.5:445       # exports RPORT=445
```

`start` creates the six target directories, creates a detached tmux session, explicitly sets its routing environment, starts the first pane log, then attaches or switches the current client. New windows and panes are logged by tmux hooks.

Use the normalized workspace name with later commands. For example, manage `10.10.10.0/24` as `10.10.10.0-24`.

## Manage sessions

```bash
tacmux list
tacmux pick                         # requires fzf
tacmux status 10.10.10.5
tacmux pause 10.10.10.5             # detach; processes keep running
tacmux resume 10.10.10.5
tacmux rename 10.10.10.5 dc01
tacmux stop dc01                    # workspace remains
tacmux stop dc01 archive            # stop, then create tar.gz
tacmux archive dc01                 # archive an inactive workspace
```

`archive` asks before stopping an attached session and again before deleting the source directory. Archives go to `TACMUX_ARCHIVE_DIR` and are created with a JSON sidecar:

```text
acme_targets_dc01_20260811_150000.tar.gz
acme_targets_dc01_20260811_150000.tar.gz.manifest.json
```

The `tacmux.archive-manifest/v1` document is generated from the completed tarball. It records the UTC creation time, TACMUX version, engagement, target, relative workspace route, tmux session, archive size and SHA-256, entry counts, and each regular file's modification time, size, and SHA-256. Links and their timestamps are recorded without following them outside the archive. Usernames, hostnames, and absolute local paths are intentionally omitted.

To verify the tarball against a manifest when `jq` and GNU `sha256sum` are available:

```bash
manifest=/path/to/archive.tar.gz.manifest.json
jq -r '"\(.archive.sha256)  \(.archive.filename)"' "$manifest" |
  (cd "$(dirname "$manifest")" && sha256sum -c -)
```

The manifest proves integrity relative to the sidecar; it is not a digital signature. Store or transmit both files through the engagement's approved evidence channel.

## Data permissions

TACMUX applies `umask 077` at install time and whenever its workspace or logging runtime creates data. New directories are therefore normally mode `700`; new logs, notes, archives, manifests, and state files are normally mode `600`.

Set `TACMUX_UMASK="027"` in `~/.config/tacmux/tacmux.conf` only for an approved group-shared workflow. Existing files are not recursively changed. Some VM shared folders, network mounts, and non-Unix filesystems ignore or emulate permission bits; use a protected local Linux filesystem for sensitive evidence.

## Logging

An operation pane logs to:

```text
$TACMUX_WORKSPACE/<route>/logs/YYYYMMDD/<window>_<title>_p<index>_<time>.log
```

A pane outside an `op_*` session logs to `TACMUX_LOG_DIR/YYYYMMDD/`. Each pane has at most one active `pipe-pane` logger.

```bash
tacmux log status
tacmux log toggle
tacmux log capture
tacmux logs                       # fzf browser
tacmux logs /path/to/logs
```

`Ctrl+Space T`, `S`, `L`, `H`, and `q` provide the same common controls. `H` intentionally forces a fallback log rather than target routing.

Raw `.log` files are authoritative. The browser renders terminal control sequences without rewriting the file and preserves repeated or sparse lines by default. Press `Alt-k` for an explicitly compact preview.

## Clipboard over SSH

TACMUX configures tmux with `set-clipboard external`; applications cannot write the host clipboard just by emitting terminal escape sequences. Explicit copies use:

```bash
printf '%s' 'text' | tacmux clip
```

Inside tmux this calls `tmux load-buffer -w -`, allowing tmux to forward an OSC 52 copy through SSH to a compatible local terminal. Outside tmux it tries Wayland, X11, macOS, then OSC 52 when SSH is detected.

## Directory helper

Create just the per-target tree in any path:

```bash
tacmux mkop ./evidence/host-a
```

This does not select an engagement or start tmux.

## NOCAP

When NOCAP integration is enabled, TACMUX exports `NOCAP_WORKSPACE` and supplies each session’s relative target route so `cap` output lands in the same tree:

```bash
cap -a nmap -sC -sV "$TARGET"
cap -a whatweb "http://$TARGET"
cap timeline --format md
```

Disable it with `TACMUX_NOCAP_INTEGRATION="false"`.

## Diagnose

```bash
tacmux config
tacmux health
tacmux version
```

The health check treats tmux, zsh, and Python 3 as required; fzf and AutoRecon are optional.
