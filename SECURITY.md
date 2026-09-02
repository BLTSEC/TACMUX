# Security policy

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/BLTSEC/TACMUX/security/advisories/new). Never put client data, credentials, or assessment evidence in a public issue.

Include the TACMUX version, operating system, Python/tmux versions, reproduction steps, and expected impact.

## Authorization boundary

TACMUX is an operator aid, not an authorization system. Version 3 deliberately does not model scope, exclusions, testing windows, or rules of engagement. Verify written authorization before running discovery or commands from TACMUX sessions.

Foreground Nmap discovery accepts only a literal IP or CIDR and constructs a fixed argument vector without a shell. Candidate review does not make an address authorized.

## Sensitive data

TACMUX can store raw passwords and hashes in `SITREP.md`, generated credential files, and operator-supplied SSH keys under `credentials/keys/`. `tacmux creds` intentionally prints password and hash values. Generated `targets.txt`, pane logs, and NOCAP captures can also contain sensitive client information.

New engagement directories are `0700` and new TACMUX files are `0600` where supported. Shared folders, FAT filesystems, network mounts, removable media, and cloud-sync directories may ignore or broaden those permissions. Use an approved encrypted evidence location and protect backups separately.

Interactive credential entry avoids terminal echo, but direct credentials remain in shell history and pane logs. Pause logging or use the prompt when required by the engagement's evidence policy.

## Filesystem and Markdown trust

- Engagement and target names are single path components.
- TACMUX refuses linked engagement control files, target directories, input files, and log destinations.
- Writes use an engagement lock, owner-only temporary file, `fsync`, and atomic replacement.
- Managed Markdown tables have exact columns and paired markers. Malformed tables fail closed instead of being rewritten.
- `$VISUAL` or `$EDITOR` runs as the current user and is trusted configuration.
- Data manually placed inside a managed table is parsed as operator input, never executed.

Treat an engagement directory received from another person as untrusted until reviewed.

## Sessions and integrations

Inside tmux, pane options identify the engagement and target. Stale inherited environment variables that disagree with pane metadata are rejected. Session names are presentation only and are not trusted as filesystem paths.

Automatic logging is limited to TACMUX-owned sessions. Prefix+`T`, Prefix+`S`, credential display, clipboard forwarding, NOCAP, and external tools are explicit operator actions.

NOCAP owns its capture metadata and command execution boundary. TACMUX exports an engagement root plus a contained route prefix; it does not parse or rewrite NOCAP records.

## Destructive operations

Target deletion is only for mistaken targets. TACMUX requires a stopped session, exact typed confirmation, containment below `targets/`, and no structured history, port records, tasks, cleanup, confirmed credential references, or NOCAP captures. It stages the target directory before updating SITREP and reports any staged data that could not be removed.

Uninstall removes only a marked TACMUX installation and matching command link. Configuration and engagement directories are preserved. Paired TACMUX markers are validated before editing `~/.tmux.conf` or `~/.zshrc`; linked shell configuration files are left untouched.
