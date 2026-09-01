# Security policy

## Reporting a vulnerability

Report security issues through [GitHub private vulnerability reporting](https://github.com/BLTSEC/TACMUX/security/advisories/new). Do not open a public issue containing client data, credentials, assessment evidence, or other secrets.

Include the affected TACMUX version, operating system, Python/tmux versions, reproduction steps, and expected impact.

## Authorization and trust model

TACMUX is for authorized security work. It records authorization metadata and warns before starting work outside a configured UTC window, but the operator remains the authority. Verify written authorization, rules of engagement, allowed techniques, evidence handling, and retention.

The following inputs are trusted local operator inputs:

- TACMUX configuration and editor selection;
- engagement names, scope, target identity, and evidence references;
- imported Nmap XML, restored archives, and NOCAP JSON;
- commands and output inside tmux panes.

Treat a workspace copied from another person as untrusted until reviewed. TACMUX previews text and Markdown but does not execute evidence files. Symlinks are skipped by the evidence browser and refused by editor/pager handoff. Manifest and authored-file reads require regular non-linked paths; generated documents, discovery artifacts, deletion staging, and exports refuse linked parent directories. Archive restore rejects absolute/traversal paths, unsafe links, special entries, multiple roots, collisions, and mismatched target metadata.

## Sensitive data

TACMUX applies an owner-only `077` umask. Newly created directories are normally `0700`; manifests, Markdown, logs, job state, archives, and archive manifests are normally `0600`. Ordinary existing workspace content is not recursively changed; restored archives are hardened recursively.

Unix permissions may not be enforced by VM shared folders, FAT filesystems, some network mounts, cloud-sync directories, or removable media. Keep engagement data on an approved encrypted local filesystem or other approved protected volume.

Automatic pane logging is enabled for TACMUX-owned sessions by default and can capture credentials, tokens, personal data, and client evidence. Non-TACMUX sessions are ignored unless `behavior.log_outside_tacmux = true`. Disable logging in the engagement form or config when required. Stopping the TUI does not stop detached sessions or their logging.
Pane-provided TACMUX log directories must resolve inside the configured workspace.

Structured access records warn when the principal, authority, or method resembles
an NTLM pair, private key, or long encoded secret. This is a narrow warning, not a
secret scanner or a hard block. Notes, evidence, imported files, and pane logs may
legitimately contain sensitive material and are not inspected or rewritten.

Handoff exports are owner-only Markdown snapshots but may aggregate all of that
sensitive text into one convenient file. Compact exports index evidence;
evidence-rich exports also embed bounded readable evidence. TACMUX does not
redact either profile. Treat exports as client evidence and use an approved
transfer and retention process.

Archive manifests contain SHA-256 integrity metadata, not a digital signature. A party able to replace both archive and sidecar can replace the recorded hashes. Protect or sign both through the approved evidence-transfer process when independent authenticity is required.

## External tools and integrations

- Nmap is optional. Host-only jobs use `-sn --reason`; enhanced jobs may then
  use `-Pn -p- --open --reason` and `-Pn -sV --open -p <discovered-ports>`.
  Fast pace adds only `-T4`. Later-stage IPs are revalidated against the
  selected ready network scope and exclusions, commands never use a shell, and
  domain scope is never resolved or scanned. Enhanced discovery is noisier and
  must be permitted by the rules of engagement.
- NOCAP is disabled by default. When enabled, TACMUX invokes only documented JSON read commands and exports workspace context to target sessions; NOCAP has its own trust boundary.
- `$VISUAL` / `$EDITOR` is executed as the current user. Configure only a trusted editor command.
- Explicit clipboard actions, including `tacmux clip`, may forward data to the local workstation through tmux, desktop clipboard tools, or OSC 52. Verify the destination before copying sensitive material.

## Destructive operations

Permanent target deletion is intended only for a mistakenly created target. TACMUX requires exact confirmation, containment under the engagement's `targets` directory, a stopped session, and no structured references. It stages the directory before saving the manifest.

Install and uninstall validate paired TACMUX configuration markers before editing tmux files. Uninstall removes only the marked fixed installation path and a command link that resolves into it. Configuration, archives, workspaces, unrelated commands, and malformed configuration blocks are preserved.

Manifest revisions reject stale writes from a second TACMUX process instead of silently overwriting newer structured state. Refresh the engagement and repeat the intended change after such a conflict.

Inside tmux, pane ownership metadata is authoritative for contextual CLI
commands. TACMUX rejects inherited engagement or target variables that disagree
with the current pane so a stale shell cannot write to another engagement.
