# Security policy

## Reporting a vulnerability

Report security issues through [GitHub private vulnerability reporting](https://github.com/BLTSEC/TACMUX/security/advisories/new). Do not open a public issue containing client data, credentials, assessment evidence, or other secrets.

Include the affected TACMUX version, operating system, Python/tmux versions, reproduction steps, and expected impact.

## Authorization and trust model

TACMUX is for authorized security work. It does not determine whether a scope entry, scan, command, or technique is authorized. The operator must verify written authorization, rules of engagement, testing windows, allowed techniques, evidence handling, and retention.

The following inputs are trusted local operator inputs:

- TACMUX configuration and editor selection;
- engagement names, scope, target identity, and evidence references;
- imported v1 directories, Nmap XML, archives, and NOCAP JSON;
- commands and output inside tmux panes.

Treat a workspace copied from another person as untrusted until reviewed. TACMUX previews text and Markdown but does not execute evidence files. Symlinks are skipped by the evidence browser. Archive restore rejects absolute/traversal paths, unsafe links, special entries, multiple roots, collisions, and mismatched target metadata.

## Sensitive data

TACMUX applies an owner-only `077` umask. Newly created directories are normally `0700`; manifests, Markdown, logs, job state, archives, and archive manifests are normally `0600`. Ordinary existing workspace content is not recursively changed; copied v1 imports and restored archives are hardened recursively.

Unix permissions may not be enforced by VM shared folders, FAT filesystems, some network mounts, cloud-sync directories, or removable media. Keep engagement data on an approved encrypted local filesystem or other approved protected volume.

Automatic pane logging is enabled by default and can capture credentials, tokens, personal data, and client evidence. Disable it in the engagement creation form or config when the rules of engagement require that. Stopping the TUI does not stop detached sessions or their logging.

Archive manifests contain SHA-256 integrity metadata, not a digital signature. A party able to replace both archive and sidecar can replace the recorded hashes. Protect or sign both through the approved evidence-transfer process when independent authenticity is required.

## External tools and integrations

- Nmap discovery is optional and limited by TACMUX to `-sn --reason -oX`. It still generates network traffic.
- NOCAP is disabled by default. When enabled, TACMUX invokes only documented JSON read commands and exports workspace context to target sessions; NOCAP has its own trust boundary.
- `$VISUAL` / `$EDITOR` is executed as the current user. Configure only a trusted editor command.
- Explicit clipboard actions may forward data to the local workstation through tmux/OSC 52. Verify the destination before copying sensitive material.

## Destructive operations

Permanent target deletion is intended only for a mistakenly created target. TACMUX requires exact confirmation, containment under the engagement's `targets` directory, a stopped session, and no structured references. It stages the directory before saving the manifest.

Install and uninstall validate paired TACMUX configuration markers before editing shell or tmux files. Uninstall removes only the marked fixed installation path and a command link that resolves into it. Configuration, archives, workspaces, unrelated commands, and malformed configuration blocks are preserved.

Manifest revisions reject stale writes from a second TACMUX process instead of silently overwriting newer structured state. Refresh the engagement and repeat the intended change after such a conflict.
