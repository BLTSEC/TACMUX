# Security policy

## Reporting a vulnerability

Please report security issues through [GitHub private vulnerability reporting](https://github.com/BLTSEC/TACMUX/security/advisories/new). Do not open a public issue for an unpatched vulnerability and do not include client data, credentials, assessment evidence, or other secrets in a report.

Include the affected TACMUX version, operating system, tmux version, reproduction steps, and expected impact. You will receive an acknowledgement as soon as practical.

## Scope and trust model

TACMUX executes local shell and tmux commands as the current user. Treat configuration files, target names, log paths, cloned source, and updates as trusted inputs. Review release changes before installing them on assessment systems.

The clipboard integration uses explicit copy commands and tmux `set-clipboard external`. Automatic pane logging is enabled by default and may capture sensitive output; use `tacmux start -n`, follow engagement data-handling requirements, and protect or securely dispose of workspace data.

TACMUX uses an owner-only `077` umask for newly created data by default. This does not retroactively change existing files and cannot override a filesystem that ignores Unix permission bits. Treat VM shared folders, network mounts, cloud-sync directories, removable media, and exported archive manifests according to the engagement's data-handling requirements.

Archive manifests provide SHA-256 integrity metadata but are not signed attestations. Protect the manifest and archive together using an approved transfer, storage, or signing process when independent authenticity is required.
