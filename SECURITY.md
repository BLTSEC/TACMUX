# Security policy

## Reporting a vulnerability

Please report security issues through [GitHub private vulnerability reporting](https://github.com/BLTSEC/TACMUX/security/advisories/new). Do not open a public issue for an unpatched vulnerability and do not include client data, credentials, assessment evidence, or other secrets in a report.

Include the affected TACMUX version, operating system, tmux version, reproduction steps, and expected impact. You will receive an acknowledgement as soon as practical.

## Scope and trust model

TACMUX executes local shell and tmux commands as the current user. Treat configuration files, target names, log paths, cloned source, and updates as trusted inputs. Review release changes before installing them on assessment systems.

The clipboard integration uses explicit copy commands and tmux `set-clipboard external`. Automatic pane logging is enabled by default and may capture sensitive output; use `tacmux start -n`, follow engagement data-handling requirements, and protect or securely dispose of workspace data.
