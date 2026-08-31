# TACMUX operator guide

## Operating model

An engagement is the authorization, reporting, retention, and evidence boundary. External and internal networks stay in the same engagement when they belong to the same assessment. Create separate engagements for a real client operation, HTB, OffSec, PNPT, or another academy so their context and evidence cannot be confused.

TACMUX keeps one `tacmux.engagement/v2` JSON manifest as durable state. The TUI is transient: closing it does not stop detached tmux sessions or discovery jobs.

## Create and front-load scope

Run `tacmux`, press `n`, and supply:

- **Client, Lab, or Platform:** the customer, organization, private lab,
  certification environment, or training platform that owns the work.
- **Engagement Name:** a recognizable assessment, project, lab, or exercise name.
- **Assessment Type:** External, Internal, External + Internal, or Single-machine Lab.
- **External/Internal scope:** optional IPs, CIDRs, or domain patterns already known. Use `Label=value` when a friendly label helps.
- **Internal scope reachability:** whether the internal scope is reachable now
  through a direct, on-site, or VPN connection, or requires later access and a
  pivot.
- **Pane logging:** per-engagement default.

Known `/32` hosts, networks, and web domains can be entered before testing. Scope groups are intentionally limited to **external** and **internal**.

## Cockpit workflow

The five tabs answer different operator questions:

| Tab | Operator question |
|---|---|
| Targets | What host am I working on, is its session live, and what access is confirmed? |
| Scope | What may I touch, what is excluded, and what discovery jobs/results need review? |
| Records | What access, activity, findings, attack paths, and cleanup obligations are recorded? |
| Situation | What does the network look like, and what confirmed chain has been demonstrated? |
| Documents | Where are the narrative, findings, notes, logs, and evidence? |

Press `a` for the contextual Actions menu. Press `Ctrl+P` for Textual's Command
Palette (fuzzy command search). The palette exposes the same actions as the
visible workflow and does not require fzf.

## Scope and pivots

Each address is stored with a scope-entry ID, not as a globally unique host key. That permits:

- a dual-homed host with one external and one internal address;
- the same RFC1918 address in two distinct scope entries;
- multiple networks accessed through one pivot;
- an internal range that begins unavailable.

Each scope entry may carry exclusions inside its own network or domain. This is
important when two engagements or routes reuse the same RFC1918 space. TACMUX
enforces exclusions in manifest validation, import review, and Nmap
`--exclude`. Select overlapping network entries in separate discovery jobs so
an address is never assigned by guesswork.

Domain entries accept exact names (`acme.test`) and strict wildcards
(`*.acme.test`). A wildcard matches subdomains, not the apex. TACMUX never
resolves or scans a domain entry. Import a bare-hostname list through discovery.
Hostname-only targets must match declared domain scope when domain entries
exist; aliases on an IP-backed target remain visible even when they are not
domain scoped.

After a foothold creates an approved route:

1. Open **Scope**.
2. Highlight the internal scope and press Enter or `a`.
3. Set availability to **Reachable now** and select the target through which it
   is reachable.
4. Refresh the Situation view.

TACMUX records the route relationship; it does not configure VPNs, SOCKS proxies, Ligolo, SSH forwarding, or firewall rules.

## Host discovery and reconciliation

Press `d` and choose one of three inputs:

1. **Run Nmap host discovery (detached)** — launches only:

   ```text
   nmap -sn --reason [--exclude <declared-carve-outs>] -oX <job>/results.xml <selected-ready-scope...>
   ```

2. **Import XML or pasted hosts** — accepts Nmap XML, `IP [hostname]`, or one bare hostname per line.
3. **Review a completed detached scan** — opens a successful job's XML.

Highlight a job and press Enter to import a successful result or cancel an active scan. Imported jobs remain visible and are marked as imported.

Every candidate must be reviewed:

- **Add** creates a stable target and evidence directory.
- **Merge** adds a scope-qualified address/hostname to an existing host. Press `m` to select the intended target when a second interface was discovered.
- **Ignore** makes no target change.

TACMUX defaults accepted results to detached target sessions. Disable that checkbox when sessions would create noise. An address matching more than one selected scope entry is ignored rather than guessed; re-import it with only the intended scope selected or add it explicitly through **Edit target identity**.

Out-of-scope, partially matched, and overlapping-scope discovery results are
locked to **Ignore**. Discovery never creates an addressless target. Manual and
legacy-imported targets may be intentionally unresolved while their identity is
still being established; add a scope-qualified address or hostname later through
**Edit target identity**.

Discovered hostnames are retained as aliases, but the accepted scope-qualified
IP is the initial primary endpoint exported as `TARGET`. A hostname-only
candidate is accepted only through selected domain scope.

## Target work

Highlight a target and press Enter. TACMUX creates the tmux session if necessary, exports stable engagement/target context, starts context-aware logging when enabled, and attaches or switches the current client.

Target actions include:

- start/attach or stop session;
- edit display name, scope-qualified addresses, hostnames, and primary endpoint;
- edit `NOTES.md` through `$VISUAL`, `$EDITOR`, or `vi`;
- inspect imported services;
- record confirmed access or activity;
- create and edit a finding;
- record an item that must be removed during cleanup;
- view a NOCAP timeline when enabled;
- create a verified target archive;
- permanently delete an unreferenced mistaken target.

Display-name changes do not rename the stable target directory or tmux identity. Starting or attaching refreshes session context; panes created afterward inherit the current primary endpoint as `TARGET`.

The optional engagement operations session starts in the engagement root. Stop-all cancels active discovery jobs and stops target and operations sessions before archival.

## Recording activity, access, and findings

### Activity

Use activity for concise, relevant events—not every command. Select one result:

- **Confirmed:** the described outcome was demonstrated.
- **Failed:** the attempt conclusively failed.
- **No Result:** the attempt did not establish an outcome.

Attach a relative evidence path when one exists. Failed and no-result records remain useful in the timeline but cannot become attack-path steps.

### Access

Record a principal, authority/realm, method, target, evidence, and the strongest demonstrated level:

1. **Authenticated** — credentials/session accepted; no command execution implied.
2. **User Execution** — code/command execution in a non-administrative context.
3. **Administrative Execution** — administrative execution demonstrated.
4. **Privileged Execution** — the platform's highest relevant execution context demonstrated.

Do not promote authenticated SMB access to execution merely because credentials work.

### Findings

Create a finding only after selecting affected targets. TACMUX records title, severity, state, targets, and evidence, then opens a Markdown narrative with Summary, Evidence, Impact, and Recommendation sections.

Use **Draft** when validation or reporting language remains incomplete, **Confirmed** when evidence supports it, and **Closed** for a resolved/retested record. Draft findings cannot be attack-path steps.

Open **Records** to correct or delete access, activity, finding, attack-path, and cleanup records. A record used by an attack path must be removed from that path first. Scope entries can likewise be fully edited or deleted when no target address uses them.

### Cleanup

Record files, accounts, services, scheduled tasks, or configuration changes left
on a target. Mark an item removed only after verifying cleanup. Both outstanding
and removed cleanup records retain their target reference; remove the cleanup
record itself before deleting a mistaken target.

### Service inventory

TACMUX never launches a port or version scan. Run an authorized scan yourself,
for example `nmap -sV -oX services.xml <in-scope-hosts>`, then import that XML
through discovery. Observed `open` and UDP `open|filtered` services attach to
scope-qualified targets during the normal Add/Merge/Ignore review. External XML
is copied into `.tacmux/imports/` only after a confirmed import so the service
snapshot retains provenance.

## Building an attack path

Network topology and attack path are separate views:

- topology maps external/internal scope, hosts, interfaces, access level, pivots,
  and unresolved or hostname-only targets not yet assigned to an address;
- an attack path is an ordered sequence of demonstrated findings, access records, and confirmed activities.

Open **Situation**, press `a`, and choose **Build confirmed attack path**. Press Enter on eligible records to add them. In the chosen list, Delete removes a step and `Ctrl+Up` / `Ctrl+Down` changes order. Optional one-line step notes explain how each fact advances the chain.

Each step may only reference structured confirmed state. The generated `notes/attack-path.md` and `SITREP.md` therefore cannot accidentally promote a failed responder attempt into a demonstrated compromise.

## Authorization window and engagement lifecycle

From the engagement picker press `a` and choose **Edit engagement details** to
record the authorizing party, reference, emergency contact, and explicit UTC
start/end times. Starting a target, operations session, detached discovery, or
an import that creates sessions outside that window requires confirmation. The
warning never overrides operator authority.

Close an engagement after stopping target/operations sessions and discovery
jobs. A closed engagement remains reviewable and archivable, but blocks new
targets, sessions, discovery commits, and record creation until reopened. The
close confirmation reports outstanding cleanup items.

## Capture from a working pane

TACMUX target and operations sessions export stable context, so a small CLI can
capture facts without leaving the shell:

```text
tacmux note "shell as svc_deploy"
tacmux activity confirmed --evidence targets/T0002-svc/recon/share.txt "Readable deployment share"
tacmux activity no-result "LLMNR produced no usable authentication"
tacmux sitrep
```

`--evidence` must appear immediately after the activity result. Notes append to
the current target's `NOTES.md`, or the engagement operator notes in an
operations session. Structured activity appears in the cockpit automatically;
press `r` after appending a note if its document preview is already open.

## ACME external-to-internal example

This example uses documentation-only addresses and mirrors a realistic flow without performing network actions.

### 1. Start with known scope

Create:

```text
Client, Lab, or Platform: ACME
Engagement Name: 2026 External and Internal Assessment
Assessment Type: External + Internal
External: Internet Perimeter=198.51.100.0/24
Internal: Corporate LAN=10.77.10.0/24
Internal scope reachability: Not reachable yet (requires access or pivot)
```

Run detached discovery against the external entry. Review two results:

```text
ADD  mail.acme.test  198.51.100.25
ADD  vpn.acme.test   198.51.100.40
```

TACMUX creates `T0001` and `T0002` plus detached sessions.

### 2. Record initial access

On MAIL, preserve proof under `exploitation/`, then create:

```text
Finding F0001: Initial access control weakness
Severity: High
State: Confirmed
Targets: MAIL

Access AR0001:
Principal: operator
Authority: ACME
Method: confirmed initial access
Level: User Execution

Activity A0001 (Confirmed):
Established the approved route from MAIL to the corporate LAN
```

Update **Corporate LAN** to Reachable now via MAIL. The terminal topology now
reads conceptually:

```text
EXTERNAL
└─ Internet Perimeter: 198.51.100.0/24
  └─ MAIL [T0001] — User Execution (198.51.100.25)
INTERNAL
└─ Corporate LAN: 10.77.10.0/24 via MAIL
  └─ No identified hosts
```

### 3. Identify internal hosts

Run discovery on Corporate LAN through the operator-established route, or import externally produced XML. Review:

```text
MERGE  mail.acme.test      10.77.10.5   -> MAIL
ADD    svc.acme.test       10.77.10.20  -> SVC
ADD    passback.acme.test  10.77.10.30  -> PASSBACK
ADD    tpm-dc.acme.test    10.77.10.10  -> TPM-DC
```

MAIL is now correctly dual-homed. The other hosts receive independent evidence/session contexts.

### 4. Preserve negative and positive results accurately

Record:

```text
Activity A0002 (No Result):
LLMNR responder attempt produced no usable authentication

Finding F0002 (Confirmed, Medium):
Readable deployment share exposed configuration material
Targets: SVC, PASSBACK

Access AR0002:
ACME\svc_deploy authenticated to PASSBACK through SMB
Level: Authenticated
```

AR0002 does not claim command execution. A0002 remains visible in activity but is not eligible for an attack path.

### 5. Order the demonstrated chain

Create **External foothold to internal authenticated access** in this order:

1. F0001 — validated initial-access weakness.
2. AR0001 — user execution on MAIL.
3. A0001 — approved internal route established.
4. F0002 — readable deployment share.
5. AR0002 — authenticated SMB access on PASSBACK.

The topology still shows all identified systems, including TPM-DC. The attack path shows only the demonstrated chain. No administrative or privileged compromise is inferred.

The repository includes this state as `tests/fixtures/recap_sanitized.json`; it is offline, uses reserved mock addresses, and contains no credentials or live-lab dependency.

## Documents and evidence

The Documents tab indexes evidence when opened (or refreshed) and previews:

- editable Markdown;
- generated Markdown;
- UTF-8 terminal evidence and logs, with control sequences cleaned;
- binary metadata and a SHA-256 for binary files up to 2 MiB.

Text previews stop at 256 KiB. Press Enter on read-only text or choose **View
full file in pager** from `a` to open the complete file through `$PAGER`,
`less -SR`, or `more`. Captured terminal output is cleaned for carriage returns,
backspaces, and common cursor redraws. Evidence indexing stops at 500 files or a
bounded directory-scan budget; use ordinary filesystem tools for larger
collections. Generated Markdown is changed through its structured TACMUX record,
not edited directly.

## Archives, restore, and permanent deletion

Target and engagement archives are private `.tar.gz` files with adjacent `.manifest.json` documents. Creation verifies the completed archive immediately. `tacmux archive verify FILE` checks archive size, SHA-256, member hashes, paths, links, and root structure.

Restore refuses an existing destination and extracts through a private staging
directory. Engagement restores validate the embedded manifest and identity;
target restores validate archived metadata against the current engagement.
Press `r` in the engagement picker to restore an engagement archive, including
when the picker is empty. In an open engagement, use **Restore verified archive**
from the Command Palette to restore a missing target or another engagement.

Permanent target deletion is deliberately stricter than archive:

- the tmux target session must be stopped;
- no scope pivot, access, activity, finding, or cleanup record may reference the target;
- the exact displayed confirmation must be typed;
- the target directory is staged, the manifest is saved, and only then are files removed.

Permanent engagement deletion is available from the engagement picker through
`a`. It removes the complete live engagement directory, including scope,
targets, evidence, notes, findings, and completed discovery jobs. TACMUX refuses
while target, operations, or discovery work is active and requires
`DELETE E-<stable-id>` exactly. It does not stop sessions, cancel jobs, create an
archive automatically, or remove verified archives stored outside the live
workspace. Choose **Create verified archive** from the same Actions menu first
when a recovery copy is required.

## v1 import

From the engagement picker press `i`. Import is copy-only: v1 target evidence is copied into stable v2 target directories and original notes/findings are retained under `legacy-import/`. The source is never converted in place.

Review imported targets, add scope-qualified addresses, and curate structured access/activity/findings manually. Import does not guess security facts from free-form notes.

## NOCAP

NOCAP remains optional and separate. With `[nocap] enabled = true`, target sessions receive the workspace/route environment and the target menu can read:

```text
cap timeline --format json
```

TACMUX does not write NOCAP state. Operator judgment remains the trust boundary.

## Clipboard

Pipe data to `tacmux clip` to use TACMUX's trusted clipboard path. It prefers a
tmux buffer, then Wayland/X11 clipboard tools, and finally OSC 52 on a terminal;
over SSH it writes OSC 52 to the controlling terminal when available. Explicit
tmux copy-mode actions use the same path. Clipboard forwarding can expose
sensitive material on the local workstation, so verify the destination first.

## Logging boundary

Automatic tmux hooks log TACMUX-owned sessions only. Explicit `prefix+T`
(toggle), `prefix+S` (scrollback capture), and `prefix+H` (fallback log) remain
available. Set `behavior.log_outside_tacmux = true` only when global tmux
logging is intentional.
