# TACMUX operator guide

## Operating model

An engagement is the authorization, reporting, retention, and evidence boundary. External and internal networks stay in the same engagement when they belong to the same assessment. Create separate engagements for a real client operation, HTB, OffSec, PNPT, or another academy so their context and evidence cannot be confused.

TACMUX keeps one `tacmux.engagement/v2` JSON manifest as durable state. The TUI is transient: closing it does not stop detached tmux sessions or discovery jobs.

## Create and front-load scope

Run `tacmux`, press `n`, and supply:

- **Client or Lab:** a recognizable organization or training platform.
- **Engagement Name:** a recognizable assessment or course instance.
- **Assessment Type:** External, Internal, External + Internal, or Single-machine Lab.
- **External/Internal scope:** optional IPs or CIDRs already known. Use `Label=network` when a friendly label helps.
- **Internal availability:** ready now or unavailable until access exists.
- **Pane logging:** per-engagement default.

Known `/32` hosts and networks can be entered before testing. Scope groups are intentionally limited to **external** and **internal**.

## Cockpit workflow

The four tabs answer different operator questions:

| Tab | Operator question |
|---|---|
| Targets | What host am I working on, is its session live, and what access is confirmed? |
| Scope & Discovery | What may I touch, what is reachable, and what identification jobs/results need review? |
| Situation | What does the network look like, and what confirmed chain has been demonstrated? |
| Documents | Where are the narrative, findings, notes, logs, and evidence? |

Press `a` for actions relevant to the active tab. Press `Ctrl+P` for Textual's fuzzy command palette. The palette exposes the same actions as the visible workflow and does not require fzf.

## Scope and pivots

Each address is stored with a scope-entry ID, not as a globally unique host key. That permits:

- a dual-homed host with one external and one internal address;
- the same RFC1918 address in two distinct scope entries;
- multiple networks accessed through one pivot;
- an internal range that begins unavailable.

After a foothold creates an approved route:

1. Open **Scope & Discovery**.
2. Highlight the internal scope and press Enter or `a`.
3. Set availability to **Ready** and select the target through which it is reachable.
4. Refresh the Situation view.

TACMUX records the route relationship; it does not configure VPNs, SOCKS proxies, Ligolo, SSH forwarding, or firewall rules.

## Host identification and reconciliation

Press `d` and choose one of three inputs:

1. **Run detached Nmap host identification** — launches only:

   ```text
   nmap -sn --reason -oX <job>/results.xml <selected-ready-scope...>
   ```

2. **Import XML or pasted hosts** — accepts Nmap XML or one `IP [hostname]` per line.
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
IP is always the initial primary endpoint exported as `TARGET`. Choosing a
hostname as primary is an explicit operator action.

## Target work

Highlight a target and press Enter. TACMUX creates the tmux session if necessary, exports stable engagement/target context, starts context-aware logging when enabled, and attaches or switches the current client.

Target actions include:

- start/attach or stop session;
- edit display name, scope-qualified addresses, hostnames, and primary endpoint;
- edit `NOTES.md` through `$VISUAL`, `$EDITOR`, or `vi`;
- record confirmed access or curated activity;
- create and edit a finding;
- edit or delete structured engagement records;
- view a NOCAP timeline when enabled;
- create a verified target archive;
- permanently delete an unreferenced mistaken target.

Display-name changes do not rename the stable target directory or tmux identity. Starting or attaching refreshes session context; panes created afterward inherit the current primary endpoint as `TARGET`.

The optional engagement operations session starts in the engagement root. Stop-all cancels active discovery jobs and stops target and operations sessions before archival.

## Recording activity, access, and findings

### Activity

Use activity for concise, curated events—not every command. Select one result:

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

Choose **Manage engagement records** from a contextual action menu to correct or delete access, activity, finding, and attack-path records. A record used by an attack path must be removed from that path first. Scope entries can likewise be fully edited or deleted when no target address uses them.

## Building an attack path

Network topology and attack path are separate views:

- topology maps external/internal scope, hosts, interfaces, access level, pivots,
  and unresolved or hostname-only targets not yet assigned to an address;
- an attack path is a curated sequence of demonstrated findings, access records, and confirmed activities.

Open **Situation**, press `a`, and choose **Build confirmed attack path**. Press Enter on eligible records to add them. In the chosen list, Delete removes a step and `Ctrl+Up` / `Ctrl+Down` changes order. Optional one-line step notes explain how each fact advances the chain.

Each step may only reference structured confirmed state. The generated `notes/attack-path.md` and `SITREP.md` therefore cannot accidentally promote a failed responder attempt into a demonstrated compromise.

## ACME external-to-internal example

This example uses documentation-only addresses and mirrors a realistic flow without performing network actions.

### 1. Start with known scope

Create:

```text
Client or Lab: ACME
Engagement Name: 2026 External and Internal Assessment
Assessment Type: External + Internal
External: Internet Perimeter=198.51.100.0/24
Internal: Corporate LAN=10.77.10.0/24
Internal availability: Unavailable until access
```

Run detached identification against the external entry. Review two results:

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

Update **Corporate LAN** to Ready via MAIL. The terminal topology now reads conceptually:

```text
EXTERNAL
└─ Internet Perimeter: 198.51.100.0/24
  └─ MAIL [T0001] — User Execution (198.51.100.25)
INTERNAL
└─ Corporate LAN: 10.77.10.0/24 via MAIL
  └─ No identified hosts
```

### 3. Identify internal hosts

Run identification on Corporate LAN through the operator-established route, or import externally produced XML. Review:

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

### 5. Curate the demonstrated chain

Create **External foothold to internal authenticated access** in this order:

1. F0001 — validated initial-access weakness.
2. AR0001 — user execution on MAIL.
3. A0001 — approved internal route established.
4. F0002 — readable deployment share.
5. AR0002 — authenticated SMB access on PASSBACK.

The topology still shows all identified systems, including TPM-DC. The attack path shows only the demonstrated chain. No administrative or privileged compromise is inferred.

The repository includes this state as `tests/fixtures/recap_sanitized.json`; it is offline, uses reserved mock addresses, and contains no credentials or live-lab dependency.

## Documents and evidence

The Documents tab previews:

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

## Archives, restore, and mistaken-target deletion

Target and engagement archives are private `.tar.gz` files with adjacent `.manifest.json` documents. Creation verifies the completed archive immediately. `tacmux archive verify FILE` checks archive size, SHA-256, member hashes, paths, links, and root structure.

Restore refuses an existing destination and extracts through a private staging directory. Engagement restores validate the embedded manifest and identity; target restores validate archived metadata against the current engagement.

Permanent target deletion is deliberately stricter than archive:

- the tmux target session must be stopped;
- no scope pivot, access, activity, or finding may reference the target;
- the exact displayed confirmation must be typed;
- the target directory is staged, the manifest is saved, and only then are files removed.

## v1 import

From the engagement picker press `i`. Import is copy-only: v1 target evidence is copied into stable v2 target directories and original notes/findings are retained under `legacy-import/`. The source is never converted in place.

Review imported targets, add scope-qualified addresses, and curate structured access/activity/findings manually. Import does not guess security facts from free-form notes.

## NOCAP

NOCAP remains optional and separate. With `[nocap] enabled = true`, target sessions receive the workspace/route environment and the target menu can read:

```text
cap timeline --format json
```

TACMUX does not write NOCAP state. Operator judgment remains the trust boundary.
