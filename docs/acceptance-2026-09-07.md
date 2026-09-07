# Deployment acceptance, 2026-09-07

These are executed checks on the self-hosted deployment, with private raw JSON
and logs retained under `.local/acceptance-20260907`. They do not establish an
organization accreditation, power-failure guarantee or production SLO.

## Credential lifecycle

| Identity family | Accountable role | Callers | Rotation |
| --- | --- | --- | --- |
| gateway-operator | Deployment operator | Local console and operator probes | Every 30 days and immediately after exposure |
| revocation-relay | Deployment operator; authority operator maintains consumer | Remote revocation-sync consumer | Every 30 days and immediately after exposure |

The current deployment operator is the provisional accountable owner; assigning
a named organizational owner remains an organizational handover requirement.
Last rotation: 2026-09-07. Next due: 2026-10-07. Replacement IDs end in
`-r20260907`; permissions were preserved. Token values are never evidence output.
Current local token files are `.local/service.token` and
`.local/revocation-relay.token`. Previously issued tokens no longer work.

Both credentials overlapped briefly under separate IDs. The production gateway
and two existing isolated drill replicas were restarted with the overlap, callers
were switched, then old IDs were removed and all three processes restarted.
Sixteen overlap checks passed. Twenty final checks passed across three local
ports and public ingress: retired tokens 401, replacement tokens 200, relay
metrics access 403. The remote consumer read all three feeds with its replacement
credential and resumed successful sync. Test replicas do not constitute production HA.

## Revoke, restart, restore

- A private one-hour membership canary was accepted by three peer authorities,
  revoked, and denied by all three after 15.40–15.49 seconds. Membership sequence
  advanced from 5 to 6. No public demo membership was added.
- A separate one-hour JoinCertificate was accepted locally and through public
  ingress, revoked, and denied after 50.35 seconds. The issuer JoinCRL floor
  reached 7. A failed preliminary drill certificate was also revoked.
- Restarted the production gateway, all three local revocation-sync consumers,
  and the remote consumer. The membership remained denied with imported floor 6;
  the JoinCertificate remained denied locally and publicly with floors retained.
- SQLite's online backup API produced a consistent backup of the live WAL store;
  `integrity_check` returned `ok`. It contained 9,410 audit rows and JoinCRL floors
  7, 1, 1 and 0 for the four configured issuers. A manifest records issuer IDs,
  sequence/time floors, CRL body hashes and the backup SHA-256.
- Copied the database and manifest to a separate host with root-only directory
  access. Digest matched. This is independent storage, not immutable storage.
- Restored into a fresh isolated volume without initialization. Disabled every
  authority/refresh URL and used an older bootstrap policy, ensuring network
  refresh could not conceal a failed restore. Every floor was retained and the
  revoked certificate remained denied. Missing state startup also failed closed.

Never use `--init-state` to repair lost history. Preserve failed storage, restore
a consistent backup, compare it with the separate floor record, then obtain and
verify any newer issuer snapshots before admitting traffic. Stop if records are
missing or conflict. Back up issuer key material through the authority's own
procedure; this gateway database backup does not back up authority signing keys.

## Audit retention and capacity decision

For this deployment, retain all local audit events: no automatic deletion or
silent acknowledgement. The SQLite logical capacity is 1 GiB; initial measured
usage was 3,776,512 bytes (0.35%), with 9,741 pending events. WAL, backups and
container logs also consume disk; reserve at least 4 GiB and monitor host space.
Pending events are expected while the external collector is disabled.

`tools/check_audit.ps1` checks authenticated metrics, emits a timestamped report,
and exits 1 at 70% or 2 at 85%. The local Windows task
`GenesisMesh-Gateway-Audit-Capacity` runs every five minutes while the operator
is logged in; its initial execution returned 0. Inspect its result and
`.local/audit-capacity.json`. This is a local capacity alarm, not a staffed paging
service. An unattended service account and notification routing belong to the
organization's monitoring activation.

Take consistent off-host backups daily and before changes; keep 30 daily and 12
monthly recovery points as the operational retention policy. The backup/restore
drill above was executed; recurring backup automation is not yet installed.
At warning, review growth and arrange verified archive/collector capacity. At
critical, stop optional load and resolve storage before the hard cap; never delete
unacknowledged audit events to regain readiness. Any purge requires a separately
approved retention policy and verified recoverable archive.

Local SQLite and root-controlled backups are not WORM and do not provide
independent tamper resistance. If that integrity requirement applies, activate
an independently administered `GATEWAY_AUDIT_URL` collector and test durable
acknowledgements, redelivery and retention before claiming it. No collector was
invented or activated during this acceptance run.
