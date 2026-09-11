# Native Windows operation

The Rust gateway can run under Windows Service Control Manager without Docker
or a signed-in desktop session. Use the verified Windows release executable;
do not rebuild or initialize trust state as part of a runtime migration.

**Acceptance status, 2026-09-11:** the native candidate passed readiness,
four-network trust readiness, operator access and retired-token rejection.
The quota backend admitted exactly 7 of 64 concurrent requests under a limit
of 7, rejected unauthenticated access, and retained its counter and TTL after
restart. Payload hashes and PowerShell syntax were checked. On retry, Windows accepted
service registration, but the final backup failed because SQLite could not open
the read-only Docker mount. Copying the stopped database directory and then
using SQLite backup passed integrity checks. The second elevation request was
canceled before final-state transfer or service startup. All ten native services
are registered and stopped; the original Docker stack was restored and public
readiness verified. Service-account execution, final-state transfer and recovery
remain acceptance gates.

The already registered services have automatic startup pending completion.
Complete the administrator resume step before rebooting this deployment.
The installer now registers future pending deployments with **Manual** startup
and enables automatic startup only when explicitly activating services, avoiding
startup against an unaccepted staged database after an interrupted migration.

## Service layout

The prepared deployment lives in `C:\ProgramData\GenesisMeshGateway`:

| Service | Process and responsibility |
| --- | --- |
| `GenesisMeshGateway` | Released Rust gateway, loopback port 8080 |
| `GenesisMeshTunnel` | Dedicated cloudflared connector for `mesh.genesismesh.org` |
| `GenesisMeshQuotaLink` | Restricted OpenSSH forwarding to the existing authority host's Redis service |
| `GenesisMeshAuthorityA`, `GenesisMeshAuthorityB`, `GenesisMeshAuthorityAnonymous` | Existing reference authorities, served by native Python and Waitress on loopback |
| `GenesisMeshRevocationA`, `GenesisMeshRevocationB`, `GenesisMeshRevocationAnonymous` | Existing authority-owned revocation consumers |
| `GenesisMeshCrlRefresh` | Existing signed CRL refresh command, once per hour |

The gateway remains Rust. The reference authority implementation and its
maintenance adapters belong to the authority project and still require Python.
They are deployed separately from the gateway executable. Waitress uses one
request thread per authority because the reference application shares a SQLite
connection. Reassess authority throughput before increasing concurrency.

Services use the passwordless, unprivileged `LocalService` account, automatic
delayed startup, dependency ordering and restart-on-failure. Service SIDs grant
access to the necessary private configuration and writable state directories.
Binaries are not writable by the service account. Logs rotate at 10 MiB with
five retained files per stream; this does not replace audit retention policy.
The existing unrelated `Cloudflared` Windows service is not modified.

## Quotas without a local container

Stock Redis 7.4.11 runs as `genesis-mesh-quota.service` on the existing USG
authority host, not on Windows. It binds only the host's loopback port 16380,
requires authentication, uses AOF with `appendfsync always`, and has a 16 MiB
`noeviction` quota budget within a 64 MiB service memory limit. The Windows
gateway reaches it at `127.0.0.1:16380` through an SSH service. Host-key checking
is mandatory. The dedicated SSH key allows forwarding only to that Redis port,
with no shell. It is not an authority administrator key.

This removes the gateway stack's Docker dependency, but preserves a network
dependency on the existing authority host. A Redis/link outage rejects protected
requests; do not fall back to local counters. Capacity, host recovery, network
latency and Redis HA remain operational responsibilities. Follow the Redis
vendor's supported patch releases. A tested Redis-compatible Windows alternative
was rejected because it did not pass the durable-acknowledgement test.

## Installation and migration

`tools/install_windows_services.ps1` installs a reviewed offline payload with
`services.json`, SHA-256 hashes, WinSW 2.12.0 wrappers/XML, released executables,
authority runtime/code, private configuration and existing state. It validates
hashes and paths, refuses an existing destination or existing service names,
and requires an elevated PowerShell session. It does not fetch binaries, stop
containers, initialize state or overwrite an existing installation.

```powershell
.\tools\install_windows_services.ps1 -Payload C:\private\reviewed-payload
```

Stage and verify native processes on alternate loopback ports before cutover.
Preserve release provenance and audit the environment-specific service XML and
manifest. Keep payloads, keys, database copies and migration evidence private.

1. Register services with Manual startup without starting them. Verify the service accounts, ACLs,
   executable paths and pending startup settings. Enable automatic startup after acceptance.
2. Stop the old gateway and all old authority writers/maintenance consumers.
   Take consistent SQLite backups of the actual configured database paths. The
   anonymous authority uses `na.db`; the other local authorities use
   `genesis_mesh_na.db`. Never infer the filename from another authority.
3. Copy the final databases to the protected native state directories. Record
   CRL sequences, revoked certificate IDs and audit counts separately. Never
   use `--init-state` to recover lost state or repair readiness.
4. When changing quota stores, allow the old 60-second quota window to expire
   while the old gateway remains stopped before enabling the new gateway.
5. Start the services; require local readiness and all expected mesh networks
   to be trust-ready. Verify the public hostname, authenticated access and
   retired-credential rejection. Confirm stored sequence floors, revocations
   and audit history have not regressed.
6. Disable automatic restart on the replaced containers. Preserve their stopped
   state until acceptance is complete. Leave unrelated containers alone.

Do not start the old stack against stale state after the native services have
accepted updates. Rollback requires quiescing native writers and consistently
transferring their latest state and sequence-floor evidence first.

## Routine checks

```powershell
Get-CimInstance Win32_Service |
  Where-Object Name -like 'GenesisMesh*' |
  Select-Object Name, State, StartMode, StartName
Invoke-RestMethod http://127.0.0.1:8080/ready
Invoke-RestMethod https://mesh.genesismesh.org/ready
```

Check revocation consumer status files under `state` and bounded service logs
under `logs`. A healthy process alone does not prove freshness or connectivity.
Run the credential, trust recovery and audit acceptance checks in
`platform.md` and `federation.md` after migration. An expired old certificate
cannot prove revocation by itself; pair negative verification with retained
CRL evidence or a fresh, isolated revocation canary.

Automatic startup configuration and service restart tests do not establish a
completed machine-reboot drill. Schedule that drill separately, then verify the
public endpoint without signing in or starting Docker Desktop.
