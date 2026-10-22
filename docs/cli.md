# Command-line tools

This repository builds three binaries. The release ZIPs and the container
image carry the first two.

| Binary | What it does |
| --- | --- |
| `genesis-mesh-gateway` | The gateway server, and its configuration and state commands |
| `genesis-mesh-operator` | A read-only preflight of an authority, which writes a policy fragment |
| `genesis-mesh` | Local signing and verification utilities over the Rust trust core |

The Rust `genesis-mesh` is not the core's Python `genesis-mesh` command,
although they share the name. The Python one runs authorities and nodes
(`genesis-mesh init`, `genesis-mesh na start`, `genesis-mesh join`,
`genesis-mesh keygen node`, …) and comes from `pip install genesis-mesh`.
When a page in these docs names a Python command, it says so.

## genesis-mesh-gateway

```text
genesis-mesh-gateway [--version | --check-config | --init-state | --healthcheck | --help]
```

| Command | What it does |
| --- | --- |
| (none) | Start the server. Settings come from the environment; see the [configuration reference](configuration.md). |
| `--version` | Print the version. |
| `--check-config` | Read the settings and the policy, check the policy and its CRL signatures, and exit, without opening a listener. With `GATEWAY_STATE_FILE` set it also restores the state file, so it needs the file to itself: check a stopped replica or a backup. |
| `--init-state` | Create the durable state file from the verified policy, once. It refuses to overwrite an existing file. See [platform controls](platform.md#durable-state-and-recovery). |
| `--healthcheck` | Ask `GET /health` on the local listener and exit 0 on `200`. The image's `HEALTHCHECK` uses it. |

## genesis-mesh-operator

```text
genesis-mesh-operator --origin HTTPS_ORIGIN --network NAME --authority-key BASE64 [--allow-http] [--report FILE] [--policy-fragment FILE]
```

It reads an authority's signed genesis block, CRL, revocation feed and
recognition catalog, checks them against the network name and the public
key you pinned, and writes a report. Only when every check passes does it
write the policy fragment. It holds no signing key and changes nothing on
the authority. See [federation](federation.md#onboard-an-authority) and the
[quickstart](quickstart.md).

## genesis-mesh

```text
genesis-mesh keygen
genesis-mesh issue --seed <b64> --key-id <id> --node-key <b64> \
                   --network <name> [--role <r>]... [--days <n>]
genesis-mesh verify --cert <file> --anchor <key-id>=<pubkey-b64> [--anchor ...] \
                   [--crl <file>]
genesis-mesh canonical --file <file>
```

| Command | What it does |
| --- | --- |
| `keygen` | Generate an Ed25519 identity. Prints the seed and the public key. |
| `issue` | Issue and sign a join certificate. Prints it as JSON. |
| `verify` | Evaluate a certificate against trust anchors, and optionally a CRL. Exits 0 if trusted. |
| `canonical` | Print the canonical JSON of a file, for cross-checking with the Python implementation. |

These are for local experiments and interoperability checks. `issue` signs
with a seed you pass on the command line; never use it with an authority's
real key.
