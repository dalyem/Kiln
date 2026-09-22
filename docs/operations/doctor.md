# Doctor and gateway monitoring

`kiln doctor` reports Kiln's stored gateway evidence, open incidents and recovery guidance. It is read-only. It does not create a VM, contact a gateway directly, alter Proxmox or repair a network.

## Run doctor

Set only the normal client credential in the environment that runs doctor:

```sh
export KILN_URL=http://127.0.0.1:4000
export KILN_TOKEN='<normal API token>'
kiln doctor --network
kiln doctor --network --node fake-node --json
```

`--network` expresses network-diagnosis intent. In this first slice it returns the same gateway report as the default command. `--node` is an exact local node-name filter. `--json` writes the unmodified Core report to standard output.

The compiled `kiln` binary exits 0 when Core reports `HEALTHY`, 2 for `DEGRADED` or `UNKNOWN`, and 1 for invalid arguments, failed authentication, transport failure or an invalid response. `go run ./cmd/kiln ...` reports the Go tool's own nonzero status, so use a compiled binary when scripting the distinction. `kiln doctor repair` and `kiln doctor apply` fail before making an API request. Repairs are unavailable.

The MCP equivalent is `kiln_doctor` with optional `network` and `node` inputs. The dashboard shows the same report, configured gateway records and open incidents. These adapters have no repair action.

## What the report means

The report has `overall`, installation and provider details, global checks, per-node gateway status, open incidents, `repairEnabled: false` and known limitations.

| Node status | Meaning | Admission result |
| --- | --- | --- |
| `READY` | Provider visibility and fresh stored evidence meet the first-slice readiness check. | A fake workload can use this node. |
| `NOT_READY` | Evidence is missing, stale, stopped, service-failed or upstream-failed. | New fake work is held. |
| `QUARANTINED` | Ownership or expected configuration cannot be verified. | New fake work is held. No adoption or repair occurs. |
| `UNCONFIGURED` | The provider reported a node with no Kiln gateway record. | The node is shown for diagnosis; it has no gateway-backed admission guarantee. |

The monitor runs every 10 seconds. A health observation is stale after 30 seconds, or invalid when it is more than five seconds in the future. It records provider visibility, ownership/configuration, power, heartbeat, policy, reservation, service and canary fields. It keeps an incident open through partial or unknown evidence, and resolves it only after a fresh `READY` observation. Health, deduplicated incidents and `gateway.*` events persist in PostgreSQL.

The fake provider can simulate every check. Its fixtures exist only in process memory, so a process restart must be treated as unknown until new fake evidence is scanned. A real Proxmox observation remains GET-only. An authenticated gateway heartbeat supplies process identity and local service observations, but it cannot prove provider ownership, VM configuration, firewall policy or guest-path connectivity. An enrolled gateway therefore remains out of admission until independent probes exist.

The dashboard refreshes visible tabs every 10 seconds. It marks its display stale after 30 seconds or when the doctor timestamp is invalid or more than five seconds ahead. A headless Chromium check verified automatic refresh and the stale warning after refresh requests were blocked.

## Network probe diagnostics

`KILN_PROBE_PROFILES_FILE` may name an operator-managed JSON array of fixed probe profiles. A requester can select only a profile ID. It cannot submit a destination, port, command or script. The probe routes share the enrollment HTTPS listener, while management creation and token rotation require the infrastructure credential.

Doctor includes probe records under each gateway as `placement: "UNVERIFIED"`. Their individual result codes are diagnostic observations. Even a profile whose checks all pass leaves gateway canary evidence and workload admission unchanged. A completed result is current for at most 30 seconds and never past its fixed profile expiry; it then becomes stale evidence. A missing report is a probe timeout, not proof that the network failed.

## Setup and scan controls

The local first slice has two credentials:

- `KILN_API_TOKEN` is the routine token for CLI, MCP, SDK and dashboard read/operate/admin calls.
- `KILN_INFRASTRUCTURE_TOKEN` is a distinct local setup token. It can create a simulated fake gateway and request a monitor scan. Keep it out of routine client environments.

The infrastructure token can call these API routes:

```text
POST /v1/gateways             fake provider only; Idempotency-Key required, body: {"node":"fake-node"}
POST /v1/monitor/scan         persists one bounded monitor pass in either provider mode
POST /v1/gateways/:id/enrollment-token  creates one 10-minute bootstrap token for an owned gateway
GET /v1/gateways/:id/identity  reads redacted identity and heartbeat status
POST /v1/gateways/:id/revoke-identity  immediately revokes gateway device authority
```

The ordinary token cannot call either route. Neither route accepts a PVE VMID, imports a VM or adopts an existing Proxmox object. `GET /v1/gateways` needs ordinary admin scope. `GET /v1/doctor` and `GET /v1/incidents` need ordinary read scope. `/healthz` is liveness, while `/readyz` returns 503 if the store cannot read the installation identity.

## Gateway identity listeners

Gateway enrollment is opt-in. Set `KILN_TLS_CERT_FILE`, `KILN_TLS_KEY_FILE`, `KILN_GATEWAY_CA_CERT_FILE` and `KILN_GATEWAY_CA_KEY_FILE` before starting the API. The first pair identifies the enrollment and heartbeat servers. The second pair signs gateway client certificates and must be a separate CA. The private-key files must be regular files with mode `0600` or stricter in a private, non-symlink directory. Kiln records the issuer certificate fingerprint and refuses a later startup with a different issuer.

The enrollment listener uses TLS 1.3 at `KILN_GATEWAY_ENROLL_HOST:KILN_GATEWAY_ENROLL_PORT`, defaulting to `127.0.0.1:4443`. The heartbeat listener uses TLS 1.3 plus a required client certificate at `KILN_GATEWAY_HEARTBEAT_HOST:KILN_GATEWAY_HEARTBEAT_PORT`, defaulting to `127.0.0.1:4444`. It does not accept forwarded certificate headers. A token that expires before first enrollment requires an administrator to revoke or replace the identity and issue a new token. Kiln never adopts a device because it presents a known certificate.

Kiln retains the current certificate and one prior certificate. The prior certificate can heartbeat for no more than 10 minutes after renewal, which covers a lost renewal response. Revocation rejects both certificates at once. An administrator may revoke an unobservable or quarantined gateway because revocation only removes Kiln device authority. It does not touch Proxmox.

## Incident response

Start with the incident's guidance, then use normal Proxmox administration to investigate the node or VM. Preserve a quarantined resource for inspection. Do not rename, retag, import, replace or delete a gateway to make the report green.

| Incident code | Meaning in this release | First action |
| --- | --- | --- |
| `PROVIDER_UNKNOWN` | Core could not obtain fresh provider/configuration evidence. | Check Core-to-provider connectivity and read-only credentials. |
| `OWNERSHIP_QUARANTINE` | The stored identity or expected configuration does not match observed evidence. | Stop and investigate ownership metadata. |
| `GATEWAY_POWER` | The configured gateway is not running. | Inspect the protected gateway and maintenance context. |
| `NODE_OFFLINE` | The provider confirms that the gateway node is offline. | Restore the Proxmox node before considering gateway recovery. |
| `GATEWAY_NOT_READY` | Gateway lifecycle is still provisioning, failed or unresolved. | Inspect the recorded operation before retrying. |
| `GATEWAY_SERVICE` | A simulated policy, reservation, heartbeat or service field failed. | Run doctor for the node and inspect the saved incident. |
| `UPSTREAM_CONNECTIVITY` | Simulated canary evidence could not confirm DNS or Internet access. | Check upstream DNS and the selected network profile. |

No email, webhook or external alert delivery is implemented. An external monitor for the control plane remains a deployment requirement. The detailed future repair and replacement design is in [gateway operations and recovery](../architecture/gateway-operations.md).
