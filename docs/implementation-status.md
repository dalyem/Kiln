# Implementation status

Status: Phase 0 design and Phase 1 foundation are implemented. Protected gateway monitoring, authenticated enrollment, diagnostic network probes and a durable provider operation journal are part of the contributor scaffold. This is not a production appliance or a working Development Lease service.

## Current KILN-25 and KILN-85 verification

Verified on 2026-09-22. KILN-25 completed the guarded Linux development-image import journal: 286 tests across 30 files passed with PostgreSQL under `--maxWorkers=2`, the full build passed, and independent review found no remaining material issues. The check used real PostgreSQL with HTTP provider fixtures and local receipts. It made no PVE writes. See [Linux import qualification](development/linux-import-qualification.md).

KILN-85 ran the contributor Compose stack from a clean `docker compose up --build --wait`. The final rebuild fixed the container wrapper by starting Node directly. It verified fake-provider and PostgreSQL status, unauthenticated API denial, resource creation, idempotency, events, dashboard access, all 26 database tables through the Linux migration, non-root application execution, loopback-only published ports, no host PostgreSQL port, and no infrastructure token in the dashboard. An empty required API token caused Compose configuration rejection. The `.env` file was absent from running containers. Generated credentials were absent from image metadata and history, rendered HTML, and captured logs. This was not a full image filesystem audit. A `docker compose down` followed by another start retained the installation ID, resource ownership and history, events, and idempotency record. The final stop exited the API, dashboard and PostgreSQL containers cleanly in 1.34 seconds, then removed the stack's containers, volume and network. See the [Compose qualification procedure](development/contributor-compose-qualification.md).

## Stage 2 qualification

The real ten-phase lifecycle, guest serial execution, saved-receipt restart recovery and guarded cleanup passed on nested PVE 9.2.2. Both test VMs and disks were removed; the empty pool and signed image remain explicitly managed. Existing configurations matched all 25 baseline hashes. All 228 tests and the full build passed. See [evidence and limits](development/stage2-qualification-evidence.md).

## Available foundation

The [Development Lease workspace increment](development/workspaces.md) adds
local Go capture, inspection and Linux materialization. It preserves separate
HEAD, index and working-file views, including nonignored untracked files, and
refuses existing destinations. This is a local snapshot boundary; it does not
upload code, enroll workloads, create a development VM or serve a preview.
The [qualification record](development/workspace-qualification.md) describes
the actual binary round trip, rejection tests and remaining limits.

The [Linux image increment](development/linux-image-qualification.md) adds a
pinned Debian builder, signed build metadata, bounded file verification and a
local no-NIC boot qualifier that exercises the shipped `kilnd` materializer.
Kiln now has a guarded Proxmox import path. The node QEMU list may omit
`type`; that shape is accepted only on the node-scoped list. Startup recovery
leaves the two resources of an active Linux import run in `PROVISIONING` and
still marks every other orphaned resource `ERROR`. The KILN-26 nested run on
2026-09-22 completed import, boot, restart recovery, and cleanup. See
[Linux PVE qualification](development/linux-pve-qualification.md). Workload
enrollment remains unimplemented.

- TypeScript Core and Fastify REST, shared request schemas, ownership checks and a fake compute provider.
- PostgreSQL/Drizzle schema and stores, explicit ephemeral memory mode, installation identity and operation/event records.
- Fake resource lifecycle and lease expiry through the ownership boundary; deterministic scheduler decisions.
- Read-only Proxmox provider with token authentication, TLS verification and node/storage/guest observation. A separate administrator-only lifecycle qualifier has passed its real nested-lab test.
- Go CLI, loopback-only kilnd health skeleton and outbound gateway identity client, generic stdio MCP client, Next.js infrastructure dashboard, JS and Python REST clients.
- Gateway enrollment over server-authenticated HTTPS, a separate strict mTLS heartbeat listener, durable certificate identity, same-key renewal and administrator revocation. See [gateway enrollment](architecture/gateway-enrollment.md).
- Fixed operator-managed network probe profiles, expiring scoped tokens, a one-shot Go DNS/HTTPS/TCP checker, durable results, guarded fake-resource cleanup and diagnostic doctor output. See [network probes](architecture/network-probes.md).
- Shared operation dispatch and reconciliation, immutable ownership snapshots, a PostgreSQL fence against conflicting unresolved operations, and sanitized resource operation history. Asynchronous completion is exercised with fake compute; the Proxmox task reader remains GET-only. See [provider operations](architecture/provider-operations.md).
- Protected persistent gateway records, gateway health observations, deduplicated incidents and a 10-second monitor. Configured gateways without fresh ready evidence hold new fake work.
- Read-only doctor API, CLI and MCP paths, plus gateway and incident dashboard data. Gateway repair returns an explicit unsupported response.
- Contributor Compose stack and architecture for appliance, bootstrap, images, gateway, workloads, browser sessions, workflows, drivers and artifacts.

The verification record below distinguishes runtime checks from design and environmental limits. See [working state](architecture/working-state.md) for the handoff boundary.

## Scope limits

No appliance image is built. Kiln Core has created and removed its own template and BIOS probe through a narrowly configured lifecycle qualifier. General live provisioning, bootstrap apply, resource import, upgrades, backups and networking automation are not implemented. Generic Proxmox lifecycle methods remain unsupported.

`dev up` creates a fake resource record for exercising the contract. It does not clone a VM, transfer files, run a server or return a preview. Fake browser and execution resource types likewise do not control browsers or execute commands. These labels test lifecycle behavior only.

The daemon exposes no command execution. The Python client does not implement durable workflow primitives. No real gateway image, automatic provisioning, workload canary, browser/desktop runtime, agent runtime, artifact service, image-management service, authentication handoff or multi-user authentication exists yet. A local development base-image builder is available. Gateway identity transport is implemented; automatic delivery of bootstrap credentials to a provisioned VM is deferred.

Service-token authentication is a local contributor scaffold. Dashboard access has no separate human login and is restricted to localhost by the development deployment. The approved design is team structure within one trusted organization, with separate identities and project access. Production human/client enrollment and authorization still require implementation; see [decisions.md](architecture/decisions.md).

The monitoring slice does not mark a real gateway healthy from PVE power state alone. With the read-only Proxmox provider, absent authenticated workload telemetry remains unknown and blocks new work on a configured node. The documented nested-lab inventory exercise did contact a real PVE API through Kiln's GET-only provider and classified operator fixtures as `EXTERNAL`; it did not exercise gateway creation, monitoring telemetry or any live Core mutation. See [nested-lab evidence](architecture/nested-lab-evidence.md).

## Read-only Proxmox configuration

Run the API on a contributor machine or the future appliance, never on a PVE host:

```sh
export KILN_PROVIDER=proxmox-read-only
export KILN_PROXMOX_URL=https://pve.example.internal:8006
export KILN_PROXMOX_TOKEN='PVEAPIToken=kiln@pve!discovery=<secret>'
export KILN_API_TOKEN='<separate Kiln client token>'
export KILN_INFRASTRUCTURE_TOKEN='<different, tightly held local setup token>'
export KILN_DATABASE_URL='postgresql://kiln:<password>@127.0.0.1:5432/kiln'
# For a private CA, set NODE_EXTRA_CA_CERTS to your trusted PEM CA file.
npm run dev
```

Use the audited privileges in [Proxmox evidence](architecture/proxmox-evidence.md). This example defines configuration; it has not been exercised against a real cluster. The built-in provider cannot mutate live PVE resources. Missing guest visibility is an observation failure, not confirmed deletion. No automatic pool creation or adoption occurs. Do not set `KILN_INFRASTRUCTURE_TOKEN` in routine CLI, MCP, SDK or dashboard environments. It authorizes fake gateway setup, explicit monitor scans and gateway enrollment-token issuance or revocation in this scaffold.

## Baseline verification record

Verified on 2026-09-08 with Node 22.23.2, npm 10.9.8, Go 1.22.2, Python 3.12.3 and a disposable PostgreSQL 16.15 instance. No system database service was installed.

| Check                                                 | Result                                                                                                             |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Clean `npm ci` followed by `npm run build`            | Pass, including API typecheck, Next dashboard, MCP and JS SDK                                                      |
| `KILN_TEST_DATABASE_URL=<disposable-db> npm test`     | 43 tests passed across six files, including four real PostgreSQL regressions                                       |
| `npm run typecheck` after final startup-order fix     | Pass                                                                                                               |
| `go test ./...` and `go vet ./...`                    | Pass                                                                                                               |
| `python3 -m unittest sdk/python/tests/test_client.py` | Four tests passed                                                                                                  |
| Python compile and wheel build                        | Pass                                                                                                               |
| `npm audit --omit=dev`                                | Zero reported vulnerabilities                                                                                      |
| Actual API with a fresh Postgres DB                   | Auth denial, concurrent idempotency, conflict, lease extension, stop/destroy, replay and durable events passed     |
| Injected Postgres audit failure                       | Destruction denied, provider resource retained and database resource stayed READY                                  |
| Actual scheduled lease worker                         | Expired owned resource destroyed through the 30-second scan                                                        |
| Restart and identity                                  | Installation and terminal state/events persisted; a second writer was rejected; mismatched identity failed startup |
| MCP stdio against the actual API                      | Initialize, list five tools and schema-validated resource lookup passed                                            |
| CLI and JS/Python clients against API                 | Resource/status calls passed                                                                                       |
| Dashboard HTTP render against API                     | Actual resource, fake-provider badge and persistence rendered; token absent from HTML                              |
| Compose YAML and local Markdown links                 | Parsed/checked; API/dashboard publications are loopback and Postgres has no published port                         |

At the 2026-09-08 baseline, safety regressions were observed failing before repair, including the ownership guard mutation check, external Postgres expiry selection, Python cross-origin redirect and installation validation before recovery. The baseline tests were green and an independent reviewer reported no remaining material findings. The monitoring changes have the separate verification record below.

The MCP and shared API schema use the same pinned Zod version. A clean installation and build verified the dependency graph after a mixed-version compile failure was corrected.

### Current verification

Verified on 2026-09-10: all 73 TypeScript tests passed, including eight PostgreSQL tests. The full API/dashboard/MCP/SDK build, Go tests and vet, four Python SDK tests, JSON/OpenAPI validation, and Markdown link checks passed. Quarantine-display and lifecycle-recovery regressions were observed failing first, then the complete TypeScript suite and typecheck passed again. Independent review reported no remaining material findings. The following runtime checks also passed:

- An actual HTTP doctor request through the read-only Proxmox provider returned `DEGRADED` with one `UNCONFIGURED` node. Inventory kept all three lab VMs `EXTERNAL`. The doctor and inventory requests together made 12 provider GET calls and no writes. They did not claim router health.
- A PostgreSQL-backed API persisted gateway incidents across two API restarts. Immediately after startup, before any manual scan, missing fake fixtures caused an admission hold. Generic gateway stop, delete and lease-extension requests were denied. The compiled CLI returned 0 for healthy simulated evidence and 2 for degraded evidence, including a real read-only Proxmox diagnosis. MCP stdio returned the same report, and the dashboard rendered incidents without exposing either credential.
- Headless Chromium verified automatic dashboard refresh. Blocking subsequent requests and advancing the browser clock produced a stale-data warning.

These checks do not prove real gateway enrollment, authenticated heartbeat, canary traffic, alert delivery, repair or private-network isolation.

### Historical baseline limits

At the 2026-09-10 baseline, Docker was not installed in that environment. The Dockerfile and Compose stack were prepared and YAML/port policy were checked, but no actual container image build or Compose run was performed there. The initial browser preview attempt timed out. The later monitoring checks used headless Chromium and verified automatic dashboard refresh and a stale-data warning when requests were blocked.

Live Core gateway provisioning, authenticated heartbeat, canary, repair, permissions, and network provisioning have not been tested against a real cluster. The adapter is backed by official-source research and mocked transport tests. The separate nested-lab inventory read proved only GET-only discovery and external classification. Version-specific storage, pool ACL, clone, deletion, and network behavior still require a disposable PVE lab.

### Known scaffold limits

- One API writer per database, enforced with a Postgres advisory lock. No distributed worker or leader election.
- The accepted [control-plane HA design](architecture/control-plane-ha.md) supports one appliance for one- and two-node installations and three replicated appliances on qualified clusters with at least three hosts. Replication, fencing, endpoint failover and the 120-second recovery target are not implemented or verified.
- Fake provider fixtures are process-local. PostgreSQL preserves records across restart, but fake workloads are not reconstructed. Later inspection fails safely rather than inventing a workload.
- Events support project-scoped cursor polling. SSE/WebSockets and the full observability dashboard are later work.
- Storage capability discovery is conservative. Real image/network placement and capacity reservations are not implemented. The scheduler is exercised with fake capabilities.
- Runtime authentication is one explicit local service identity with scopes. Production human/client identities, general workload enrollment, multiple organizations and scoped-token issuance remain unimplemented. Gateway identities have their own scoped enrollment and mTLS transport.
- Initial SQL is applied at startup. Versioned appliance upgrade/rollback, secret export and restore quarantine executors remain designs.
- Real pool creation and resource import are deferred. IMPORTED classification is tested using explicitly seeded records, not a live import endpoint.
- Gateway health is durable in PostgreSQL. In-memory mode is intentionally ephemeral. Fake-provider fixtures are process-local, so a restart yields unknown evidence until the fake provider is recreated and scanned.
- The monitor runs every 10 seconds and treats gateway evidence older than 30 seconds as unready. It persists incidents and events, but sends no email, webhook or external alert.
- `kiln doctor`, the MCP doctor tool and the dashboard only report evidence and recovery guidance. No repair plan or repair executor exists. `POST /v1/doctor/repair` returns 501.

## Gateway identity verification

The implementation adds outbound Go gateway enrollment, strict mTLS heartbeats, durable installation-bound certificates, same-key recovery, revocation and redacted doctor diagnostics. These provide process identity and telemetry; they do not qualify routing or permit external-resource mutation.

Actual local TypeScript API listeners, PostgreSQL and compiled Go daemon verified enrollment, authenticated heartbeat, reconnect after Core restart, administrator-token separation, missing-client-certificate rejection and HTTP 401 for a revoked certificate. A separate factory test used 30-second leaf certificates and kept Core offline past expiry; the same daemon renewed and resumed heartbeats after Core returned. The factory restored explicit fake-provider observations, since fake infrastructure is process-local. This is not a physical-host or HA failover test.

Final verification on 2026-09-10: all 85 tests across 11 files passed with no skips, including nine PostgreSQL integration tests and the real Go-to-TypeScript TLS test. `npm run build`, `go test ./...`, `go vet ./...` and four Python SDK unittest checks passed. Independent product review found no remaining material findings after the revocation and CA-lifetime fixes.

The permanent integration test creates a disposable database and local TLS certificates, builds the actual Go daemon, and exercises the TypeScript TLS applications. Contributor prerequisites and the command are in [CONTRIBUTING.md](../CONTRIBUTING.md). Real gateway image provisioning and policy enforcement remain unimplemented; diagnostic probe execution is covered below.

## Diagnostic network probes

Core persists immutable profiles/plans, hashed per-job tokens, results and audit events. The compiled Go checker performs real local DNS, verified HTTPS and TCP checks through the TLS plan/report API. The permanent PostgreSQL integration test covers restart persistence, identical report replay, credential separation and guarded cleanup, including ownership drift denial.

Probe compute is still simulated. Reports carry `placement: "UNVERIFIED"`, cannot prove network isolation and never clear workload admission holds. A failed connection to an expected-blocked destination is UNKNOWN. Doctor marks results stale after expiry, 30 seconds or a binding/profile change. No live Proxmox mutation, VM deployment or automatic probe credential delivery was exercised.

Verification on 2026-09-10: all 102 tests across 13 files passed with PostgreSQL enabled, with no skips or unhandled errors. The full npm build, Go tests/vet, focused Go race checks and four Python SDK tests passed. Independent review found no remaining runtime issues; its final OpenAPI response-schema finding is fixed and checked. Test teardown now allows graceful PostgreSQL disconnects instead of forcibly terminating closing connections.

## Provider operation journal

The shared Core executor now persists a versioned ownership snapshot and audit record before dispatch. PostgreSQL permits only one unresolved operation per resource. Pending or unknown outcomes block conflicting mutations and lease extension, and prevent gateway admission. Known submitted fake tasks survive store restart and can complete after fresh ownership and power checks. Lost submission receipts are never resubmitted automatically. Failed, mismatched or expired tasks remain blocked for investigation.

MemoryStore uses the same state guards and isolates saved operation records from provider callbacks. Core passes copies of resource and gateway metadata to providers and rechecks the retained ownership binding before completion. Resource history returns the newest 100 sanitized entries through the project-authorized API. Legacy duplicate unresolved rows stop migration; missing historical provenance is never reconstructed from current resource names or tags.

Verification on 2026-09-11: all 168 tests across 17 files passed with PostgreSQL enabled, with no skips or unhandled errors. The full npm build passed. Go tests/vet and four Python SDK tests passed before the final TypeScript-only fixes. An actual API process verified create, idempotent replay, stop/destroy, redacted history, authentication denial, restart persistence and terminal replay against a fresh PostgreSQL database. Separate integration tests cover submitted fake task recovery and legacy migration refusal. Independent review found no remaining material findings after the provider callback isolation fixes.

The Proxmox task reader is GET-only and tested through bounded HTTP fixtures. It accepts the pinned direct QEMU worker/action mapping; no live task, mutation, clone, HA, restore or LXC task path was qualified. Fake task completion is not evidence of real VM provisioning or physical-host failover. No Proxmox resources were changed during this milestone.

## Image and attachment provenance

Stage 1 is complete and independently reviewed as of 2026-09-21. Core verifies a bounded fake artifact against a signed image manifest and operator-configured, scoped Ed25519 trust policy. Image versions are immutable. Concurrent import requests serialize through the same idempotency and catalog boundaries in memory and PostgreSQL.

Generated fake templates and full-clone plans carry immutable operation bindings. Template import recovery checks the stored image body, manifest digest, capabilities, nonce, provider identity and attachment intent. Clone plans bind the exact source and destination separately; the fake worker verifies its prepared plan against the submitted receipt before effects. Template and clone children share an ownership registry. Missing records, changed references and unexpected graph fields deny lifecycle actions.

The shared Core path covers ordinary lifecycle, leases and asynchronous completion. Pending creates need not have destination attachments yet; a known successful destroy requires authoritative absence. Template retirement refuses live or unresolved dependencies and does not delete provider disks. A missing provenance plan cannot downgrade a resource to legacy fake behavior.

New API paths are `POST /v1/images/import`, `POST /v1/templates/{id}/retire` and `GET /v1/resources/{id}/provenance`. Normal project-scoped resource creation accepts an eligible `templateId`. Import and retirement require the separate infrastructure credential. Runtime publisher policy comes from `KILN_IMAGE_TRUSTED_KEYS_FILE`; requests cannot supply trusted signing keys. See the [fake-image walkthrough](development/image-provenance.md) and [design](architecture/image-provenance.md).

Verification passed all 185 tests across 19 files against fresh PostgreSQL, with no skips or unhandled errors, and the full npm build. This includes 10 unit and 7 PostgreSQL provenance tests covering concurrent import/retirement behavior, submitted-task restart, source/manifest substitution and missing child ownership. The actual HTTP/PostgreSQL smoke passed signed import, tamper/auth denial, replay, clone lifecycle, retirement pinning, sanitized output and completed-history persistence across an API restart. Independent review found no remaining material findings and reproduced clone and template receipt-body tampering denial before any provider effects. Go and Python code was unchanged and their checks were not rerun for this stage.

This is fake compute only. Artifacts are limited to 128 KiB, and a catalog version currently supports one simulated template import. Additional node replicas, large image distribution, native configuration parsing and live import/clone/delete qualification remain future work. Existing lab fixtures remain external. No Proxmox resource was changed during Stage 1.

## Next milestone

Stage 2 qualified the narrow BIOS profile described above. The next live step
is a signed Linux workload image with bounded staging and a strict configuration
and attachment profile, followed by a Kiln-owned gateway and qualified network
placement. Workload enrollment, authorized workspace transport, preview routing
and real TTL cleanup then complete the first Development Lease. The
[milestone design](architecture/development-lease.md) records these gates.
Local workspace reconstruction does not satisfy the complete VM milestone.
HA still requires separate replication, fencing and client-recovery proof.
