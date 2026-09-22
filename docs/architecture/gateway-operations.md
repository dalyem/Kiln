# Gateway operations and recovery

## Problem

Automatic private networking depends on one Kiln gateway VM per prepared compute node. If that VM is stopped, loses its policy, loses its reservation state, or no longer matches its recorded identity, new workloads must not start on that node. Existing workloads must retain the last validated deny policy instead of gaining a route to the LAN.

The design must give an administrator a clear incident signal and a guarded recovery path. It must not treat a gateway as an ordinary disposable workload, nor allow an agent to repair infrastructure.

The first implementation slice now has protected persistent gateway records, a 10-second monitor, durable health and incidents, node admission holds, authenticated enrollment and mTLS heartbeat, and read-only doctor reporting. It deliberately has no real gateway deployment, workload canary, alert delivery or repair executor. The fake provider simulates evidence for tests and local development; it is not network proof. See [doctor and gateway monitoring](../operations/doctor.md).

## Options

### Let Proxmox protect and restart the VM

Set PVE protection and boot order, then rely on an administrator to inspect failures. This is cheap and useful against accidental deletion, but PVE protection does not prevent stop or every configuration edit. VM power state also cannot prove that DHCP, DNS, firewall policy, reservations, or egress work.

### Make the gateway an ordinary Kiln resource

Use the existing resource lifecycle and TTL cleanup machinery. This keeps one implementation path, but a lease expiry, workflow cancellation, project deletion, or generic stop request could take down node networking. It also gives a dangerous interface to clients that should have no infrastructure repair rights.

### Treat the gateway as protected infrastructure

Keep a separate, persistent infrastructure record and require an infrastructure-admin maintenance operation for lifecycle changes. Core combines PVE inspection with a gateway heartbeat and an isolated egress/DNS canary. The current doctor command diagnoses only. A later doctor command can create an explicit, short-lived repair plan before any mutation.

This adds state and operational work. It keeps the critical path narrow and prevents ordinary workload cleanup from touching the gateway.

## Recommendation

Use protected infrastructure. Each prepared node owns one node-local gateway and private network. Kiln does not promise automatic cross-node migration or HA for workloads that depend on that gateway. Healthy prepared nodes may accept new work while an affected node is held. Existing workloads remain node-local until an explicit reprovision operation.

PVE [`protection=1`](https://pve.proxmox.com/pve-docs/qm.1.html) protects against accidental VM or disk removal. It does not prevent a stop or every configuration edit. Boot order and boot readiness gates are part of the defense. They reduce accidental loss and let the gateway start before workload admission. Core must not infer readiness from `RUNNING` alone. Kiln must not install a permanent PVE task lock because that would block legitimate operator recovery.

Trusted PVE root administrators can still stop, change, or delete the gateway. PVE documents `root@pam` and Administrator as unrestricted system administrators. Kiln cannot hide a VM from them. The product records the change, holds the node, and requires the same ownership checks before it acts. See the [PVE user-management manual](https://pve.proxmox.com/pve-docs/pveum.1.html#_system_administrator).

## Bootstrap and cluster rules

An explicit provider cluster-status result may establish that a host is standalone. A one-row or permission-filtered inventory, `403`, or missing quorum data cannot. It stops bootstrap writes. A multi-node installation connects to one existing cluster endpoint for discovery. Its selected hosts must already belong to that same PVE cluster, the cluster must have quorum, inventory must show enough membership to make that conclusion, and each selected host must be online and pass node qualification. An unselected member may be offline. An offline selected node is ineligible and appears in the plan and health report. A two-node quorate cluster is not rejected for lacking a third node, but Kiln reports its availability limits. Bootstrap never creates or joins a cluster, forces quorum, edits Corosync, or attempts Corosync repair. Moving a standalone host into a cluster is an administrator project outside Kiln. It requires provider-binding revalidation and quarantine before later Kiln writes, never an automatic `pvecm` or expected-votes action. PVE documents the read-only consequences of quorum loss in its [administration guide](https://pve.proxmox.com/pve-docs/pve-admin-guide.html#_quorum).

Automatic-network bootstrap performs a temporary, host-key-verified, read-only SSH qualification on every selected online node. It runs during initial preparation, when an administrator adds a node, after a relevant PVE upgrade, or after the administrator declares a host-network change. It does not run for each workload VM. Bootstrap enrolls the host key through a trusted operator path, never blind trust-on-first-use. It permits only reviewed bridge and address inspection such as `bridge -j vlan show` and `ip -j address show`, plus `sha256sum` of selected non-secret network configuration paths. It captures a bounded redacted transcript and before/after hashes, forbids arbitrary shell commands, and disables agent forwarding. The operator supplies the credential only for the bootstrap window or a resumed bootstrap. Kiln retains no SSH credential. A root SSH credential still has full host authority despite the read-only command policy; Kiln relies on the trusted administrator boundary for that credential.

PVE's structured API omits runtime bridge-self VLAN membership needed for this check. The source audit referenced `PVE/Report.pm` and `PVE/API2/Network/SDN/Nodes/Zone.pm`. API-only `USER_ATTESTED` is not approved for automatic mode. The qualification remains point-in-time evidence. [Nested lab evidence](nested-lab-evidence.md) is `LAB_PROBE_ONLY`; it does not qualify a production node or cluster.

The control appliance remains on the existing LAN and does not depend on a node gateway for its own access. Its availability and the gateway's availability are monitored separately.

## Protected infrastructure contract

Core records a gateway as a normal Kiln-owned resource with a protected-infrastructure classification and metadata. It uses the same ownership authority as every other managed resource, with these rules:

- It has no TTL and is excluded from workload garbage collection, workflow cancellation, project deletion, and generic resource stop or destroy paths.
- Only an `infrastructure-admin` principal may request maintenance. Agents, MCP clients acting for agents, and project-scoped users cannot repair or alter a gateway.
- A maintenance operation includes the gateway, node network, lease segments, dependent workloads, policy generation, and operation generation. Core rejects a request when a dependency is unknown or no longer matches.
- Every mutation rechecks the database record, provider metadata, installation ID, resource ID, generation, full VM attachment set, and recorded task state. Read-only diagnostics report ownership drift rather than refusing inspection. Core never adopts an external VM, repairs missing tags, or mutates an external network object.
- Missing or incomplete provider visibility means `UNKNOWN`, not deleted. A timeout cannot trigger a duplicate gateway or a blind rebuild.

PVE protection is enabled for the owned gateway VM. Boot configuration puts the gateway ahead of dependent workload classes. Core waits for authenticated service and policy readiness before it admits workloads, regardless of the VM power state.

The persistent gateway uses `onboot=1` after its guarded setup. Node-local automatic-mode workloads use `onboot=0` and have no HA membership. Core resumes an unexpired workload only after gateway attestation and network readiness. PVE boot order cannot prove that readiness.

## Monitoring and incident states

The current monitor runs every 10 seconds and makes stored evidence stale after 30 seconds or invalid when more than five seconds in the future. It distinguishes a provider-confirmed offline node from missing provider visibility, and keeps an incident open through unknown evidence until a fresh ready observation recovers it. It has fake provider evidence for local tests, persisted health/incidents and a read-only PVE observation. It does not yet have gateway enrollment, an authenticated heartbeat, workload canary, SSH qualification at install time or alert delivery. In particular, the read-only PVE adapter cannot turn a running VM into a ready real gateway.

The target design samples four sources for each prepared node. Normal diagnosis uses stored qualification evidence, PVE API, gateway heartbeat and canary results. It does not require SSH on every doctor call:

| Source | Required signal | What it establishes |
| --- | --- | --- |
| PVE API | VM power and configuration, ownership metadata, node state, task status | The recorded object is visible and still matches its plan |
| Gateway heartbeat | Authenticated identity, policy and reservation generation, DHCP/DNS/firewall service health, local watchdog result | The expected gateway process is alive with the expected state |
| Isolated canary | DHCP, DNS, route and permitted Internet egress from a dedicated journaled probe lease on a validated access VLAN | The workload-side path works without treating a public outage as a VM failure |
| Core health | API, worker, database and scheduler availability | Whether Core can evaluate and notify about the other signals |

The gateway watchdog may restart a known local service with a known valid configuration. If it cannot load the recorded policy, it disables forwarding and lease interfaces. It does not invent a policy, broaden egress, or recreate VM configuration. A gateway-local request cannot substitute for a workload-side canary. Core validates each admitted lease's VLAN mapping and configuration; a canary proves only its own access VLAN.

The watchdog validates the full firewall transaction before it brings lease interfaces or forwarding up. Its service restart budget and backoff are bounded. Exhausting them reports an incident and leaves the gateway fail closed.

Future records carry enough evidence to explain an incident without rereading logs:

| Record | Required facts |
| --- | --- |
| Health sample | Gateway generation, `received_at`, individual signals, freshness expiry, and canary result |
| Incident | Deduplication key, severity, first and last seen, acknowledgement, recovery, and delivery attempts |
| Node maintenance | Desired state, operator, reason, and expiry. Expiry never starts a gateway. An administrator explicitly resumes normal operation. |
| Repair plan | Expected pre- and post-states, dependencies, expiry, risk and impact, and idempotency key |

The first slice deduplicates open incidents by gateway and fault class, records recovery and observation events, and stores health/incidents in PostgreSQL. It sends no notifications. The target design also keys incidents by generation and policy generation, supports maintenance windows and makes best-effort configured sends. A LAN or Internet outage may prevent delivery, while the dashboard and local doctor can still show a persisted incident when Core is reachable. An independent receiver is required when the operator needs notice of a Core or LAN outage.

| Condition | Node action | Operator signal |
| --- | --- | --- |
| Gateway heartbeat stale, policy mismatch, reservation failure, or local service failure | Mark network `NOT_READY`; hold new work | Gateway degraded, with last good heartbeat and policy generation |
| PVE says gateway stopped, missing, or config differs | Hold node; classify as `QUARANTINED` when ownership cannot be proved | Gateway missing or changed; do not rebuild automatically |
| DNS or Internet canary fails while heartbeat and policy remain healthy | Hold new work only if the selected profile needs egress; identify upstream fault | Upstream DNS or Internet failure, not a confirmed gateway failure |
| PVE API unknown or cluster quorum lost | Hold affected nodes and preserve the last known policy | PVE visibility unavailable or quorum lost |
| Core unavailable | Gateway keeps persisted deny policy and reservations; Core cannot evaluate or alert | External watchdog should detect Core loss |

Core holds new work immediately for an identity or firewall mismatch. It holds new work when a heartbeat exceeds the stale threshold. Before admission it fails closed after the configured bounded staleness window. It clears the hold only when every required check passes and no quarantine or maintenance state remains. Healthy prepared nodes remain eligible. Core never moves an existing node-local workload just because another node is healthy.

Core cannot guarantee that it detects or blocks a trusted host administrator who creates a new LAN bypass outside Kiln's resources. Node qualification, runtime configuration checks, and incident reporting reduce that risk but do not override host root authority. Lease expiry needs a signed store that workloads cannot write, a trusted boot-clock design, and defined clock-rollback handling. Until those pass a bounded Core-outage, gateway-reboot, and clock-change test, automatic leases cannot be enabled. On lost clock trust after a gateway reboot or Core outage, the gateway denies expired or unverifiable traffic. That sacrifices availability to preserve isolation. The local expiry action revokes network access only. The gateway never receives PVE credentials or destroys a workload VM. Core performs guarded VM cleanup after reconciliation. Expired IP and VLAN reservations remain quarantined until Core proves the old attachment is gone. After Core returns, it reconciles uncertain expiry and provider state as `UNKNOWN` before any mutation.

An external monitor should poll a Core health endpoint or receive a separate heartbeat. It must not depend on the node gateway it is meant to report on. This is a deployment recommendation, not an implemented alerting feature.

## Doctor interface

The read-only commands and report endpoints below are available now. Repair-plan endpoints remain proposed and do not exist in the current CLI or API.

| Command or endpoint | Behavior |
| --- | --- |
| `kiln doctor` | Read-only installation, stored gateway evidence, open incidents and recovery guidance |
| `kiln doctor --network [--node name] --json` | Read-only report, optionally narrowed to a node; JSON is the Core response |
| `GET /v1/doctor?network=true&node=name` | Read-only doctor report for REST, CLI, MCP and dashboard |
| `GET /v1/incidents?status=open|all&node=name` | Read persisted gateway incidents |
| `GET /v1/gateways` | Read configured gateway records and last health observation; admin scope required |
| `POST /v1/doctor/network-repair-plans` | Creates an immutable, expiring repair plan. It binds operator, installation, node, resource generation, configuration digests, policy generation, dependencies, risk, and expected impact. |
| `kiln doctor repair` or `kiln doctor apply` | Unavailable. The CLI fails locally before sending a request. |
| `POST /v1/doctor/repair` | Explicitly returns 501. It performs no provider write. |

When Core is unreachable, the local CLI may report that limit and run read-only PVE diagnostics only with temporary credentials supplied by the operator. It must not retain those credentials, bypass Core, or start automatic repair.

`--apply` takes a node operation lock, writes an idempotency journal before each request, records the PVE task ID, runs post-checks, and enforces a cooldown with bounded attempts. A lost provider response becomes `UNKNOWN`; Kiln does not resubmit the request.

The default recovery policy does not automatically start or rebuild a hypervisor VM. Safe plan actions may start the same owned stopped gateway after an administrator explicitly applies a plan outside a maintenance window, restart a local service, or reapply the last verified policy when its hash and generation still match. A NIC, disk, provenance, attachment, or storage mismatch quarantines the node. It authorizes no mutation.

Replacement is separate from a restart. An explicit plan captures dependents, then confirms the old owned gateway is stopped, has `onboot=0`, has no HA membership, and has its journaled private NIC detached in PVE configuration. Core freshly verifies full identity and attachments and persists the fenced, retired generation before it allocates a new VMID and generation. An unknown HA entry or ownership drift needs manual operator resolution. Kiln must not mutate an external HA object. It revokes the old identity, restores only validated reservations and policy, and requalifies networking when the host changes. The retained disks remain available for investigation until an infrastructure administrator performs a separate guarded retirement. Trusted root can undo this; Kiln cannot prevent it. It admits workloads only after readiness passes.

## Failure handling and repair guidance

| Diagnosis | First operator action | Automatic action allowed |
| --- | --- | --- |
| PVE API unreachable or no cluster quorum | Restore PVE/API or quorum with normal PVE operations | None. Doctor records the dependency failure. |
| Gateway disk full | Inspect artifacts, logs, and reservation growth | None until a reviewed repair plan identifies the owned disk and safe cleanup. |
| Gateway stopped with exact matching provenance | Inspect the incident and maintenance window | A guarded same-instance start through an explicit doctor plan |
| Gateway policy differs or cannot load | Compare the recorded policy hash and generation | Restart or reapply only the exact verified policy, otherwise quarantine |
| VM, NIC, disk, or attachment mismatch | Investigate as possible administrator change or provider fault | None. No adoption, overwrite, or deletion. |
| Replacement required | Review dependency impact and old-instance fencing | Only after a separate explicit replacement plan passes all checks |

## Rollout and acceptance

The first shippable slice is implemented: read-only health reporting and node admission hold. Do not enable repair in the same release.

| Stage | Checkable acceptance |
| --- | --- |
| Bootstrap qualification | A one-host selection may be an explicitly standalone host or an eligible host in an existing cluster that passes preflight. A multi-node plan rejects no quorum, an offline selected node, hosts outside one existing cluster, and incomplete cluster or permission visibility. The temporary SSH check stores only evidence and never runs for a workload create. |
| Protected records | Generic lease expiry, workflow cancellation, project delete, and non-admin stop/destroy attempts cannot affect a gateway. |
| Health and hold | Killing DHCP, DNS, firewall, or the gateway blocks new work on that node and emits one incident plus recovery. Healthy nodes still accept new work. |
| Fail closed | Core loss, gateway reboot, and clock change preserve the last deny policy and prove signed lease-expiry handling. Uncertain expiry later reconciles as `UNKNOWN`. |
| Doctor diagnosis | Read-only doctor distinguishes upstream DNS/Internet loss, gateway failure, PVE visibility loss, quorum loss, and Core loss using saved evidence. |
| Doctor repair | A stopped matching gateway starts exactly once through a plan. A changed attachment, task timeout, or PVE visibility loss causes no duplicate or destructive request. |
| Replacement | Old identity is fenced, has its private NIC detached, and is revoked before a new generation becomes ready. A host reboot cannot let the old gateway serve DHCP. Existing workloads are not silently moved. |

Rollback disables repair-plan execution and new network admission while preserving existing deny policy. It does not delete gateways, networks, reservations, or workload VMs.

## Risks and early probes

| Risk | Early probe |
| --- | --- |
| PVE boot order does not match real readiness | Reboot a disposable node and verify gateway heartbeat and policy before a test workload starts. |
| Gateway state cannot survive Core loss safely | Stop Core during a lease expiry simulation and inspect forwarding, reservation persistence, and post-recovery reconciliation. |
| API reports an incomplete or stale VM configuration | Change a disposable owned attachment under controlled conditions and prove doctor quarantines without mutation. |
| Incident noise hides a real outage | Flap DNS, Internet egress, and a gateway service independently; inspect deduplication, severity, recovery, and maintenance behavior. |
| Replacement can create duplicate routing identities | Force a provider timeout after create and prove the journal prevents a second VMID or an old-identity reuse. |

## Open questions

1. What local persisted format can enforce lease expiry without letting a compromised workload edit it?
2. What gateway image and service supervisor meet the memory target while preserving enough evidence for diagnosis?
3. Which external monitor integrations should be supported first, and how should their credentials be scoped?
4. What PVE releases and cluster conditions pass the production qualification suite?
