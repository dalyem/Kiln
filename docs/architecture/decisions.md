# Decisions and unresolved deployment questions

The user approved the following architecture decisions. They define the design target; production identity enrollment, network enforcement and real provider mutations still require implementation and verification.

| Decision                | Agreed direction                                                                                                                                              | Why it matters                                                                                                  | Status                                                                                                                                            |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| PVE administrator trust | Trusted administrators; quarantine a restored database before operations                                                                                      | An administrator can forge tags, attach external disks and reuse VMIDs; API checks cannot defeat host ownership | Accepted                                                                                                                                          |
| Tenant model            | Team structure from V1 within one trusted organization, distinct principal types and project scopes                                                           | Mutually untrusted tenants require stronger authorization, quotas, workload networks and secret isolation       | Accepted                                                                                                                                          |
| Sandbox networking      | Automatic private networking is the default. Existing networks and subnets are an advanced mode. Both require a proven isolation boundary before provisioning | A bridge, VLAN, or NAT rule does not prove that guests cannot reach peers, management, or storage               | Accepted product requirement; controlled PVE 9.2.2 lab evidence exists, but production and cluster qualification remain pending |
| Node qualification      | Automatic mode uses temporary, host-key-verified read-only SSH at installation, node preparation, relevant PVE upgrade, or declared host-network change        | PVE's structured API omits bridge-self VLAN membership needed to qualify the private network                     | Accepted; no host install or SSH credential retention; not required for each workload VM                                                        |
| Cluster bootstrap       | Standalone PVE is supported. Multi-node bootstrap requires an existing quorate PVE cluster and qualified online selected nodes                                | Kiln must not become a cluster-formation or Corosync repair tool                                                  | Accepted; Kiln never joins nodes, forces quorum, or changes expected votes                                                                       |
| Gateway operations      | Per-node gateway VMs are protected infrastructure with monitoring and explicit doctor repair plans                                                            | A node gateway carries private-network policy and cannot be ordinary lease-managed compute                       | Protected-record monitoring and read-only doctor reporting are implemented; real enrollment and the detailed repair contract remain proposed |

Trusting the organization does not mean trusting executed code. Agent workloads still require isolation. No trusted-LAN bypass has been approved. NAT is not an isolation boundary. A restored control plane must remain read-only until the former writer is fenced and resource ownership is reconciled. These are accepted requirements, not claims that the current scaffold implements restore, team authentication, or network enforcement. See [workload networking](networking.md).

## Enrollment and appliance consolidation

- Accepted: gateways should recover automatically after a Core outage using a previously enrolled, still-authorized device identity. Certificate renewal must preserve revocation, quarantine and lease-expiry rules. This is a design decision; recovery is not implemented yet.
- Accepted: bootstrap is one installation procedure that creates the main Kiln appliance, then hands management of new Kiln-created resources to Core. Existing administrator VMs and the current operator-created lab fixtures must not be adopted by this setup. Advanced networking may reference existing external networks without taking ownership of them.
- Accepted: use temporary Kiln-created probe VMs rather than requiring an always-on probe VM per node. Probes report evidence to Core; Core records the result and performs ownership-validated cleanup. Probe results do not independently authorize infrastructure repair. Probe cadence and freshness gates still need implementation and testing.
- Accepted: one main appliance runs Core, database, dashboard, continuous monitoring and probe orchestration. Automatic-mode routing runs in separate protected gateway VMs, one per prepared node running Kiln workloads. This supersedes the proposed combined Core-and-router appliance. Advanced existing-network mode does not require Kiln router VMs.
- Accepted: temporary probes exercise the workload network during installation, relevant network changes, recovery verification and deeper doctor checks. They are not required alongside every workload. Appliance management-network checks cannot substitute for guest-path evidence. Precise schedules, expiry of evidence and admission gates still require design and testing; deleted probes do not provide continuous guest-path monitoring.

## Workload movement and failure recovery

The appliance/router topology and the failure-response direction below are accepted. Recovery mechanisms and eligibility checks are not implemented. The accepted control-plane availability design is documented separately below.

- Accepted response direction: diagnose application, guest, router and host failures separately; restart locally where policy permits; hold new admission on a failed network; recover elsewhere only when eligible. Report failures and recovery outcomes in the UI and event stream.
- Accepted product intent: when the installation can safely recover a failed host's VM elsewhere, preserve its existing durable disks, record the destination and any network changes, and prevent the old instance from starting when its host returns. This is a restart from disk, not preservation of lost RAM or running processes. Never delete a shared disk as stale-source cleanup.
- Accepted fallback: when cross-node disk recovery is unavailable, retain important state on the original host and report the outage for operator action. Disposable sessions may be recreated elsewhere under their recovery policy. Interrupted build/execution attempts should report failure or an unknown execution outcome; an authorized retry is a new attempt, not a claim that the original command never ran.
- Open qualification detail: the user proposed Ceph as the automatic-recovery condition. Eligibility must also account for surviving storage availability, cluster quorum and fencing, destination network readiness and capacity. Whether other supported shared storage or replicated local storage qualify remains a design decision. Ceph presence alone cannot establish eligibility.

- Proxmox supports planned VM migration when CPU, devices, storage and network configuration permit it. Local disks can be copied during migration; shared storage is not mandatory for planned migration. Node failure is different: unavailable local disks cannot be copied from an unreachable source.
- Automatic mode currently uses node-local sandbox networks and per-node routers. Moving a VM does not transfer its router's policy, DHCP reservations or NAT connection state. Matching bridge names on two nodes do not establish a shared network. Ceph alone does not solve this network requirement.
- Implementation gate: place new workloads on any qualified eligible node, but keep active leases on their assigned node until destination network preparation, ownership reconciliation and recovery coordination are implemented and tested. The accepted conditional-recovery intent above extends the earlier recommendation to keep leases node-bound; it does not enable arbitrary migration or Proxmox HA today.
- An unreachable workload may still be running. Diagnose guest, router and host health separately. Do not launch a second writer from a missed heartbeat. Any replacement requires policy authorization, recoverable workspace state and proof that the old execution cannot continue; Kiln must not fence external hosts itself or race Proxmox HA.
- Later, a controlled restart or recreation on another qualified node can recover a workload where its disks or captured workspace are available. This does not preserve running processes, active connections or uncaptured guest edits. Non-idempotent commands must not be retried automatically just because their result is unknown.
- Live migration can be offered for a qualified cluster network and compatible storage/compute configuration. Failed-node restart requires accessible shared disks or a usable replica, sufficient capacity and a supported fencing/HA policy. Replication can lose changes since the last successful synchronization.

References: [Proxmox VM migration](https://github.com/proxmox/pve-docs/blob/master/qm.adoc#requirements), [Proxmox HA fencing](https://github.com/proxmox/pve-docs/blob/master/ha-manager.adoc#fencing), [Proxmox storage replication](https://github.com/proxmox/pve-docs/blob/master/pvesr.adoc). These describe provider capabilities, not a tested Kiln support matrix.

## Control-plane availability

- Accepted: one physical PVE node runs one Core appliance and has no host-failure HA.
- Accepted: a two-node existing PVE cluster runs one Core appliance and may schedule on either qualified node. It needs no Kiln replication, witness or Ceph to use Kiln. Normal PVE cluster quorum still governs PVE writes; Kiln never changes Corosync votes or forces quorum.
- Accepted: a qualified cluster with three or more physical PVE hosts runs three full appliance replicas on three distinct hosts, with one fenced infrastructure coordinator. This is the only advertised Kiln Core HA mode. It works with or without Ceph.
- Accepted availability target: after one control host failure, authenticated client operations, durable event delivery and safe admission must resume within 120 seconds. Acknowledged durable control records must survive. This is a release qualification requirement, not current behavior or a promise through quorum, storage or network loss.
- Accepted safety behavior: record durable intent before every PVE write; reconcile ambiguous operations after leader change; do not duplicate a provider write because a client lost its response. A returning former coordinator rejoins as follower or quarantine and cannot activate stale state.
- Accepted operational behavior: HA mode never falls back to an unsafe single-member mode after losing members. Adding nodes never automatically changes a one- or two-node installation into HA mode. Planned topology changes require an explicit qualified migration; an outage does not authorize bypassing quorum or durability.
- Artifact metadata is part of the durable control record. Artifact content, VM disks, browser profiles, working directories, unacknowledged stream data and process memory need separately qualified storage and recovery policies.
- The stable API/dashboard endpoint cannot rely on one appliance-hosted load balancer. The selected endpoint and fencing mechanism remain implementation gates.

The detailed design, alternatives, qualification and release matrix are in [control-plane availability](control-plane-ha.md). PostgreSQL with Patroni and a three-member etcd cluster are candidates, not selected or tested Kiln production configuration.

## Accepted implementation choices

- TypeScript Core, Go CLI/daemon, Python workflow SDK boundary, PostgreSQL and Drizzle, per the brief.
- One appliance VM and one control-plane writer in the current development stack. The accepted cluster HA design is documented separately and remains unimplemented.
- REST owns the external contract. MCP, CLI, SDK and UI are clients of it.
- Live provider is read-only in Phase 1. There is no hidden enable-mutations switch.
- Tags use dashes because `=` is invalid in PVE guest tags.
- Installation UUID persists in Postgres. Names and credentials never derive identity.
- EXTERNAL observations are separate from persisted managed-resource records.
- No automatic adoption, ownership repair, live pool creation or template mutation.
- Discovery uses a dedicated audit-only token. A future mutation token is a separate deployment concern.
- PostgreSQL is the durable default. Ephemeral memory mode must be explicit and visibly labeled.
- No domain deployment or registration is implied by kiln.dev branding.

## License decision: MIT

Accepted on 2026-09-10. Kiln uses the standard MIT license in the repository's LICENSE file. The user chose fully open-source distribution, superseding the earlier proposed resale and functional-improvement restrictions.

MIT permits use, modification, redistribution, commercial use and sale of unchanged or modified copies. Copies or substantial portions must retain the copyright and permission notices. The standard license's warranty disclaimer applies. This choice keeps reuse and contributions straightforward without adding custom licensing terms.

Sources: [MIT terms](https://opensource.org/license/mit), [Open Source Definition](https://opensource.org/osd).

## Decisions required before Phase 2 or Phase 3

1. Pin and test supported PVE major/minor versions. Current upstream source is evidence, not a support matrix.
2. Select API-compatible appliance artifact and verify file-backed staging storage for block-backed targets. Probe upload/import in a disposable lab.
3. Validate exact create/clone pool ACLs with a privilege-separated token. Publish tested commands only after permission tests.
4. Test the local Core LAN access, TLS, enrollment, address renewal, and CLI discovery design. Optional Tailscale remains private remote access, not an automatic requirement or public-exposure mechanism.
5. Choose production human sign-in and client enrollment. Local service tokens are development scaffolding, not a multi-user identity system.
6. Define import semantics for attached disks, snapshots, firewall objects and movement from an existing pool.
7. Complete release and production-node qualification for the automatic private-network construction on the pinned PVE release. This includes internal segments, anti-spoofing, IPv6 and link-local denial, protected-destination policy, DNS, egress, and allowed package/Git destinations.
8. Confirm image signing, update provenance and rollback policy before distributing appliance images.
9. Decide restore handoff/fencing procedure before the first backup restore can enable mutations.

## Direction after the foundation

Proceed to an explicit disposable-lab integration plan for one Development Lease: owned golden image, journaled VM creation from that image, outbound daemon enrollment, exact workspace transfer, authenticated preview, lease extension and guarded destruction. Use cloning only after equivalent ownership guarantees are verified. Do not claim that milestone from a fake provider run. Browser and workflow work remains behind this deployment proof.
