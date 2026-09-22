# Appliance, bootstrap, upgrades and backup

## Phase 1 local stack

The root Compose file starts PostgreSQL, the TypeScript API and the infrastructure dashboard on the contributor machine. It is a development control plane, not a built appliance image. A separate ephemeral mode runs without Postgres for unit tests and quick fake-provider exploration.

The API and dashboard bind published ports to loopback by default. The scaffold applies its initial SQL at API startup under the singleton writer lock; versioned production migration/rollback orchestration remains future work. PostgreSQL is private to the Compose network. Explicit development credentials are required. No Proxmox credentials are included in the repository or an image. Do not run this stack on a PVE hypervisor.

## Appliance design

The single-appliance design below is the current baseline for development, one-node installations and two-node installations. The accepted three-member HA design is in [control-plane availability](control-plane-ha.md). Cluster HA is not implemented. Do not deploy independent writable copies of this baseline as replicas.

Phase 2 builds `kiln-appliance-amd64.qcow2` from a minimal supported Linux image with Docker Engine and Compose, cloud-init, the pinned Kiln release manifest and first-boot setup. A qcow2 file is not produced by Phase 1. The appliance is a VM; Proxmox hosts remain hypervisors and need no npm, Node, Python, Playwright or Kiln daemon.

The appliance runs one API writer and Postgres. The dashboard is optional for functionality. Add a worker when tasks need independent process lifetimes; add a gateway when previews/browser/desktop sessions exist. In automatic network mode, the appliance uses its existing-LAN DHCP address while each eligible compute node runs a separate lightweight gateway VM for private workload networking. Keep the database on a persistent appliance disk. A separate workload storage target may be local or shared; Ceph is not required. See [workload networking](networking.md).

Cluster discovery is identical for one or many nodes. A one- or two-node installation retains one appliance and no Kiln HA requirement. A qualified three-or-more-node installation will use three replicas on distinct physical hosts, a single fenced coordinator and a redundant client endpoint. Ceph is optional for that Core HA design. A database advisory lock is not a substitute for coordinator fencing when copies of the database exist.

## Bootstrap plan

`kiln bootstrap proxmox` is a separate pre-Core client. The Phase 1 command is a plan-only scaffold. Future apply must follow a resumable journal:

1. Collect one endpoint, privilege-separated bootstrap credentials and verified CA, then inspect version, cluster membership, quorum, nodes, stores, pool and network inventory through GET calls. Explicit provider evidence may establish a standalone host. A one-row or permission-filtered inventory, `403`, or missing quorum data cannot. It denies bootstrap writes. A multi-node selection must already be one quorate PVE cluster with adequate membership visibility and qualified online selected nodes. Do not create or join a cluster, force quorum, or repair Corosync. An offline selected node appears as ineligible; an unselected member may be offline.
2. Ask the operator to select storage roles and access method. Automatic private networking is the default; existing networks and subnets are an advanced, explicit selection. Display existing uplinks, bridges, VLAN references, routes, and external workloads as read-only context. For automatic mode, temporarily use host-key-verified read-only SSH to capture the host baseline and access preflight on every selected online node. The credential is available only for bootstrap or a resumed bootstrap, installs nothing, uses a small read-only command allowlist, disables agent forwarding, and is never retained. This preflight does not qualify a private bridge that does not exist yet. Verify capability and visibility limits.
3. Select appliance artifact format and verify signature, digest and minimum PVE compatibility. File-backed staging is needed for raw qcow2 upload when target storage is block-backed. Do not shell out to `qm importdisk` on a hypervisor.
4. Select the control-plane mode. One selected physical node uses one appliance. Two selected nodes use one appliance without Kiln HA. HA selection requires three selected, online, qualified physical hosts in distinct fault domains, a redundant endpoint plan and the controls in [control-plane availability](control-plane-ha.md). Do not infer physical fault domains from VM count. Then produce a concrete change plan containing exact new pool/control VM/storage usage, VMID reservation attempt, expected image digest, and network settings. For automatic mode, include a node-local private network, protected gateway VM, allocated CIDR, policy, boot readiness gate, and external uplink reference. Refuse an ambiguous existing `kiln` pool or control VM until ownership is established; never auto-adopt based on name.
5. Persist a bootstrap installation UUID and operation journal on the operator machine before any create call. Bootstrap-created resources need provenance before the new database exists. This journal is imported during first boot, not reconstructed from names.
6. Create only planned objects. Tag managed VMs with the installation and resource identities, and record API-specific provenance for network objects that do not support VM tags. Journal returned provider task IDs and await completion. A timeout does not trigger another VM allocation.
7. Deliver distinct single-use enrollment material through first-boot configuration before starting an appliance or gateway that needs an authenticated Core identity. Keep permanent hypervisor credentials exclusively in Core after a deliberate handoff; rotate bootstrap credentials.
8. Poll authenticated appliance readiness and confirm the same installation UUID. For HA mode, prove replica durability, coordinator fencing and endpoint ownership before marking the installation HA-ready. After the SDN apply and gateway creation, rerun the read-only SSH qualification against the created private bridge. Capture bounded redacted evidence and before/after host configuration hashes. Then run gateway readiness and workload-side canaries. A failed check blocks user workload admission.
9. Point normal CLI configuration at Kiln REST.

Automatic private networking is a reviewed bootstrap plan, not a PVE host package, host NAT, global firewall, router, VLAN-hardware, static-route, UPnP, or port-forward change. Existing-network mode needs an explicit operator selection and isolation proof. Bootstrap rollback only considers exact journaled objects and validates fresh ownership. Unknown or partially tagged resources require investigation rather than automatic removal. The gateway is protected infrastructure, never a disposable resource. Its monitoring and proposed doctor recovery procedure are in [gateway operations](gateway-operations.md). The proposed construction and its gates are in [workload networking](networking.md).

## Permissions

Phase 1 uses audit-only permissions documented in [Proxmox evidence](proxmox-evidence.md). The backing PVE service user and its privilege-separated token both need the intended rights. Permission-filtered API lists cannot prove cluster completeness.

Do not distribute an untested broad role called "minimal". Phase 2 must test the selected create, clone, import, configure and power paths against the pinned PVE release and pool ACLs. Bootstrap-only pool allocation and any reviewed SDN privileges should not remain in the normal runtime token. Storage allocation privileges are limited to selected targets. Never grant Ceph administration or cluster networking privileges for basic workloads.

TLS verification is mandatory. Local development can trust a private PVE CA through the runtime CA bundle. Never set `NODE_TLS_REJECT_UNAUTHORIZED=0` or add an insecure transport mode.

## Upgrade design

A release manifest pins OCI image digests and schema compatibility. Upgrade obtains an appliance-level maintenance lock, stops new writes, waits for or records active operations, exports a matched backup, pulls verified images, applies ordered migrations, restarts services and probes API/database/worker health. Existing leases remain durable and the worker catches up on restart through the normal guarded path.

HA upgrades are cluster-wide operations, not independent appliance updates. A tested application/schema compatibility matrix controls which members may serve requests or become coordinator. One migration authority holds the cluster-wide upgrade lock. Compatible rolling upgrades preserve quorum, synchronous durability and at least one eligible coordinator. For an incompatible migration, drain writes and incompatible readers, fence promotion to old code, and enter explicit maintenance before changing the schema. Do not claim the normal 120-second failover target during an announced incompatible maintenance window. Release the maintenance and promotion gates only after the required members run compatible code and pass health checks. A host failure during migration must leave the operation journaled and safely paused or resumable, never promote an incompatible member.

Failure before migration permits rollback to old images. After a non-backward-compatible migration, restore the matched backup into quarantine or use a specifically tested forward fix. Never promise automatic rollback for arbitrary migrations. The scaffold has no upgrade executor.

In HA mode, rollback must also preserve the compatibility matrix and coordinator fencing across every member. Never downgrade or restore one member independently against the live upgraded cluster. Restore after an incompatible migration is an explicit cluster recovery with a declared data-loss boundary; a pre-upgrade backup cannot preserve writes acknowledged after that backup.

## Backup and restore design

Normal Proxmox backup protects the control VM. Disposable workload VMs do not need routine backup, but artifact retention and browser identities may hold persistent data and must be covered by policy.

In HA mode, an individual appliance VM backup is not a self-contained cluster restore. Recovery must coordinate database history, installation keys, member identity, leadership and endpoint ownership with the surviving cluster. A stale restored member starts quarantined and must never start independently as a primary or issue PVE writes. Use the qualified cluster recovery procedure to rejoin or replace a member; test stale snapshots and clones against a live cluster as required by [Core HA qualification](control-plane-ha.md#release-qualification).

`kiln backup` will export database, configuration, provider/project/workflow definitions and encrypted secret material with schema/release/installation metadata and checksums. Encryption keys require a separately protected recovery mechanism. Exporting ciphertext without recoverable keys is not a usable backup.

Restore must verify the backup, restore the same installation identity and secrets, start read-only in quarantine, fence the former appliance and compare recorded operations/resources with current PVE state. Only an administrator can enable lifecycle management after reconciliation. A restored old lease or resource row cannot by itself authorize deletion. Phase 1 has no backup/restore apply implementation.
