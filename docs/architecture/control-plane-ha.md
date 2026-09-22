# Control-plane availability

## Problem and decision

Kiln must keep its control records intact and restore authenticated API access within 120 seconds after one qualified control-plane host fails. A short interruption to the dashboard, agent connections and event streams is acceptable. Running workloads, browser sessions, RAM-only process state and unacknowledged output are outside that promise.

Kiln supports these modes:

| Installation | Control-plane topology | Availability promise |
| --- | --- | --- |
| One physical PVE node | One appliance VM | No host-failure HA. |
| Two-node existing PVE cluster | One appliance VM | No Kiln HA or replication requirement. The installation may schedule work on either qualified node. Normal PVE quorum still governs PVE writes. |
| Three or more qualified physical PVE nodes | Three full appliance replicas on three separate hosts | One host failure must restore authenticated operation, event delivery and safe workload admission within 120 seconds, without losing acknowledged durable control records. |

Three appliance replicas are enough on a larger cluster. Kiln does not install a replica on every compute node. A three-member mode does not automatically shrink to one writable appliance after members fail. It stops unsafe writes when it cannot preserve quorum and durability.

This is the accepted product direction. It is not implemented or qualified today.

## Options considered

One appliance protected by Proxmox HA is simpler and fits a cluster with surviving shared storage. It still has an outage while Proxmox fences and restarts the VM. It does not meet the requested non-Ceph recovery model without adding separate replication.

Three replicated appliances add PostgreSQL replication, leader coordination, endpoint failover and fencing work. They meet the same HA model with or without Ceph, and avoid maintaining different Core availability systems. That is the accepted design.

Independent writable appliance copies are unsafe. A load balancer can route requests, but it cannot preserve database history or stop two coordinators from provisioning the same infrastructure.

## Design

Each HA appliance contains Core and a PostgreSQL member. One elected appliance is the infrastructure coordinator. Only that coordinator may issue Proxmox writes. The others serve health checks and become candidates after a safe leadership change. Every acknowledged control record must commit under the selected synchronous durability policy before Core returns success.

Core awaits synchronous durable acknowledgement of an operation intent, idempotency key and request hash before each Proxmox write. A timed-out intent commit does not authorize dispatch. After leader change, an uncertain request is reconciled against its operation record and Proxmox task or resource state. A new leader never repeats a PVE request merely because the client lost a response.

The old coordinator must lose write authority before a new coordinator receives it. Database advisory locks alone do not provide that protection. The chosen implementation must fence coordinator access to PVE credentials and write paths, handle an isolated old appliance, and keep a former primary in follower or quarantine state when it rejoins. A stale restored backup must never self-promote.

PostgreSQL with [Patroni replication modes](https://patroni.readthedocs.io/en/latest/replication_modes.html) and a three-member [etcd quorum](https://etcd.io/docs/v3.6/faq/) are candidate building blocks. Their exact versions, strict synchronous commit settings, leader lease, promotion rules, credential fencing and recovery commands remain unqualified. Kiln must never silently fall back to asynchronous acknowledgement to meet the 120-second target.

The client address also needs redundancy. A sole load balancer inside the failed appliance is not a stable endpoint. The qualified deployment may use fenced LAN virtual-IP ownership or an external endpoint, but it must prove that only the elected coordinator accepts mutating traffic. Read requests may use a different route only after their consistency rules are defined.

### Durable state

The HA promise covers acknowledged control metadata: installation identity, resource ownership and provenance, leases, operation journals, idempotency records, events, configuration, policy and recoverable secret material. Key encryption and recovery need their own replicated, access-controlled design. A copied database without usable keys is not a usable control-plane recovery.

Artifact metadata is part of the durable records. Artifact content is covered only when it resides on storage that has separately passed the same availability and integrity requirements. VM disks, working directories, browser profiles, process memory and streamed output that has not been persisted remain subject to their own resource recovery policies.

### Bootstrap qualification

Bootstrap selects one of the three modes and records it in the installation configuration. A one-node install creates one appliance. A two-node existing cluster creates one appliance and does not require a witness, Ceph or Kiln replication to use Kiln. It must still have normal PVE quorum for PVE cluster writes. Kiln never joins nodes, changes Corosync votes or forces quorum.

HA mode requires three online, selected, qualified PVE hosts in distinct physical fault domains, plus a tested control network and durable appliance disks. Use independent node-local control disks by default so Core does not depend on the workload Ceph cluster staying available. Three nested appliances on one physical host are useful for software tests but do not qualify as a host-failure proof. Ceph is optional for Core HA mode. It may improve other resource recovery policies.

Adding a node does not automatically promote an existing one- or two-node installation to HA. An administrator must run a separate, qualified migration that creates replicas, establishes durability and fencing, moves the stable endpoint, and proves failover. A failed three-member setup also never degrades itself into an unsafe single-member mode.

### Bootstrap and recovery behavior

Bootstrap journals every appliance creation and delivers distinct appliance identities within the same installation UUID before any appliance starts. It confirms physical-host placement, replica health, synchronous durability status, endpoint ownership and coordinator fencing before advertising HA readiness. Router VMs remain one protected gateway per prepared workload node. Temporary probes remain workload-side checks; neither changes Core HA membership.

After one control host fails, survivors first establish quorum and a fenced coordinator. The endpoint then restores authenticated API access. Clients reconnect and event delivery resumes from durable event positions. New workload admission remains held until the coordinator's state and required network health gates are ready. If these steps cannot complete safely, Kiln reports degraded control-plane health and rejects mutations.

When the former primary returns, it joins only as a follower after it discards or reinitializes stale state through the qualified recovery procedure. It cannot activate a restored snapshot or reuse old credentials to reclaim coordination.

## Release qualification

The 120-second clock starts at a simulated or actual loss of one control-plane host. A passing test must show all of the following:

| Case | Required evidence |
| --- | --- |
| Loss of each control-host role | Repeat host loss for the coordinator, database primary, current synchronous standby and other follower roles as applicable. Authenticated operations, durable events and safe admission recover within 120 seconds in every single-host case; changing synchronous standby must preserve acknowledged writes. |
| Asymmetric coordinator partition | Isolate the old coordinator from database/leadership peers while leaving its existing credentials and PVE access intact. Survivors may take over only after the old coordinator loses mutation authority. Provider-side evidence must show no interval with two authorized mutators, including delayed and resumed requests. |
| Event resumption | A client reconnects and receives durable events without losing acknowledged records. |
| Admission safety | The new coordinator admits work only after leadership, database and network gates pass. |
| Ambiguous PVE request | Failover reconciles the recorded intent and does not duplicate a provider write. |
| Former coordinator return | It remains fenced or follows the current primary, and cannot issue writes. |
| Stale appliance snapshot or clone | Restore an old coordinator image while the current cluster is live, retaining stale identity, leadership and PVE credentials. It must remain quarantined, acquire no client endpoint and issue zero PVE writes. |
| Quorum loss | Kiln rejects mutations rather than accepting unreplicated ownership changes. |
| Endpoint loss | The client reaches the replacement coordinator without a single appliance-hosted load balancer. |

Implementation starts with a local, reproducible three-member fault test using the fake provider. It must exercise each host role, asymmetric partitions, stale-image restoration, promotion, fence enforcement, acknowledged-write survival, operation ambiguity and client reconnection. Next, an isolated three-physical-fault-domain PVE qualification must repeat the matrix with the intended endpoint and identity system. Only then may a release advertise Core HA readiness.

## Open implementation gates

- Select and pin the PostgreSQL, Patroni and etcd releases, then test their exact strict-synchronous and promotion behavior.
- Design the fencing path for PVE credentials and Core write workers.
- Select and test the stable endpoint mechanism on supported LANs.
- Define backup, encryption-key recovery and artifact-content durability for HA mode.
- Define migration from a single appliance to HA mode and its rollback boundary.

Provider HA and workload recovery remain separate. Proxmox fencing and storage/network eligibility govern whether a failed workload can restart elsewhere. See [decisions](decisions.md#workload-movement-and-failure-recovery).
