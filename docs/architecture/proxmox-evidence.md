# Proxmox Phase 1 evidence

Retrieved 2026-09-08 from official Proxmox Git repositories with shallow,
read-only `git clone --depth=1` calls. The commit hashes below identify the
exact source read. The normal HTML API viewer returned HTTP 403 to the web
reader in this environment, but the linked upstream source URLs returned HTTP
200 with `curl -L --fail` on the same date.

This document describes observed Proxmox VE source behavior. It does not grant
Kiln permission to mutate a provider. Kiln ownership checks remain a Kiln
security policy.

## Versions and source caveats

| Repository | Commit read | What it establishes |
| --- | --- | --- |
| [pve-manager](https://git.proxmox.com/?p=pve-manager.git;a=commit;h=614bede5d65599c67e068cbf18d49717ea8ab33b) | `614bede5d65599c67e068cbf18d49717ea8ab33b` | Cluster, node, pool, and HTTP API handlers. |
| [qemu-server](https://git.proxmox.com/?p=qemu-server.git;a=commit;h=6c0127e612f6c576888a13f9bfb30874911b804d) | `6c0127e612f6c576888a13f9bfb30874911b804d` | QEMU guest API handlers. |
| [pve-storage](https://git.proxmox.com/?p=pve-storage.git;a=commit;h=7c6a03839920d4939a8ae725a2b0ef91c0cbc6c9) | `7c6a03839920d4939a8ae725a2b0ef91c0cbc6c9` | Storage API handlers. |
| [pve-common](https://git.proxmox.com/?p=pve-common.git;a=commit;h=f665029eac78022e81810ab2e44eace57ade13fb) | `f665029eac78022e81810ab2e44eace57ade13fb` | Tag validation. |
| [pve-access-control](https://git.proxmox.com/?p=pve-access-control.git;a=commit;h=5ccd07d9302562b73374d331b63d25b04b86766c) | `5ccd07d9302562b73374d331b63d25b04b86766c` | Token privilege separation. |

The endpoint and permission checks can change between Proxmox releases. The
provider should record the detected PVE version, probe its required read-only
calls during connection setup, and run a supported-version integration suite
before any write path is enabled.

## Read-only discovery

| HTTP request | Verified access check or filtering | Phase 1 use | Source |
| --- | --- | --- | --- |
| `GET /api2/json/cluster/resources?type=vm` | Results are filtered by object permissions. The handler checks `VM.Audit` for guests. | Cluster-wide inventory and external-resource classification. | [Cluster handler](https://git.proxmox.com/?p=pve-manager.git;a=blob;f=PVE/API2/Cluster.pm;h=614bede5d65599c67e068cbf18d49717ea8ab33b#l264) |
| `GET /api2/json/cluster/status` | `Sys.Audit` on `/`. | Cluster membership and quorum status. | [Cluster handler](https://git.proxmox.com/?p=pve-manager.git;a=blob;f=PVE/API2/Cluster.pm;h=614bede5d65599c67e068cbf18d49717ea8ab33b#l868) |
| `GET /api2/json/nodes` | Node fields are limited when the caller lacks `Sys.Audit` on each node. | Node names, high-level capacity, and TLS fingerprints. | [Nodes handler](https://git.proxmox.com/?p=pve-manager.git;a=blob;f=PVE/API2/Nodes.pm;h=614bede5d65599c67e068cbf18d49717ea8ab33b#l2909) |
| `GET /api2/json/nodes/{node}/status` | `Sys.Audit` on `/nodes/{node}`. | Node CPU and memory metrics. | [Node status](https://git.proxmox.com/?p=pve-manager.git;a=blob;f=PVE/API2/Nodes.pm;h=614bede5d65599c67e068cbf18d49717ea8ab33b#l354) |
| `GET /api2/json/nodes/{node}/storage` | Lists stores with `Datastore.Audit` or `Datastore.AllocateSpace` on `/storage/{id}`. | Storage capability and capacity discovery. | [Storage status](https://git.proxmox.com/?p=pve-storage.git;a=blob;f=src/PVE/API2/Storage/Status.pm;h=7c6a03839920d4939a8ae725a2b0ef91c0cbc6c9#l68) |
| `GET /api2/json/nodes/{node}/qemu` | Lists only VMs with `VM.Audit` on `/vms/{id}`. | Per-node guest state. | [QEMU list](https://git.proxmox.com/?p=qemu-server.git;a=blob;f=src/PVE/API2/Qemu.pm;h=6c0127e612f6c576888a13f9bfb30874911b804d#l1075) |
| `GET /api2/json/nodes/{node}/qemu/{vmid}/config` | `VM.Audit` on `/vms/{vmid}`. | Read tags, disk configuration, and config digest before classification; pool membership comes from inventory/pool APIs. | [QEMU config handler](https://git.proxmox.com/?p=qemu-server.git;a=blob;f=src/PVE/API2/Qemu.pm;h=6c0127e612f6c576888a13f9bfb30874911b804d#l1702) |
| `GET /api2/json/pools/{poolid}` | `Pool.Audit` on `/pool/{poolid}`. | Inspect explicit `kiln` pool membership. | [Pool handler](https://git.proxmox.com/?p=pve-manager.git;a=blob;f=PVE/API2/Pool.pm;h=614bede5d65599c67e068cbf18d49717ea8ab33b#l20) |

For a truthful all-resource EXTERNAL view, the discovery identity needs
`VM.Audit` over the intended guest scope and `Datastore.Audit` over the
intended storage scope. Otherwise the API omits objects. A partial inventory
must say `PARTIALLY_OBSERVED`, never imply that omitted guests do not exist.

## Authentication and least privilege

Use a dedicated Proxmox user with an API token created with privilege
separation enabled. The token has only its own ACLs, and those ACLs remain a
subset of its backing user's available rights. API-token calls are stateless;
the server skips CSRF checks for them. Ticket authentication is a separate
browser-oriented mechanism and requires a CSRF prevention token for mutations.

| Phase | Token ACLs | Reason |
| --- | --- | --- |
| Phase 1 discovery | `Sys.Audit` on `/`; `VM.Audit` on `/vms`; `Datastore.Audit` on `/storage`; `Pool.Audit` on `/pool` | Discover cluster, nodes, storage, pool membership, and guest configuration without writes. |
| Bootstrap only | Add `Pool.Allocate` for creating the `kiln` pool. | Pool creation is a write operation. Remove from the normal runtime token. |
| Later workload management | Add only after a separate design and provider integration tests: `VM.Allocate`, `VM.Clone`, `VM.Config.Options`, `VM.Config.Disk`, `VM.PowerMgmt`, and `VM.Snapshot` on the exact managed scope; `Datastore.AllocateSpace` on selected Kiln storage; `SDN.Use` only on configured bridge or VNet paths. | QEMU create and clone checks require these rights by operation. |

Sources: [official administration guide, API-token privilege separation](https://pve.proxmox.com/pve-docs/pve-admin-guide.pdf), [token role code](https://git.proxmox.com/?p=pve-access-control.git;a=blob;f=src/PVE/AccessControl.pm;h=5ccd07d9302562b73374d331b63d25b04b86766c#l1792), and [token/CSRF request handling](https://git.proxmox.com/?p=pve-manager.git;a=blob;f=PVE/HTTPServer.pm;h=614bede5d65599c67e068cbf18d49717ea8ab33b#l84).

Kiln must use HTTPS certificate validation. Bootstrap should record a verified
CA chain or an administrator-confirmed server certificate fingerprint. It must
not expose an "accept any certificate" configuration.

## Ownership and destructive operations

Proxmox does not enforce Kiln ownership. Its delete endpoint requires only
`VM.Allocate` on the target guest. It removes the VM, its used or owned
volumes, VM ACLs, and VM firewall configuration. An optional
`destroy-unreferenced-disks` parameter makes cleanup broader.

The provider must therefore deny a destructive request unless all checks below
pass in one operation attempt:

1. Kiln has a current database resource record for the provider VM.
2. The record is `KILN_MANAGED` or an explicitly approved `IMPORTED` record.
3. A fresh QEMU config read identifies the expected VM ID, node, and QEMU type.
4. The guest belongs to the expected `kiln` pool.
5. Its tags include `kiln`, `kiln-managed`, the expected installation tag, type
   tag, and resource-ID tag.
6. The lease or explicit admin operation permits this lifecycle action.
7. The database operation row owns an idempotency key and records the fresh
   provider observation immediately before the delete request.

Any failed read, missing field, changed tag, wrong pool, wrong installation,
or ambiguous provider result must deny the mutation and emit a safety event.
Never pass `destroy-unreferenced-disks` in Phase 1.

Proxmox locks guest configuration and repeats some internal checks during
deletion. That prevents particular provider races but does not bind deletion to
Kiln's ownership policy. The real protection is Kiln's revalidation immediately
before its API call plus its narrowly scoped credential.

Sources: [delete endpoint and required `VM.Allocate`](https://git.proxmox.com/?p=qemu-server.git;a=blob;f=src/PVE/API2/Qemu.pm;h=6c0127e612f6c576888a13f9bfb30874911b804d#l2775), [delete implementation](https://git.proxmox.com/?p=qemu-server.git;a=blob;f=src/PVE/API2/Qemu.pm;h=6c0127e612f6c576888a13f9bfb30874911b804d#l2853), and [pool modification behavior](https://git.proxmox.com/?p=pve-manager.git;a=blob;f=PVE/API2/Pool.pm;h=614bede5d65599c67e068cbf18d49717ea8ab33b#l225).

## Tag and VMID limits

Proxmox guest tags do not accept `=`. The exact validation regex is
`[a-z0-9_][a-z0-9_\-+\.]*`, case-insensitively. Kiln tags must use a
delimiter allowed by that grammar, for example:

```text
kiln
kiln-managed
kiln-installation-abc123
kiln-resource-development
kiln-resource-id-dev_84721
```

The full ownership values also belong in PostgreSQL. Tags are corroborating
provider metadata, not a source of truth by themselves.

`GET /cluster/nextid?vmid=<id>` reports whether an ID is free at that instant.
It is not a durable provider identity. Proxmox's cluster file system provides
strong checks to avoid duplicate VM IDs, but a later user or process can reuse
an ID after deletion.

Kiln should persist provider creation time and a fresh random ownership nonce
alongside the required tags. This is a Kiln recommendation inferred from the
VMID reuse risk. Proxmox does not provide it as an ownership guarantee.

Sources: [tag regex](https://git.proxmox.com/?p=pve-common.git;a=blob;f=src/PVE/JSONSchema.pm;h=f665029eac78022e81810ab2e44eace57ade13fb#l890), [next-ID endpoint](https://git.proxmox.com/?p=pve-manager.git;a=blob;f=PVE/API2/Cluster.pm;h=614bede5d65599c67e068cbf18d49717ea8ab33b#l1014), and [pmxcfs guarantees](https://pve.proxmox.com/pve-docs-9-beta/chapter-pmxcfs.html).

## Appliance QCOW2 import

The storage upload endpoint accepts `content=import` but rejects storage
without a filesystem path. QEMU create supports disk `import-from` syntax.
The traditional `qm importdisk` entry point exists in the CLI code, not as a
dedicated REST handler.

The pinned upload handler checks `Datastore.AllocateTemplate` on the staging
storage. Importing the uploaded volume additionally requires source access
(`Datastore.Audit` is sufficient) and `Datastore.AllocateSpace` on the target
storage for the new disk. Upload permission is not interchangeable with target
allocation permission. The handler can overwrite an existing upload name, so
Kiln must reserve a unique staging identity, verify its absence, persist intent
before dispatch and never repeat an upload whose outcome is unknown.

These source checks inform the Linux import implementation; its actual 8 GiB
VM configuration and permissions remain subject to KILN-26 lab qualification.

Phase 2 bootstrap therefore needs one of these tested paths:

- a file-backed staging storage where the appliance QCOW2 can be uploaded as
  import content, followed by QEMU create with `import-from`; or
- an appliance delivered as a supported Proxmox backup archive and restored by
  the QEMU create/restore endpoint.

Do not assume a raw QCOW2 can upload straight into block-only RBD, LVM-thin, or
ZFS storage through the generic upload endpoint. This is a verified API limit.

Sources: [storage upload handler](https://git.proxmox.com/?p=pve-storage.git;a=blob;f=src/PVE/API2/Storage/Status.pm;h=7c6a03839920d4939a8ae725a2b0ef91c0cbc6c9#l519), [QEMU create and import-from validation](https://git.proxmox.com/?p=qemu-server.git;a=blob;f=src/PVE/API2/Qemu.pm;h=6c0127e612f6c576888a13f9bfb30874911b804d#l1160), and [CLI importdisk command](https://git.proxmox.com/?p=qemu-server.git;a=blob;f=src/PVE/CLI/qm.pm;h=6c0127e612f6c576888a13f9bfb30874911b804d#l614).
