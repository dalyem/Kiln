# Resource ownership and safety

## Two separate models

A managed resource is a persisted Kiln record. An observation is a provider object seen during discovery. Discovery never inserts observations into the managed-resource table. External resources remain observations even if their names, pool or tags look like Kiln's.

Ownership states:

| State | Origin | Lifecycle authority |
| --- | --- | --- |
| KILN_MANAGED | This installation created the resource and persisted provenance | Guarded lifecycle only |
| IMPORTED | Administrator explicitly imported this exact resource | Guarded lifecycle within recorded import scope |
| EXTERNAL | No valid ownership proof for this installation | Observation only |

`ORPHANED` describes an observation with Kiln-looking metadata and no matching database record. It is not a fourth ownership grant. `QUARANTINED` is a lifecycle state for a known record whose provenance or state needs investigation.

The database stores provider identity, native providerKind such as qemu or lxc, provider resource ID, installation UUID, resource UUID, expected pool and ownership tags. Native providerKind is distinct from the Kiln capability type such as development or browser. Future live creation also records a per-creation nonce, template provenance, provider task ID and attached resource graph. Provider IDs such as VMIDs are addresses, not permanent identities. Resource IDs must never be reused.

## Physical encoding

Require these guest tags, using lowercase PVE-safe characters:

```
kiln
kiln-managed
kiln-installation-<installation-uuid>
kiln-resource-<resource-type>
kiln-resource-id-<resource-id>
```

Pool membership must be exactly the configured Kiln pool. Tags with `=` from the original brief cannot be used because PVE's tag grammar forbids that character. The resource-type parser must distinguish the `kiln-resource-` and `kiln-resource-id-` namespaces. Reject conflicting, duplicated, malformed or missing ownership tags. Extra unrelated tags do not grant authority.

A future dedicated description block may carry signed structured provenance, but it cannot replace the database or provide protection against a fully privileged host administrator.

## Mutation path

Every lifecycle mutation, including start, stop and configuration changes, must pass this path:

1. Authenticate the caller and authorize the project and operation.
2. Load the exact persisted Kiln resource record. A supplied VMID or provider object cannot substitute for it.
3. Require KILN_MANAGED or IMPORTED with allowed lifecycle scope and this installation's UUID.
4. Acquire the resource operation lock and check lifecycle/idempotency state.
5. Inspect the provider object afresh. Authentication, transport, parsing and incomplete metadata failures deny the operation.
6. Match provider, object kind, provider ID, placement, pool, managed marker, installation marker, resource type marker and resource ID marker. Later live mutations also validate creation nonce and affected dependency provenance.
7. Persist operation intent and audit record. If audit persistence fails, stop.
8. Invoke the guarded provider operation. Phase 1 ProxmoxProvider always rejects this step; only the fake provider has lifecycle side effects.
9. Persist the result and event. Unknown provider outcome stays pending investigation rather than being retried as a new operation.

Any ownership mismatch emits `resource.safety_denied` and returns a sanitized denial. Never repair missing tags, move the resource into a pool or import it during this path. A stopped VM is not safer to delete. Expired leases do not override ownership.

Deletion of a VM may also delete disks, guest firewall rules and ACLs. Later delete authorization must enumerate affected child resources and reject unknown attachments or broadened deletion options. Pool ownership alone does not authorize changing network, storage, Ceph, cluster, firewall or pool configuration. Each mutable infrastructure object needs its own record and guard suited to its API semantics. Phase 1 treats all such objects as read-only.

## Limits of the guarantee

The boundary protects against Kiln mistakes, untrusted client requests, accidental naming collisions, stale records and ownership drift. PVE does not expose a universal compare-and-delete operation tied to Kiln tags. Re-fetching immediately before deletion narrows a race but does not make it atomic. A malicious PVE administrator can forge metadata and alter attached disks. The accepted threat model trusts PVE administrators. It does not promise protection against a malicious host administrator.

The safest current provider implementation has no real mutation transport. No runtime configuration turns one on. Tests verify fake lifecycle guard behavior and that real provider mutation methods reject operations. This is evidence for Phase 1, not certification of future PVE deletion.

## Import design, deferred

`kiln resource import vm 105` first produces an inspection plan listing exact resource, existing attachments, current pool, effects of moving it and lifecycle permissions Kiln would receive. An authenticated administrator must confirm that plan. Import is audited, writes a durable import intent, stamps verified metadata in an explicit enrollment operation and records the affected resource graph. Failure leaves the object external or quarantined. Import never silently claims unrelated disks or a whole existing pool.

Phase 1 has no import endpoint. Tests may seed IMPORTED records to test classification and guards. Seeding a test record is not an implementation of administrative import.

## Reconciliation design

- Known record, confirmed provider absence: mark LOST and emit an event. Do not recreate by default.
- Unknown provider object with Kiln tags: observation remains EXTERNAL, diagnostic ORPHANED. Do not delete.
- Known record with metadata mismatch: classify live observation external and quarantine known record. Require administrator investigation.
- Provider timeout or partial inventory: retain prior state with an observation error; do not infer absence.
- Migration to another node: require a recorded operation or explicit reconciliation of unchanged provenance before updating placement.

No cleanup loop selects resources by name, pool, stopped state, free space, or apparent lack of use.
