# Image and attachment provenance

## Scope and success criteria

Kiln needs evidence for the template it clones and every object a VM operation can affect. VM names and tags alone cannot authorize deleting disks or changing shared infrastructure.

Stage 1 implements a fake-provider path from a verified image manifest through a managed template, an immutable full-clone plan and guarded lifecycle operations. PostgreSQL must preserve the same records and uncertainty across restart. Proxmox remains read-only during this stage. A fake import does not qualify image transfer, storage semantics, network placement or live provisioning.

Stage 2 follows after tests and independent review. It qualifies a newly created disposable probe in the nested lab, with bounded write permissions and fresh checks against the installed Proxmox version. Existing operator fixtures remain external. A managed gateway follows the probe because it adds routing policy, protected lifecycle and admission requirements.

## Decision

Extending VM ownership tags alone would leave child objects and clone lineage unaccounted for. A general image registry, signing service and storage controller would add several systems before Kiln has a working provisioning path.

Use immutable image, template, plan and attachment records in the existing database, with verification in Core and effects behind the provider contract. Start with full clones. This costs additional records and conservative refusals, but avoids linked-disk dependency semantics until those can be qualified separately.

## Image trust and template lineage

A portable image manifest describes its name, version, architecture, artifact digest and size, source build and capabilities. Ed25519 signatures cover a canonical representation. Core accepts signatures only from operator-configured public keys. An import request cannot introduce its own trusted signer. Artifact verification computes the digest over the actual supplied bytes; a caller-provided digest is not evidence that a transfer occurred.

Trust policy constrains a signing key to approved image names, capabilities and architectures. The initial manifest schema and digest algorithm are fixed. Preserve the signer fingerprint and matched policy digest with the accepted image. A signature from a development-image publisher cannot authorize a gateway image unless the operator's policy permits it.

Provider identities do not belong in the portable signed manifest. An installation-specific template record separately binds the image to a Core-generated resource ID, creation nonce, provider identity, placement, intended configuration and import operation. No API adopts an arbitrary existing template. Familiar names or matching tags do not make a replica eligible.

An eligible template requires a known successful import and matching observed configuration. The import operation binds a canonical intent digest covering the image identity, manifest digest, capabilities, creation nonce, provider placement and attachments. Recovery recomputes that binding from the durable image and template records before accepting completion. An ambiguous submission or mismatched observation remains blocked. The record describes the chain of custody; it does not claim continuous byte-level integrity of a mutable disk.

## Attachments and external references

Each owned attachment has an explicit immutable record tied to its parent resource and provisioning intent. The inventory accounts for boot and data disks, cloud-init, EFI/TPM state, unused volumes and network interfaces. Firewall and HA configuration affect the observed configuration too. Unsupported devices, incomplete inventory and unexpected fields fail closed.

Storage targets and bridges can be approved external references. Using them grants no authority to modify or delete them. An external writable disk cannot become an owned child because it is attached to a managed VM. References must match the saved plan exactly; unexpected disks or NICs are never detached automatically to make a guard pass.

Provider output never grants ownership. Stage 1 preallocates exact fake child identities in the intent and requires observations to match them. Enforce unique provider child identities across resources. A future live adapter whose allocation returns new native IDs must separately qualify how those IDs are bound to the successful operation; it cannot simply insert whatever disks it observes as owned.

The first implementation supports a deliberately narrow fake configuration. Its normalized graph is not a qualified Proxmox configuration parser. Stage 2 must enumerate actual provider fields and attachment effects before enabling live operations.

## Plans and operation guards

A full-clone plan separately binds source template and destination resource. It includes the canonical template intent digest, exact source provider identity and configuration, destination nonce and placement, owned attachments and approved external references. Core generates destination identities; callers request capabilities and permitted profiles. The fake provider checks the recorded source before clone effects, and Core verifies source and destination evidence before accepting completion. A missing source during this Stage 1 path leaves the outcome blocked.

Persist the resource, immutable plan, attachment records and audit evidence before effects. The operation journal binds the plan digest. The resource must retain an independent marker that provenance is required, so losing its plan cannot silently downgrade it to legacy fake lifecycle handling.

Before dispatch, inspect the source where relevant and the complete affected configuration. Before completion, verify fresh destination ownership and attachment observations against the retained intent. Provider callbacks receive copies, never authoritative records. Start, stop, destroy, TTL cleanup and asynchronous reconciliation must all use the same guards.

Missing or changed evidence denies mutation and emits a safety event. Unknown provider outcomes remain fenced; no automatic retry allocates another template or VM. Template retirement refuses live dependents and uncertain operations. References from an unresolved clone remain pinned even if its destination has not become ready.

Clone reservation and template retirement serialize on the same template record. A clone pins its dependency while the template is eligible, atomically with plan creation. Retirement checks dependencies and changes eligibility under that same lock. Database foreign keys restrict deletion of referenced provenance. Exercise concurrent clone and retirement requests in both stores.

## Persistence, API and rollout

Use an additive migration with separate image, template/lineage, plan and attachment records. Preserve immutable bindings and enforce identity uniqueness. Do not backfill historical provenance from current observations. MemoryStore must provide the same copy isolation and state guards as PostgreSQL.

Image import and template administration require the infrastructure identity in this contributor release. Project-scoped resource creation may select an eligible template with the requested capability. Project-authorized reads return sanitized provenance summaries. Signing keys are operator configuration; raw provider handles and snapshots are not routine API output. CLI, MCP and future UI integrations remain adapters over Core operations.

The bounded fake artifact path is for exercising verification. Large image distribution, persistent artifact storage, production publisher-key lifecycle and real image import remain separate work. Existing legacy fake resources remain simulation-only and cannot acquire template authority.

Stop application writers and restore a matched database backup to roll back an incompatible schema change. Never run an older writer against provenance records it does not understand.

## Required verification

- Accept a correctly signed manifest and matching artifact. Reject altered bytes, altered metadata, unknown signers and unsupported input before dispatch.
- Create a fake managed template and full clone, then exercise lifecycle through the shared Core boundary.
- Reject changed templates, source/destination confusion, extra NICs, foreign or missing disks and changed external references without provider mutations.
- Refuse template retirement while live or unresolved clones depend on it.
- Preserve plans and submitted operation identity through PostgreSQL restart. A lost receipt never causes resubmission.
- Deny missing provenance even if ordinary VM tags still match. Exercise audit-write failure and provider argument mutation.
- Verify API authorization, bounded input, sanitized output and actual HTTP behavior.

The baseline on 2026-09-20 passed 168 tests across 17 files against a fresh PostgreSQL database. Stage 1 completion requires its new regression tests, the full build and independent review. Live networking and image-transfer claims require Stage 2 evidence.

## Stage 2 qualification boundary

The pinned provider-source review supports a candidate API-only sequence: upload an artifact to file-backed staging, create a template candidate with `import-from`, convert the stopped VM to a template, then request a full clone. The sequence needs separate `imgcopy`, `qmcreate`, `qmtemplate` and `qmclone` receipts. The clone receipt identifies its source VM; destination ownership and attachments need separate completion checks. See [Proxmox source evidence](proxmox-evidence.md) and [the task contract](provider-operations.md).

This is a candidate path, not installed-version qualification. Before live dispatch, recheck the nested host, staging and target capabilities, precise permissions, complete attachment parsing and per-task recovery. Artifact staging is itself a managed allocation with its own journal and cleanup scope. The existing GET-only provider must not become a generic write proxy. No host-side Kiln runtime or `qm importdisk` command is part of the proposed path.
