# Proxmox lifecycle qualification

## Purpose

Stage 2 must prove that Kiln can create and remove its own real Proxmox resources while preserving external resources and uncertain operations. The first qualification uses a signed, bootable BIOS disk with no network interface. It proves provider lifecycle and disk ownership, not Linux readiness, network admission, daemon enrollment or a Development Lease.

The existing Proxmox observer remains read-only. A separate, explicitly configured infrastructure operation invokes Kiln Core through REST. No routine project credential enables live provisioning.

## Options and decision

Extending the general development API immediately would require large image distribution, Linux configuration and network admission while the disk and task contracts are still unproven. Keeping only mocked tests would not establish the installed provider's behavior.

Use a narrow lifecycle qualification service with a durable phase journal. Limit the initial image to the existing signed 128 KiB artifact contract, one BIOS boot disk, no NIC, one node, file-backed import staging and local LVM-thin target storage. This delays general provisioning but gives each live effect a small, testable scope. Broaden profiles only after their attachment and recovery semantics have their own evidence.

## Durable intent and phase execution

Before any effect, save the installation-bound run, verified image, explicit managed resource records and immutable allocation plan. Bind the node, storage configuration, pool, staging filename, source and destination VMIDs, intended volume names, generated ownership nonces and complete VM configuration. The server supplies infrastructure placement; clients cannot introduce arbitrary paths or provider commands.

Each phase saves its intent before dispatch and its receipt immediately afterward. The closed sequence is pool creation, image upload, VM import, template conversion, full clone, clone identity assignment, start, stop, probe deletion and template deletion. Pool creation requires absence; an existing pool is not adopted. The signed staging artifact and empty pool remain explicit managed infrastructure after success. There is no staging, pool or standalone volume deletion path in this milestone.

An unsubmitted phase can be started only once. A saved provider receipt can be polled after restart. An intent without a receipt becomes UNKNOWN and cannot be resubmitted. A synchronous operation whose acknowledgement was lost is equally uncertain. Task failure does not authorize cleanup of partial effects. No automatic transition leaves UNKNOWN.

Recompute immutable intent digests immediately before effects and completion. Provider callbacks receive copies. Serialize phases and retain the existing single-writer restriction. Only the transaction inserting a unique phase intent obtains permission to dispatch it. A concurrent handler that finds an existing intent cannot dispatch. Persist phase transitions and events together. Idempotent client retries return the existing run rather than allocate more infrastructure.

## Native ownership boundary

The first adapter accepts only the qualified configuration grammar. Inspect current and pending configuration, snapshots, firewall settings and rules, HA membership, pool membership, inventory and storage contents. Unexpected devices, foreign volumes, changed bridges, passthrough, hooks, custom command arguments, pending edits or incomplete visibility deny mutation.

Volume names are planned before dispatch. A successful task and a fresh exact match establish the expected allocation; observed disks never become owned merely because they are attached. Template conversion changes the expected LVM-thin volume name from `vm-<id>-disk-0` to `base-<id>-disk-0`. Full cloning allocates a new destination volume. Preflight requires the relevant destination identities to be absent, and completion requires the planned result. Unknown storage behavior stops the run.

The clone task identifies the source template VMID. Bind that receipt to both the source and planned destination. Proxmox copies source tags and generates new firmware identity values during cloning. The dispatch record binds the exact endpoint, request body including destination VMID, token identity and returned UPID. Persist only the explicitly allowed generated UUIDs and creation metadata after task success, then compare them again before identity assignment. A separate identity-assignment phase may replace inherited tags only after the saved clone task succeeds and the stopped clone matches the complete planned configuration. This is completion of a recorded creation operation, not import or adoption of an existing VM.

Deletion uses neither purge nor unreferenced-disk cleanup. Require known successful deletion and authoritative absence of the exact VM and volumes. A filtered inventory result alone is insufficient evidence of absence. Require full audit visibility, direct configuration and status absence, node and cluster inventory agreement and absence of target volumes. A remaining disk fences the run for investigation; its name never authorizes a standalone delete.

## Qualification and limits

The installed lab was rechecked on 2026-09-21: PVE 9.2.2, qemu-server 9.1.15 and libpve-storage-perl 9.1.5. `local` accepts file-backed import content; `local-lvm` is active, nonshared LVM-thin image storage. These observations qualify candidate API contracts, not successful provisioning. See the pinned [provider sources](proxmox-evidence.md).

| Phase | Worker | Task object identity |
| --- | --- | --- |
| Upload | `imgcopy` | Empty; the saved request binds the filename and checksum |
| Import VM | `qmcreate` | Template VMID |
| Convert template | `qmtemplate` | Template VMID |
| Full clone | `qmclone` | Source template VMID; saved request binds destination |
| Start / stop | `qmstart` / `qmstop` | Probe VMID |
| Destroy | `qmdestroy` | Exact managed VMID |

Pool creation and configuration updates return synchronous acknowledgements. They still require a durable receipt and a fresh postcondition check. An acknowledgement lost across a crash is not grounds for resubmission.

The lab token grants audit visibility at the root, VM allocation/configuration/clone/power rights only on two preselected unused VMIDs, pool allocation on `/pool/kiln`, staging upload on `/storage/local` and disk allocation on `/storage/local-lvm`. Both the token and its backing user have matching scoped ACLs. No network allocation, storage deletion or `Sys.Modify` permission is granted. The installed default tag policy permits free tags; a different policy must be qualified explicitly rather than silently broadening privileges.

First run provider HTTP fixture tests, PostgreSQL restart/idempotency tests and independent review. Then use a temporary, scoped token against the nested host with verified TLS. Keep it available while recorded tasks need polling; retain the submitting token identity in each receipt. The REST qualifier requires its own credential, distinct from routine and infrastructure credentials, plus explicit server configuration. Save external VM, storage and network configuration baselines before live writes. Exercise the complete sequence, pause/restart with a known receipt, reject an external VM target without dispatch, and compare external baselines after cleanup.

Every test result must distinguish task completion, VM power state and guest execution. A successful power task alone does not prove that guest code ran. This milestone does not admit private-network workloads or qualify Ceph, cross-node movement, LXC, linked clones, HA, production bootstrap or automatic repair.

## Lab access finding

On 2026-09-21 the outer router's firewall and LAN one-shot services reported active, but its LAN address was missing. Logs showed `systemd-networkd` restarted on September 14; its LAN configuration declared no address, and DNS subsequently failed to bind. Restarting the existing LAN and DNS services restored the declared address and access to the nested host. The firewall rules were not changed. Appliance readiness must check actual addresses and connectivity; an active service is insufficient. Persistent network-reconfiguration handling remains separate appliance work.

## Intentionally retained infrastructure

The artifact record binds installation, run, storage, exact volume ID, signed digest and size, upload intent, checksum-verifying task receipt and observed metadata. Successful completion reports it as `MANAGED_RETAINED_IMAGE_CACHE`, alongside the retained installation pool and its creation nonce. Lost acknowledgements remain UNKNOWN; matching names cannot establish ownership. Neither object is silently treated as disposable or orphaned.

This lab assumes trusted Proxmox administrators, as the existing ownership design does. The upload checksum and subsequent fresh metadata check establish the transfer history, not continuous disk integrity. Reusing this cache in a future run requires a newly qualified content checksum or a new upload. Avoid granting `Datastore.Allocate` solely to implement an unqualified staging cleanup operation.
