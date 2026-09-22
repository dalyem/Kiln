# Durable provider operations

## Problem and boundary

An infrastructure request can take effect even when Kiln loses its response. The operation journal must preserve what Kiln intended, which provider task it knows about and what remains uncertain. Restarting Core must never resubmit a request because its outcome is missing.

This milestone implements and verifies that boundary with fake compute. Proxmox remains read-only. Real image provenance, attachment ownership, VM provisioning, repair and HA fencing remain separate release gates. A provider task reporting success does not prove guest readiness or safe network placement.

## Options and decision

- Keep the existing intent/completion rows. This is simple, but loses task identity and cannot safely distinguish pending work from a failed request.
- Extend the existing PostgreSQL journal and use one Core dispatch/reconciliation service. This adds durable state and recovery tests without introducing another runtime. Use this option.
- Introduce a workflow engine now. It could coordinate long operations, but would still need this provider-specific ownership and uncertainty policy, plus another service to operate. Revisit when durable workflows justify it.

## Required behavior

Persist an immutable, versioned snapshot before dispatch: installation ID, project ID, resource ID, ownership, capability type, provider ID, provider resource ID, native kind, node, pool, expected ownership tags and action. Bind it with a canonical digest. Never overwrite that binding with fields returned by the provider. Record task identity immediately after receipt. A crash between dispatch and receipt persistence leaves an unknown operation; it is not safe to issue the request again.

Provider callbacks receive copies of resource records, operation records, task handles and gateway metadata. Core retains its authoritative records and checks the operation binding again after provider calls, before committing completion. A callback that changes its arguments cannot change Kiln's saved ownership or task identity.

Serialize resource operations. A PostgreSQL partial unique index permits at most one unresolved operation per resource. Pending or unknown operations block conflicting requests, lease extension, automatic lease cleanup and gateway admission. Idempotent create replay returns the existing record. No request can attach an arbitrary task, acknowledge uncertainty or force a retry in this release.

| State | Meaning | Recovery |
| --- | --- | --- |
| INTENT | Snapshot and dispatch fence committed; task receipt not committed | On restart, mark UNKNOWN. Never dispatch again. |
| SUBMITTED | Provider task handle committed | Poll the saved task within its persisted reconciliation deadline; never resubmit. |
| COMPLETED | Required outcome and postcondition verified | Terminal; repeated requests do not repeat the effect. |
| UNKNOWN | Outcome, provenance or partial effects unresolved | Block writes and stop automatic polling; investigation is required. |

There is no FAILED state that automatically releases the fence. A failed provider task may already have changed infrastructure. Store a sanitized reason such as `TASK_FAILED`, retain its task identity and stop polling that terminal failure. A later repair design must explicitly establish safe resolution before allowing further writes.

Reconciliation polls only a recorded task. Transient read errors or a postcondition not yet observed leave the operation SUBMITTED until its persisted deadline. Missing task identity, binding mismatch, terminal task failure or an exhausted deadline makes it UNKNOWN. No automatic transition leaves UNKNOWN. A failed task can leave partial effects, so failure does not authorize another mutation. Repeated identical observations must not flood the event stream.

Completion requires the expected task outcome and the operation's postcondition, including fresh ownership checks where the object remains. Deletion additionally requires confirmed absence; a reused native ID or an inspection error cannot prove deletion. Only fake compute can be promoted through this path in the current milestone. Commit the operation result, resource transition and event together. The in-memory implementation must have the same atomic visibility as PostgreSQL. Unknown outcomes remain inspectable through a project-authorized resource operation history API; raw provider logs, UPIDs and error bodies do not enter that API.

## Proxmox task evidence

The read-only endpoint is `GET /api2/json/nodes/{node}/tasks/{upid}/status`. A UPID encodes node, process identity, task type, object ID and submitting identity. Kiln must compare those fields with the recorded request; an arbitrary task cannot authorize resource completion. See the pinned [task status handler](https://git.proxmox.com/?p=pve-manager.git;a=blob;f=PVE/API2/Tasks.pm;h=614bede5d65599c67e068cbf18d49717ea8ab33b#l455) and [UPID implementation](https://git.proxmox.com/?p=pve-common.git;a=blob;f=src/PVE/UPID.pm;h=f665029eac78022e81810ab2e44eace57ade13fb#l18).

`running` is nonterminal. Only `stopped` with `exitstatus: "OK"` qualifies as task success in Kiln. Warnings and all other terminal values require investigation in this milestone. Task-log absence is not object absence. The task API offers no client idempotency key that safely resolves a lost submission response.

The current reader requires the task object ID to match the recorded native resource ID. This does not qualify clone operations: the pinned QEMU clone worker uses the source VMID in its task identity. A future clone submission must separately bind source/template provenance and the destination VMID. See the [clone worker](https://git.proxmox.com/?p=qemu-server.git;a=blob;f=src/PVE/API2/Qemu.pm;h=6c0127e612f6c576888a13f9bfb30874911b804d#l4749).

The initial reader accepts only pinned direct QEMU workers: create uses `qmcreate`, start uses `qmstart`, stop uses `qmstop`, and destroy uses `qmdestroy`. The saved action and worker type must match this mapping as well as the UPID. LXC, HA, clone and restore worker paths are refused until separately qualified; LXC inventory discovery remains available. These mappings come from the pinned [QEMU API handlers](https://git.proxmox.com/?p=qemu-server.git;a=blob;f=src/PVE/API2/Qemu.pm;h=6c0127e612f6c576888a13f9bfb30874911b804d#l1578). A complete response with contradictory task identity produces a terminal mismatch signal; an incomplete or unavailable response remains a transient unknown observation.

A token can inspect tasks created by that exact token. Its backing user can inspect its own token tasks; other identities need `Sys.Audit` on `/nodes/{node}`. Rotating tokens may therefore require that audit permission to poll older tasks. The status handler splits the submitting token identity into response `user` and `tokenid`; reconstruct that identity before comparing it with the full identity encoded in the UPID. Do not compare it with the current reader token. This does not grant mutation rights. See the [task ownership check and conversion](https://git.proxmox.com/?p=pve-manager.git;a=blob;f=PVE/API2/Tasks.pm;h=614bede5d65599c67e068cbf18d49717ea8ab33b#l19). These sources establish the pinned behavior, not qualification of every installed PVE release.

## Verification and rollout

Operation history is available at `GET /v1/resources/{id}/operations` with the same read scope and project authorization as the resource itself. The response is `{operations: [...]}`, limited at the store query to the newest 100 entries. Entries expose `id`, `kind`, `status`, `createdAt`, `submittedAt`, `completedAt` and `safeReason`. A SUBMITTED operation is still being observed for at most 15 minutes from its intent. UNKNOWN requires investigation; repeating stop, destroy or lease extension cannot clear it. The endpoint is read-only and does not trigger polling or dispatch.

Use asynchronous fake tasks to prove delayed completion, restart recovery, no duplicate submission, absent task identity, failed/unknown task outcomes, provider/resource binding mismatch and external-resource safety. Exercise API history and restart persistence against PostgreSQL. Test the Proxmox reader through bounded HTTP fixtures and assert GET-only behavior. No live cluster is required.

Add an ordered additive migration. Preserve legacy unresolved records conservatively; never invent missing historical ownership or task provenance. If legacy data contains multiple unresolved operations for one resource, fail migration safely rather than discarding records to satisfy the new index. The current singleton API writer remains required. Multiple writers and failover fencing are not supplied by an in-process resource lock.

Rollback requires stopping the new application and restoring its matched database backup. An older application must not dispatch against a database containing task states it does not understand. A full appliance upgrade/restore executor remains deferred.
