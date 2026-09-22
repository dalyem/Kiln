# First Development Lease

## Problem and completion criteria

A development lease must run the developer's current project in a Kiln-owned
Linux VM without a commit or push. It is ready only after authenticated daemon
enrollment, workspace materialization, service health and authenticated preview
registration. VM power-on is not readiness.

Stage 2 proved the guarded BIOS lifecycle on one nested Proxmox host. Its small
inline image format, NIC-free configuration parser and serial readiness marker
do not qualify a Linux development VM. The lab network remains
`LAB_PROBE_ONLY`. Existing operator-created routers and probes remain external.

The milestone is complete when a real client request captures a dirty repository,
creates a managed VM, serves the captured application behind authenticated
preview access, survives a Core restart without duplicate provisioning, and
expires with access revoked and ownership-checked cleanup. External resources
must remain unchanged throughout qualification.

## Order of work

1. Implement and qualify exact workspace capture and materialization using the
   real Go client and daemon binaries. This can be tested without giving a VM
   network access. The format must preserve the difference between HEAD, index
   and working files, including untracked content.
2. Build and sign the Linux image. Add bounded large-image staging, immutable
   image identity and a strict Linux VM configuration parser. Track every disk
   and seed attachment before importing or cloning. Do not relax the BIOS
   qualifier's existing parser or upload limits to accept a different profile.
   Resume the lab installation from its verified database backup before using
   its retained pool or staging image. A fresh database cannot adopt those
   allocations merely because their names match.
3. Provision a managed node gateway and temporary network probes through the
   operation journal. Qualify actual bridge/VLAN placement and protected-network
   denial. Read-only SSH verification belongs to installation and relevant
   configuration changes. A guest report alone cannot grant admission.
4. Add workload-specific enrollment and outbound authenticated control. Bind
   commands, workspace digests and registered ports to installation, project,
   resource, operation and lease. Gateway credentials cannot authorize workload
   execution. No administrative workload listener is exposed.
5. Integrate development creation and readiness in Core. Add isolated-origin
   preview routing with authorization and lease enforcement. Expiry revokes
   access even if provider cleanup is uncertain or denied.
6. Qualify the complete REST/CLI flow in the nested lab, including restart,
   rejected ownership, failed readiness and expiration. Record the exact image,
   network and provider profile covered by the evidence.

Steps 2 through 6 are not implemented by the workspace step. Normal Proxmox
lifecycle remains disabled until its corresponding safety gates pass. HA,
browser/workflow execution and automatic repair are outside this milestone.

## Workspace options

| Approach | Cost and limitation |
| --- | --- |
| Git patches plus a base fetch | Compact, but requires source access and careful binary, index and untracked-file handling. Git filters can change the bytes used for tests. |
| Git bundle plus worktree archive | Uses established Git transport and preserves history. Transferring all reachable history can be large and can disclose content unrelated to the current project state. |
| Explicit HEAD, index and worktree manifest | Transfers only the required state and permits validation before writing. Requires a format and materializer; initial limits and unsupported Git features must be explicit. |

Use an explicit manifest for the first implementation. The original HEAD identity
and its tree, the index and the effective working files are distinct inputs.
Materialization creates a fresh repository without source remotes, local Git
configuration, credentials or hooks. Historical commits are not needed to run
the captured state; later history fetch requires its own authorization.

The first format targets SHA-1 Git repositories and reconstructs detached HEAD.
The original commit and tree IDs must match after reconstruction. HEAD is a
shallow boundary when its parents are absent, following Git's
[shallow repository semantics](https://git-scm.com/docs/shallow). Rebuild the
logical index through [Git plumbing](https://git-scm.com/docs/git-update-index);
do not transfer machine-specific index caches. Submodules, unresolved conflicts,
sparse state, LFS and index flags that cannot be reproduced are explicit errors
in this version. Unsupported features are not silently flattened.

Initial bounds are 96 MiB encoded, 64 MiB of unique decoded content, 16 MiB per
blob and 10,000 entries across the three views. These bound the local operation,
not the future image-transfer service. Git objects and working files both occupy
space in the destination. Treat the snapshot as private source material and
store it with restrictive permissions. Ignore rules are exclusions, not secret
scanning; included tracked or untracked files may contain secrets.

The Go CLI owns reading local files. A shared Go package owns format validation
and reconstruction, reused by `kilnd`. Neither component owns compute lifecycle.
Initial local commands qualify this boundary before the format is transported
through Core. They must not imply that upload, enrollment or remote execution
already exists.

## Failure model and verification

Capture must detect observed changes to HEAD, index or included file content and
fail without publishing an incomplete snapshot. Editors should be quiesced during
capture. Repeated observations are not a filesystem-wide atomic snapshot and
cannot prove the absence of every change-and-revert race.

The receiver treats snapshot bytes as untrusted. It checks version, size, hashes,
paths, file modes, duplicates, parent conflicts and symlink safety before
publishing a workspace. A checksum proves byte identity, not sender authority.
The future transport still needs project/resource authorization and lease checks.

Materialization must refuse an existing destination and never execute project
commands, hooks or filters. A failed attempt removes only its own private
staging directory. An unrecognized Git feature must produce an explicit error,
not an apparently successful partial workspace.

Qualification compares original and reconstructed HEAD, staged changes,
unstaged changes, untracked bytes, executable modes and safe symlinks. It also
exercises tampered content, path traversal, symlink escape, concurrent edits,
size limits and existing-destination denial. Run compiled binaries in a fresh
directory as well as package tests.

## Rollout and remaining decisions

The initial commands are local and additive. No database migration, provider
permission or infrastructure mutation is needed. Removing the commands rolls
back this increment without changing existing Core records.

Before networked qualification, settle the precise supported Linux image and
seed attachment profile against the installed PVE API, and place Core's TLS
workload endpoint where the qualified sandbox network can reach it without
granting general management-LAN access. Preserve the accepted appliance and
node gateway boundaries. Any new network-policy behavior needs an explicit
design and packet evidence before admission.
