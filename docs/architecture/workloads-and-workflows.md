# Workloads, gateway, artifacts and workflows

This document defines later interfaces. Phase 1 includes client/daemon scaffolds, not remote execution, browsers or workflow execution.

## kilnd communication

kilnd is a small Go workload daemon. The Phase 1 binary exposes loopback health only. It does not execute commands or accept an unauthenticated administrative API.

Future workload images establish an outbound control connection to Kiln. Enrollment uses a short-lived single-use token bound to an exact resource/operation, followed by an installation-issued short-lived mTLS workload certificate. The control plane verifies resource identity, project and lease on every stream. A certificate authenticates a workload, not arbitrary command authority.

The protocol in `proto/kiln.proto` describes heartbeat, readiness, command and output shapes. Before implementation, finalize sequencing, flow control, cancellation, exit status and artifact upload semantics. Command IDs are idempotent; reconnect reports known command status. Output uses bounded buffers and sequence numbers so a disconnected observer does not exhaust guest or appliance memory. Secrets must not be written into command logs by the platform.

Execution requests run as the configured workload user in a constrained workspace. Process groups provide cancellation. Workspace paths are normalized and cannot traverse the allowed root. Exposed ports are registered against resource identity; agents cannot register arbitrary LAN targets. Metrics are observations, not permission grants. Shutdown stops services and uploads declared artifacts before lease destruction where possible.

## Exact working state

Phase 3 must materialize HEAD plus staged, unstaged and untracked content without forcing a push. A client-generated manifest identifies base commit, file paths, mode bits, content hashes, deletions and binary blobs. Capture index and worktree separately if index fidelity matters. Preserve the effective working tree used for tests; never silently drop binary changes or untracked files.

Capture detects local modifications during transfer and retries or reports inconsistency instead of claiming an exact snapshot. Ignore rules are explicit; secrets and `.git` administrative files require deliberate policy. Git submodules, LFS and symlinks need tests and documented behavior. Archive extraction rejects absolute paths, traversal, hard-link escape and symlink traversal before writing into a remote workspace. Uploads are authenticated, size-limited and bound to the destination resource/project.

Development commands and services come from `.kiln/project.yaml`, captured with the same project revision. Profiles constrain CPU/RAM/storage/network and duration. A ready response requires daemon readiness, materialized files, command/service health and registered preview routing. VM power-on alone is insufficient.

## Execution and verification

Internal runners execute detached commands with IDs, timestamps, stdout/stderr, exit codes and artifacts. A trusted container backend runs inside workload compute, never on a PVE host. Unknown scripts, Docker and system-level work use disposable VMs. Containers on the appliance must not become an accidental shared untrusted execution backend.

Verification presets resolve to a pinned list of deterministic checks. Independent checks may run concurrently within project quotas. Each result records command, environment/image digest, working-state digest, timing and exit code. Failed checks remain inspectable after a retry. The coordinator remains an orchestrator, delegating heavy tests and builds remotely.

## Gateway

Routes identify registered resources: `/preview/<id>`, `/browser/<id>`, `/desktop/<id>` and `/artifact/<id>`. All requests require authentication, project authorization, an active lease where applicable and a registered route. The gateway terminates TLS and checks websocket upgrades as well as HTTP.

Preview origins must not share sensitive dashboard cookies. Use isolated origins with host-only cookies or a carefully tested separate-domain design. A service behind a preview may serve hostile content, so URL path separation alone is inadequate security isolation. Do not fetch arbitrary URL inputs or let guest-controlled Host headers choose a management endpoint.

Tailscale can supply private reachability but does not replace Kiln authorization. Expiration revokes routing and live sessions even when provider cleanup fails. Live browser and KasmVNC sessions stay behind the gateway; raw workload ports remain private.

## Artifacts

Artifact records include ID, installation/project/workflow/resource IDs, producer attempt, content type, byte length, cryptographic digest, creation time, retention and storage reference. Initial storage may be a dedicated appliance filesystem volume with metadata in Postgres. S3-compatible storage is a later backend, not an initial requirement.

Uploads write to temporary paths and atomically finalize after hash/size checks. Download authorization resolves the artifact record; it never accepts a caller-supplied disk path. Content-Disposition and safe MIME behavior prevent uploaded HTML from gaining dashboard-origin privileges. Browser downloads, traces, screenshots and execution logs finalize before disposable compute is destroyed. If retention/upload fails, emit a visible failure and apply a bounded cleanup grace policy; never retain resources forever silently.

## Python workflows

Python is the user-facing workflow language; TypeScript Core owns durable stage state and resource operations. Do not serialize a running Python interpreter as the sole workflow state. The SDK records stage declarations/attempt IDs and their input/output artifacts through REST; execution occurs in a leased coordinator VM.

Planned primitives are agent, run, runner, parallel, browser, desktop, approval, retry, artifact and report. They represent durable stages or resource requests, not one giant agent prompt. Side-effecting steps need stable keys and explicit retry policy. A resumed workflow pins its definition digest and completed attempt results; changing workflow code creates a new version or explicit migration.

Each stage stores dependencies, driver/environment version, command/task input references, max attempts, status, timestamps, result and feedback. A retry is a new attempt of the failed stage or designated builder stage, with prior feedback. Earlier completed Scout and Plan stages are not rerun by default. Approvals are scoped signed-in human decisions with expiry and an immutable decision record; an agent cannot approve itself by emitting a matching event.

The coordinator runs selected agent CLIs through AgentDriver. It requests runners/browsers through Kiln, receives structured results, and emits observable events. Token usage is recorded only when a driver reports it, with missing values distinct from zero. Replay is an event/artifact timeline, not re-execution and not hidden model chain-of-thought.

Temporal may replace the simple durable stage executor once failure recovery complexity justifies it. The REST, stage IDs, artifacts and agent-driver boundaries should survive that change. No Temporal cluster is required initially.
