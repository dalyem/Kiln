# Compute, browser and agent contracts

## Compute provider

The executable TypeScript provider interface lives under `packages/providers`. Its responsibilities are discovery, exact inspection, create, status, start, stop, destroy and metrics. Provider methods accept typed identities; they must not expose arbitrary PVE route forwarding to callers.

Discovery returns nodes, storage and workload observations with observation freshness and visibility limits. Kiln connects once to a cluster API address and discovers nodes through PVE. Node membership is not manually registered. The same flow works on one node. Per-node storage inspection is required because a named storage may be local, disabled or absent on some nodes.

Storage capability fields include shared, local, persistent, snapshots, clones, linked clones and ephemeral preference. Capabilities depend on PVE storage plugin, content type and configuration. Never infer clone support solely from a friendly storage name or from `shared=true`. Unknown capability is not true. Ceph is optional; local-LVM and ZFS remain valid deployment targets when the chosen image/import/clone flow supports them.

The scheduler first filters online nodes by capacity headroom, storage content/availability, network policy and image replica locality, then uses a deterministic ranking. Discovery capacity includes external load. Capacity is a snapshot, not a reservation. Phase 1 decisions are exercised against fake capabilities. Later scheduling commits a reservation and provisioning intent before issuing a clone, then releases it on a known terminal outcome.

FakeComputeProvider exposes fixtures for external, managed, imported and orphaned objects. Its guard contract tests exercise lifecycle effects and confirm denied operations leave objects untouched. Live ProxmoxProvider verifies HTTPS, uses a dedicated token and performs GET calls only in Phase 1. Auth/transport errors and absence are separate outcomes. Check [official-source evidence](proxmox-evidence.md) for ACL and endpoint details.

A future provider must pass the shared lifecycle/ownership contract suite and its own integration tests before production use. Fake tests cannot establish provider atomicity, task behavior, storage semantics or network isolation.

## Image manager design

An image is a versioned manifest, digest, build provenance, supported architectures and capabilities. Its replicas identify exact template resource IDs, node availability and storage. Install/update/remove are managed resource operations and must pass the same safety policy. Image update installs a new immutable version; existing leases keep their pinned version. Removal refuses versions referenced by live resources or uncertain operations.

A template in the `kiln` pool with a familiar name is external until its record proves ownership. Bootstrap never reuses an arbitrary existing `kiln-dev` template. Signed image distribution, QEMU guest agent/cloud-init configuration and kilnd enrollment are Phase 2/3 work. Workload images contain no PVE tokens.

## Browser provider design

BrowserProvider methods are createSession, destroySession, navigate, snapshot, click, type, select, scroll, wait, screenshot, console, network, startTrace, stopTrace and liveView. Additional tabs/upload/download operations remain behind the provider. Core accepts browser session IDs and project authorization; raw CDP, Playwright and VNC addresses are internal.

Initial provider is Playwright with a headed browser on a virtual display. Sessions are isolated, and browser-engine support is explicit. Chromium and Firefox are first targets; WebKit availability must be proven for the selected image. A browser resource may target a development resource or public web research independently.

The browser gateway authenticates each operation and checks lease and control generation. Human takeover changes control state before allowing input and rejects queued agent actions from an older generation. An authentication challenge creates a WAITING_FOR_HUMAN event and the user enters credentials in the same browser. Persistent profiles are explicit encrypted identities with exclusive-session policy; profile names never reveal cookie contents.

KasmVNC attaches to the same display for desktop escalation. Its websocket and HTTP endpoints are only reachable through Kiln Gateway. Full desktop access has stronger permission requirements than read-only observation. None of this browser runtime is implemented in Phase 1.

## Agent driver design

AgentDriver has start, resume, cancel, status, events and result. A run stores driver name/version, configuration reference, attempt ID and resource ID. Credentials are delivered using secret references appropriate to the selected driver, never embedded in workflow prompts or persisted event payloads.

Codex, Claude Code, OpenCode, Grok and Hermes drivers can differ in resume capability, observable events, structured output and cancellation guarantees. Advertise those capabilities instead of inventing uniform behavior that a CLI cannot provide. Unsupported resume requires an explicit new attempt, not silent replay of the entire workflow. The Phase 1 repo defines this direction only; it does not claim installed or working agent drivers.
