# Data, events and API boundaries

## PostgreSQL model

The executable schema and SQL migration live in `packages/database`. This document describes the relational direction, including later phases; future tables are not claimed to be implemented.

| Entity | Keys and important constraints | Phase |
| --- | --- | --- |
| installations | Singleton persisted UUID, schema/config version; configured ID must match | 1 |
| resources | Kiln ID, installation/project, type, ownership, state, provider identity and ID, node, pool, profile, actor, timestamps | 1 |
| leases | One active lease per temporary resource, expiration and policy; FK to resource | 1 |
| operations | Unique installation/project/idempotency-key, request hash, resource and result; persisted before side effect | 1 |
| events | Monotonic sequence, immutable event type/payload, installation/project/resource, timestamp | 1 |
| compute_providers | Installation, type, endpoint and secret reference; encrypted credential storage later | Planned |
| compute_nodes / storage_targets / network_profiles | Observation freshness, capabilities, operator-approved usage | Planned |
| projects / identities / grants | Project definitions, principal kind and scopes; no PVE credentials in grants | Planned |
| images / image_replicas | Immutable version and digest, provenance, storage and node locality | Planned |
| executions / verification_runs | Commands/preset snapshot, operation IDs, result and log/artifact references | Planned |
| browser_sessions / desktop_sessions | Engine, profile reference, control state, resource and lease | Planned |
| workflows / stages / agent_runs | Definition digest, attempt number, dependencies, driver, result | Planned |
| approvals / artifacts | Approver and immutable decision; artifact metadata, digest, storage reference | Planned |

Use foreign keys, unique constraints and transaction boundaries for safety, not TypeScript types alone. Provider resource uniqueness must be scoped by installation, provider and object kind and handle tombstones when provider IDs are reused. Do not delete a resource row to free its provider ID; preserve historical events and provenance. Runtime database access should not have schema-owner privileges in a hardened appliance. The development stack does not claim hardened database role separation.

No ORM model of an external observation has a cascade into lifecycle deletion. Future resource dependency edges explicitly record owned disks, snapshots, volumes and attachments. Importing a parent does not infer ownership of every child.

## Events

Every event has a stable sequence/cursor, ID, installation ID, optional project/resource/workflow/stage/agent IDs, event type, UTC time and structured payload. The Phase 1 subset focuses on installation/resource/lease/safety events. Resource transitions and their events commit atomically when a durable store is used.

Events are append-only through application operations. Do not confuse this with tamper resistance against a PostgreSQL administrator. Later retention policies archive old partitions while preserving workflow/artifact references. Never include raw credentials, cookies, full PVE responses or hidden model reasoning.

Phase 1 exposes ordered cursor-based polling at `/v1/events`. Cursor filtering occurs together with project authorization; pages return a stable next cursor. Future SSE uses the same event IDs and Last-Event-ID replay. Slow consumers reconnect rather than blocking resource lifecycle. A subscription cannot bypass project authorization.

Safety events must be persisted before a denied mutation returns if the database is healthy. If audit persistence fails, the operation still fails closed. A separate operational log may report the audit storage failure without exposing secrets.

## API and identity

See [the concrete Phase 1 contract](phase-1-contract.md). API paths are versioned `/v1`; schema validation rejects invalid TTLs, IDs, unexpected fields and malformed bodies. Capability creation endpoints later map high-level development/execution/browser requests to Core operations. Clients never select arbitrary VMIDs for mutation.

Authorization checks both scope and project. Planned principal kinds are HUMAN, CLIENT, WORKLOAD and WORKFLOW. Browser identity is a protected server-side profile reference, not an API principal with access to hypervisor credentials. Workload identities may access only their own work queue, heartbeats, ports and artifacts. Workflow identities receive resource quotas and project-scoped capabilities for the duration of a run.

Phase 1 service tokens are explicitly configured development credentials with fixed scopes and project membership. They are not production human authentication or a general administrator-token recommendation. A production token is hashed at rest, revocable, expiring where appropriate, and bound to a principal. User-supplied project IDs cannot expand its access.

No endpoint returns PVE token values. Detailed external inventory requires administrator scope. Health checks expose health, not internal credentials or guest configuration. Unknown internal errors return a generic error code; detailed logs must redact secrets.

## Adapter rules

CLI, MCP, SDK and dashboard authenticate to REST and share its errors and results. They may parse durations, format output and manage a client-side upload stream; they do not schedule, validate ownership or call PVE during routine operations.

Bootstrap is the explicit exception before Core exists. It has a separate command, credentials and capability-checked plan. It never shares the normal CLI resource mutation code path. The Phase 1 command prints architecture guidance and does not apply changes.

The dashboard server holds its API token. Before deployment beyond localhost it needs real user authentication and per-user authorization, rather than proxying one development service token to every visitor. Never configure a secret using `NEXT_PUBLIC_`.
