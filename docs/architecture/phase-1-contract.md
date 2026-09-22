# Phase 1 implementation contract

Status: implementation boundary. Security decisions in `decisions.md` remain open where marked.

## Runtime

Node 22+, TypeScript strict, npm workspaces, Fastify REST, Zod input validation, Drizzle/Postgres. Core owns orchestration. REST is the client contract. CLI, MCP, and dashboard call REST. PostgreSQL is required in Compose; an explicit ephemeral in-memory store is available for tests and quick fake development. No automatic fallback from a failed database connection.

Root scripts: `npm run build`, `npm run typecheck`, `npm test`, `npm run dev`. API defaults to 127.0.0.1:4000. Compose binds API on localhost. Never publish Postgres.

## HTTP v1

The [OpenAPI document](../api.openapi.json) records the initial routes. Runtime validation lives in `packages/api-schema`.

All `/v1` routes require a scoped bearer credential. Local development uses explicit `KILN_API_TOKEN` with dev project access; no committed or implicit default token. Health `/healthz` and readiness `/readyz` are public and return no credentials or provider internals. A configured routine identity has project `default` and scopes `read`, `operate`, `admin`; production identity enrollment is deferred. `KILN_INFRASTRUCTURE_TOKEN`, when set, must be different and is the only local credential accepted for fake gateway setup and explicit monitor scans. Do not put it in routine CLI, MCP, SDK or dashboard environments. Missing `KILN_API_TOKEN` must not start a network service.

- GET `/v1/status`: `{installationId, providerMode, mutationEnabled, persistence, monitoring: {enabled: true, repairEnabled: false}}`.
- GET `/readyz`: unauthenticated database readiness. It returns `{ok: true}` only when the store can read its installation identity, otherwise HTTP 503 and `{ok: false}`. `/healthz` remains an unauthenticated liveness response.
- GET `/v1/doctor?network=true&node=<node>`: read-only report with schema version, provider and persistence mode, overall `HEALTHY`, `DEGRADED` or `UNKNOWN`, per-node readiness, open incidents and recovery guidance. `network` currently selects the same gateway report; it reserves the network-diagnosis intent for later telemetry. Reading doctor does not persist an observation or mutate a provider.
- GET `/v1/incidents?status=open|all&node=<node>`: open incidents by default, or all persisted gateway incidents for the requested node.
- GET `/v1/gateways`: admin view of configured gateway records and their last persisted health observation.
- POST `/v1/gateways`: infrastructure credential only, fake-provider-only gateway simulation. Requires `Idempotency-Key` and `{node}`. Returns 201 initially and 200 for the same normalized request. It never accepts a caller-supplied PVE ID or adopts an existing VM.
- POST `/v1/monitor/scan`: infrastructure credential only. Runs one bounded monitor scan and returns `{ok: true}`. The normal server loop also scans every 10 seconds.
- POST `/v1/doctor/repair`: infrastructure credential only and always returns 501 `UNSUPPORTED`. No repair plan or executor exists in this release.
- GET `/v1/resources`: `{resources: Resource[]}`; owned records only.
- GET `/v1/resources/:id`: Resource.
- POST `/v1/resources`: fake-mode-only creation; `{type: 'development'|'execution'|'browser', projectId?: 'default', ttlSeconds: integer 60..86400, profile?: string}`, requires `Idempotency-Key`. Returns Resource, HTTP 201 initially, 200 on replay. Reused key with different normalized payload -> 409.
- POST `/v1/resources/:id/stop`: guarded fake mutation. `{}`. Resource response.
- DELETE `/v1/resources/:id`: guarded fake destruction. Resource response. Retry is a safe no-op only after verifying the recorded terminal operation; never acts on a reused provider ID.
- POST `/v1/resources/:id/lease`: `{ttlSeconds: integer 60..86400}` extends from max(now, current expiry), bounded policy. Resource response.
- GET `/v1/inventory`: `{nodes, storage, resources}`; provider discovery, observation records visibly `EXTERNAL`, `KILN_MANAGED`, `IMPORTED`, or unknown orphan diagnostic. Inventory requires admin scope because it exposes external environment metadata.
- GET `/v1/events?after=<cursor>`: `{events: Event[], nextCursor}`; replay by stable persisted event sequence, project filtered. Polling is sufficient for scaffold; SSE may be added at `/v1/events/stream`.

Errors: `{error: {code, message}}`. 400 invalid input, 401 unauthenticated, 403 unauthorized/safety denial, 404 unknown record, 409 conflict, 502 provider failure, 501 unsupported operation. `NETWORK_NOT_READY` is a 409 admission hold, not a provider request. Do not return provider response bodies, auth headers, stack traces, or hypervisor secrets.

Resource JSON uses camelCase. Required fields: id, installationId, projectId, type, ownership, state, providerId, providerResourceId, providerKind, node, pool, createdBy, createdAt, expiresAt, profile. Timestamps ISO UTC strings. Native providerKind is separate from Kiln capability type, for example qemu versus development. Provider resource ID is bound to provider, installation, kind, and expected ownership metadata, not a name.

Events: monotonic cursor id, installationId, projectId nullable for installation audit, resourceId nullable, type, timestamp, payload. Never record credentials. Authorized administrators can inspect installation safety events. Regular client events are restricted to their project.

## Ownership and mutation

`EXTERNAL` is observational only; never insert discovery results as managed records. `KILN_MANAGED` and `IMPORTED` require a preexisting persisted record for this installation and exact matching provider identity, kind, ID, pool, and ownership tags observed afresh. Unknown tagged resources are external with an ORPHANED diagnostic, never adopted. Mismatch is external with a diagnostic and mutation denial. DB ownership alone or tags alone never authorize mutation.

Physical tags use PVE-safe separators, pending research: `kiln`, `kiln-managed`, `kiln-installation-<uuid>`, `kiln-resource-<type>`, `kiln-resource-id-<id>`. Require exactly one value in each ownership namespace; duplicate/conflicting markers deny. Pool `kiln` is also required. Do not repair metadata as part of a mutation.

Core serializes operations per resource, reads authoritative persisted record and live provider observation, validates all properties, persists intent/audit, then invokes a provider's guarded operation. Provider rechecks before any fake side effect. The live Proxmox adapter is read-only in Phase 1 and must reject every mutation, even if ownership checks pass. No token, URL flag, environment setting, or request can enable a live mutation in this phase.

Lifecycle state transitions: REQUESTED -> PROVISIONING -> READY -> STOPPING -> STOPPED -> DESTROYING -> DESTROYED. READY/STOPPED -> DESTROYING. Provisioning failure -> ERROR; uncertain effects are not retried as a new create. Provider disappearance -> LOST. Ownership drift -> QUARANTINED. A refused operation never changes the provider. Record a safety event before returning a safety failure. Safety audit persistence failure also fails closed.

Lease expiry scans persisted managed records, uses exactly the same guarded destruction path, and never enumerates stopped/name-matched provider resources as cleanup targets. A `gateway` is persistent (`expiresAt: null`) and cannot pass generic create, stop, destroy, lease extension or expiry cleanup. Denial for one lease must not stop processing other leases. Extension and expiry coordinate under the same lock. Tests cover time boundaries and repeated cleanup.

Gateway records use the same installation, provider, pool and ownership-tag checks as other resources, plus persistent metadata: node, generation and expected configuration fingerprint. A missing or mismatched observation is `UNKNOWN` or `QUARANTINED`; it never causes adoption, replacement or deletion. Health observations bind the gateway generation and expected fingerprint. Admission requires a matching current record in READY state. The first slice stores gateway health and incidents durably in PostgreSQL. Memory mode exists for tests and is explicitly non-durable.

The monitor runs every 10 seconds. Evidence older than 30 seconds, or more than five seconds in the future, is unready. It distinguishes a provider-confirmed offline node (`NODE_OFFLINE`) from missing provider visibility (`PROVIDER_UNKNOWN`), while a proven identity or configuration mismatch is `QUARANTINED`. It checks PVE/provider availability, ownership/configuration, power, heartbeat, policy, reservation, service and canary fields. The fake provider can simulate all fields. The real Proxmox provider remains GET-only and cannot supply authenticated gateway heartbeat or workload-side canary evidence, so configured real gateways remain unready until those later features exist. Monitoring serializes gateway admission and scans, keeps incidents open through unknown evidence, resolves them only after fresh readiness, and writes deduplicated incidents plus append-only `gateway.*` events. It delivers no email, webhook or external alert.

## Provider contract

`ComputeProvider` owns discover, inspect, create, start, stop, destroy, metrics and optional gateway observation. `ProxmoxProvider` is the typed read-only implementation for discovery/inspection and read-only gateway observation; mutation methods explicitly unsupported. `FakeComputeProvider` is deterministic test infrastructure with visible fixtures, mutation history and injectable gateway evidence. Missing observation is distinct from transport/auth failure. Requests use timeouts and TLS certificate verification. Token format `PVEAPIToken=user@realm!tokenid=secret`; token secret is never returned by API. No credentials are materialized in workload or client code.

Scheduler filters online nodes by configured storage availability, network and image locality and sufficient headroom before ranking; incomplete capability data must make a node ineligible for real placement. Phase 1 only tests scheduling decisions with fake capability data, without allocation promises. All capacity decisions later need reservations in the same transaction as scheduling.

## Scaffold clients

Go CLI uses `KILN_URL` and `KILN_TOKEN`, implements status/resource list/get/stop/delete, dev up with TTL, discovery and `kiln doctor [--network] [--node name] [--json]`. Human-readable doctor output includes incidents and guidance. JSON output is the API report. It exits 0 for `HEALTHY`, 2 for `DEGRADED` or `UNKNOWN`, and 1 for argument, request or response errors. `doctor repair` and `doctor apply` fail locally without sending a repair request. `bootstrap proxmox` provides a plan only and explicitly errors on apply. No PVE credentials in normal CLI flows.

MCP uses the official TypeScript SDK, stdio transport, high-level status/resource tools and read-only `kiln_doctor` as REST calls. Diagnostic output goes to stderr. Tool schemas must not suggest real dev VMs are already available or offer gateway repair. Dashboard is Next.js/React/TypeScript with Tailwind, server-side API token only, basic infrastructure views with IDs, gateway readiness and open incidents, and conspicuous fake/read-only mode labels. Visible dashboard tabs refresh monitoring data every 10 seconds and show a stale warning after 30 seconds. A headless Chromium check verified automatic refresh and the stale warning when subsequent requests were blocked. No browser editor or workflow UI.

kilnd is a Go skeleton with loopback health only. No unauthenticated execute endpoint. The protobuf design records outbound enrollment and mTLS command-stream requirements for later implementation.
