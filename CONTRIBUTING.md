# Contributing to Kiln

Read [ownership and safety](docs/architecture/ownership.md) before modifying lifecycle code. No normal client adapter may bypass Core orchestration or forward arbitrary Proxmox routes.

## Project tracking

Plane's **Kiln** project (`KILN`, project ID
`82260ee3-4717-4521-82c2-00231ac66f60`) is the source of truth for tasks,
priorities, dependencies and work status. Check for an existing ticket before
creating work, and include its `KILN-N` identifier in implementation handoffs.
Repository architecture and qualification documents remain the evidence for
design decisions and tested behavior.

Use the existing workflow: **Needs Spec** for unresolved designs, **Backlog**
for future work, **Ready for Agent** for defined work ready to start, and
**Blocked** when named prerequisites prevent progress. Move a ticket to
**Agent Working** only when implementation begins, then **Needs Review** and
**Done** after appropriate review and verification. Use **Changes Requested**
when review requires fixes. A completed design or fake-provider scaffold does
not complete the corresponding live infrastructure feature.

Record the actual validation and remaining limits before marking work Done.
The initial completed-ticket import represents historical work; its Plane
completion timestamps are import timestamps, not original completion dates.

## Repository map

```text
apps/api                 Fastify REST adapter and server
apps/dashboard           Next.js infrastructure dashboard
apps/mcp                 Generic stdio MCP adapter calling REST
apps/docs                Documentation entry point
packages/core            Resources, ownership policy, lifecycle, leases, scheduling
packages/database        Drizzle schema, SQL and memory/Postgres stores
packages/api-schema      Shared request validation
packages/auth            Scoped development client identity
packages/events          Event exports and contracts
packages/providers       Fake compute provider and provider boundary
packages/proxmox         Read-only Proxmox adapter
packages/sdk-js          Thin JavaScript API client
packages/workflows       Future workflow runtime boundary
packages/gateway         Future authenticated routing boundary
cmd/kiln                 Go client CLI
cmd/kilnd                Go workload daemon skeleton
internal/workspace       Shared Go snapshot capture, validation and materialization
proto                    Future workload communication schema
sdk/python               Python REST client and workflow SDK direction
images                   Appliance and workload image plans
examples/projects        .kiln project example
deploy                   Compose and bootstrap documentation
tests                    Safety, lifecycle, API and provider tests
docs/architecture        Design, evidence and unresolved decisions
```

## Development modes

Use `npm ci`, explicitly set `KILN_API_TOKEN`, `KILN_STORE=memory`, then `npm run dev` for fake ephemeral development. Run the dashboard separately with `KILN_URL`, `KILN_TOKEN` and `npm --workspace @kiln/dashboard run dev -- --hostname 127.0.0.1`. Never put the API token into a `NEXT_PUBLIC_` variable.

`KILN_INFRASTRUCTURE_TOKEN` is optional for local fake gateway setup, explicit monitor scans and managed fake image import/retirement. Generate a value different from `KILN_API_TOKEN`; never set it in ordinary CLI, MCP, SDK or dashboard environments. It cannot enable a live Proxmox write. See [doctor operations](docs/operations/doctor.md).

The [image provenance walkthrough](docs/development/image-provenance.md) creates a signed fixture, configures a scoped public-key policy and exercises the fake template/clone API. It requires no Proxmox environment.

The [workspace walkthrough](docs/development/workspaces.md) exercises local
capture, inspection and Linux materialization with the Go binaries and Git.
It requires no API token, database or Proxmox access. These commands qualify
workspace reconstruction; remote transfer and development VM creation remain
separate milestones.

## Compose development

For durable contributor development, copy `.env.example` to `.env` and set different `openssl rand -hex 32` values for `KILN_API_TOKEN`, `KILN_INFRASTRUCTURE_TOKEN` and `KILN_DB_PASSWORD`. Then run this from the repository root:

```sh
docker compose up --build
```

The API binds to `127.0.0.1:4000` and the dashboard to `127.0.0.1:3000`; PostgreSQL remains private to the Compose network. The API applies migrations `0000` through `0008` on startup. `docker compose down` preserves the named PostgreSQL volume for the next start. `docker compose down --volumes` removes it and resets the contributor database.

Compose uses fake compute. Database records persist, while fake provider state is process-local and disappears when the API container restarts. The stack cannot create a workload VM, run project code, contact Proxmox or qualify an appliance. Do not publish the shared-token dashboard beyond localhost. The [Compose qualification procedure](docs/development/contributor-compose-qualification.md) describes the bounded contributor check.

The API defaults to loopback. `KILN_HOST` is for explicit container binding. `KILN_DATABASE_URL` selects Postgres when ephemeral mode is not explicitly requested. Database unavailability never falls back to memory. No API starts without an explicitly configured token.

## Checks

```sh
npm run typecheck
npm test
npm run build
go test ./...
go vet ./...
python3 -m compileall -q sdk/python/src
python3 -m unittest sdk/python/tests/test_client.py
```

Additional database integration tests may need `KILN_TEST_DATABASE_URL`; use a dedicated disposable database, never an existing application database. The test role needs `CREATEDB`: probe persistence and runtime tests create and remove separate temporary databases. Tests using only fake providers require no hypervisor. A real PVE integration suite is a later milestone with explicitly supplied dedicated test infrastructure.

The opt-in gateway runtime integration test also requires `go` and `openssl`. It starts local TLS listeners, runs a compiled `kilnd` process, and uses the disposable `KILN_TEST_DATABASE_URL` database:

```sh
KILN_TEST_DATABASE_URL=postgresql://... npx vitest run tests/gateway-runtime.integration.test.ts
```

The opt-in network probe runtime test uses those credentials to create its own disposable database, then starts local-only DNS, HTTPS and TCP fixtures. It compiles and runs `kilnd probe` against Core's TLS probe listener. It does not contact Proxmox or the Internet:

```sh
KILN_TEST_DATABASE_URL=postgresql://... npx vitest run tests/network-probe-runtime.integration.test.ts
```

Safety tests must assert both denial and unchanged provider state. Cover absent DB records, missing/wrong/conflicting tags, wrong installation, wrong provider/type/pool, EXTERNAL records, imported resources, repeated operations, expired leases and uncertain outcomes. Gateway tests must also cover generic lifecycle/TTL denial, infrastructure-token separation, idempotent fake creation, stale/unknown/quarantined evidence, incident recovery and admission holds. A new guard regression test should be observed failing under a deliberate local guard break before its pass is trusted. Do not commit the broken guard.

## Read-only PVE setup

See [verified endpoint and ACL evidence](docs/architecture/proxmox-evidence.md). Use a dedicated privilege-separated API token and a verified TLS CA. The provider uses the `PVEAPIToken=user@realm!tokenid=secret` authorization format. Broad inventory requires audit rights over the intended scope; API results can be permission-filtered.

Configuration names and a tested connection example are listed in [implementation status](docs/implementation-status.md). No live environment is required for contribution, and this repository does not contain live credentials. Normal CLI/MCP calls use Kiln tokens rather than PVE tokens.

## Gateway monitoring boundary

The current monitor runs every 10 seconds and treats stored evidence older than 30 seconds as unready. PostgreSQL persists health, incidents and gateway events. Memory mode is deliberately transient, and fake evidence disappears on process restart. A read-only PVE observation cannot prove gateway services, authenticated heartbeat, policy generation, reservation state or workload egress. Do not label a running real PVE VM as a ready gateway until those evidence sources are implemented and tested.

`kiln doctor [--network] [--node name] [--json]` and MCP `kiln_doctor` are read-only. A degraded or unknown doctor report exits with code 2. Gateway repair is not an experimental feature: CLI repair requests fail locally and the API returns 501 before any provider write.

## Before enabling real mutation

A contributor must complete the unresolved trust/network decisions, implement resource/attachment provenance, prove exact provider ACLs, add task-journal recovery and test the ownership boundary in a disposable PVE lab. Keep any new backend behind a capability declaration until its shared contract and integration tests pass. An environment variable alone must never turn the Phase 1 adapter into a live deletion implementation.
