# Kiln

**kiln.dev** · Self-hosted compute infrastructure for software-engineering agents.

Agents own code and tasks. Kiln owns compute.

Kiln targets Proxmox, from one node with local storage to clusters with shared storage. REST, MCP, the Go CLI, SDKs and an infrastructure dashboard share one control plane. Kiln is infrastructure, not an IDE.

This repository contains the Phase 0 architecture and Phase 1 engineering foundation. It does **not** provision real development VMs yet. General lifecycle operations run against a fake provider. A separately enabled administrator path has completed a [real Proxmox lifecycle qualification](docs/development/stage2-qualification-evidence.md); normal discovery remains read-only. A live Linux image import has completed on nested Proxmox, including restart recovery and cleanup ([Linux PVE qualification](docs/development/linux-pve-qualification.md)). See [implementation status](docs/implementation-status.md) for exact limits and verification evidence.

Kiln now includes a protected gateway-monitoring scaffold. It persists fake gateway health and incidents, holds new fake work when configured gateways are not ready, and reports the condition through `kiln doctor`, MCP and the dashboard. It does not deploy a router, test a real network, send alerts or repair infrastructure.

## Run locally

Requires Node.js 22+, npm and optionally Go 1.22+. No Proxmox is needed.

```sh
npm ci
export KILN_API_TOKEN="$(openssl rand -hex 32)"
export KILN_STORE=memory
npm run dev
```

This mode is explicitly ephemeral. In another terminal, use the same token:

```sh
export KILN_TOKEN='<the API token from the first terminal>'
export KILN_URL=http://127.0.0.1:4000
go run ./cmd/kiln status
go run ./cmd/kiln resource list
go run ./cmd/kiln dev up --ttl 2h
go run ./cmd/kiln doctor --network
```

The returned resource is fake compute, not a VM or a preview. With no configured fake gateway, doctor reports the provider nodes as unconfigured. Start the dashboard with `npm --workspace @kiln/dashboard run dev -- --hostname 127.0.0.1` using the same `KILN_URL` and `KILN_TOKEN`.

The first Development Lease increment provides [local workspace capture and
materialization](docs/development/workspaces.md). Its Go commands reconstruct
working state without a Kiln server or Proxmox access. The [milestone
design](docs/architecture/development-lease.md) tracks the remaining integration.
The next increment provides a [signed Linux base image builder](images/dev/README.md)
and [local boot qualification](docs/development/linux-image-qualification.md).
Proxmox Linux import, networking, enrollment and previews remain separate steps.

For durable development with PostgreSQL:

```sh
cp .env.example .env
# Set independent random KILN_API_TOKEN and KILN_DB_PASSWORD values in .env.
# KILN_INFRASTRUCTURE_TOKEN is optional and must differ from KILN_API_TOKEN.
docker compose up --build
```

API: `http://127.0.0.1:4000`. Dashboard: `http://127.0.0.1:3000`. The Compose stack is for contributors; a distributable appliance image is planned.

## Safety first

Existing provider objects are EXTERNAL by default. Names, stopped state, pool membership or tags alone never grant lifecycle authority. Kiln requires a persisted record and matching installation, provider identity, resource type, pool and ownership tags. Unknown or conflicting metadata denies mutation. TTL cleanup uses the same ownership checks.

No Phase 1 command creates a real pool, imports a VM, edits a network, stops an external VM or deletes a PVE object. The destructive safety suite exercises these boundaries using fake providers and a read-only PVE adapter.

Gateway records are persistent protected infrastructure. The ordinary resource and lease APIs cannot create, stop, destroy, extend or expire them. A separate local infrastructure token can create a simulated gateway only in fake mode and can trigger a monitor scan in either provider mode. Do not expose that token to routine CLI, MCP, SDK or dashboard processes. [Doctor operations](docs/operations/doctor.md) describes the report and recovery limits.

## Documentation

- [Architecture and component boundaries](docs/architecture/README.md)
- [Ownership security boundary](docs/architecture/ownership.md)
- [Proxmox APIs and minimum read-only permissions](docs/architecture/proxmox-evidence.md)
- [State machines](docs/architecture/state-machines.md)
- [Data, events and API design](docs/architecture/data-and-api.md)
- [Phase 1 API contract](docs/architecture/phase-1-contract.md)
- [Appliance and bootstrap design](docs/architecture/deployment.md)
- [Future workloads, workflows and gateway](docs/architecture/workloads-and-workflows.md)
- [Doctor and gateway monitoring](docs/operations/doctor.md)
- [Open decisions](docs/architecture/decisions.md)
- [Contributor guide](CONTRIBUTING.md)
- [MCP setup](apps/mcp/README.md)

Licensed under [MIT](LICENSE). See the [license decision](docs/architecture/decisions.md#license-decision-mit). No software is installed on Proxmox hosts by this scaffold.
