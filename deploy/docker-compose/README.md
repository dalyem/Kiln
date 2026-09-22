# Development Compose stack

The canonical file is [compose.yaml](../../compose.yaml) at the repository root. This is a contributor control plane. It is not an appliance, a Proxmox deployment, or a real workload environment.

From the repository root, copy the example environment file and give each required value a different random hex string:

```sh
cp .env.example .env
openssl rand -hex 32 # KILN_API_TOKEN
openssl rand -hex 32 # KILN_INFRASTRUCTURE_TOKEN
openssl rand -hex 32 # KILN_DB_PASSWORD
```

Put those three values in `.env`, then start the stack:

```sh
docker compose up --build
```

The API is available only at `http://127.0.0.1:4000` and the dashboard only at `http://127.0.0.1:3000`. PostgreSQL has no host port. The dashboard uses the shared development service token and has no production user login. Keep these loopback bindings in place.

The API applies migrations `0000` through `0008` at startup. Do not run migration SQL by hand for normal contributor restarts. `docker compose down` stops containers and retains the named PostgreSQL volume, so records remain after the next `docker compose up`. `docker compose down --volumes` deletes that database volume. Use it only when an empty development database is intended.

Compose uses the fake compute provider. PostgreSQL records and events persist in the named volume, but fake compute state lives in the API process and disappears when that container restarts. It cannot create a VM, run project code, contact Proxmox, or qualify the appliance. See the [Compose qualification procedure](../../docs/development/contributor-compose-qualification.md) for the bounded contributor check.
