# Contributor Compose qualification

KILN-85 passed on 2026-09-22 using Docker Engine 29.8.1 and Compose 5.5.1
on Linux. This checks the contributor control plane with fake compute and real
PostgreSQL. It does not qualify a Proxmox deployment or appliance.

## Procedure

Follow the [Compose setup instructions](../../deploy/docker-compose/README.md).
For qualification, use a unique project name and a private environment file
outside the repository containing independently generated credentials:

```sh
docker compose --project-name kiln-qualification --env-file /private/kiln.env up --build --detach --wait
```

Use an unused project name and free localhost ports 3000 and 4000. Keep the same
project name and environment file on all subsequent commands. The actual run
used a randomly suffixed project name and disposable credentials.

1. Check unauthenticated `/v1/status` returns 401, authenticated status reports
   `fake` and `postgres`, and `/readyz` succeeds.
2. Create a development resource with an idempotency key. Repeat the request
   and confirm the same resource ID. Save its ownership fields and events.
3. Open the dashboard and confirm it renders the installation and resource.
   Check captured HTML and logs for the generated credentials.
4. Inspect published ports, application users, database tables and image
   configuration. Check missing required credentials reject Compose startup
   configuration.
5. Run `down` without `--volumes`, then `up --detach --wait`. Confirm the same
   installation, resource ownership/history, earlier events and idempotency
   result. Open the dashboard again.
6. Run `stop --timeout 30`, inspect container exit codes, then use
   `down --volumes` only for this disposable qualification project. Confirm
   unrelated containers have not changed.

Do not use `down --volumes` on a development database you want to preserve.

## Verified results

- A clean build and empty-volume startup passed. API startup applied the schema
  through migration 0008; all 26 public tables were present.
- Authentication denial, readiness, fake resource creation, idempotent replay,
  persisted events and actual dashboard HTTP rendering passed.
- API and dashboard published only to loopback. PostgreSQL had no published
  host port. Both application containers ran as a non-root user.
- `.env` was absent from the application containers. Generated credentials
  were absent from image metadata/history, rendered HTML and captured logs.
  The dashboard did not receive the infrastructure token. This was not an
  exhaustive image filesystem secret audit.
- An empty required API token caused Compose configuration to fail.
- Container removal and recreation preserved installation identity, resource
  ownership/history, events and idempotency records. The dashboard rendered the
  same installation and resource afterward.
- Final normal shutdown completed in approximately 1.34 seconds. API, dashboard
  and PostgreSQL each exited with code 0; none was OOM-killed.
- The qualification containers, network and database volume were removed.
  Existing Plane container IDs and names were unchanged.

The first run exposed npm wrappers reporting normal SIGTERM as exit 1. The
Dockerfile now launches the API directly through Node with the `tsx` loader;
Compose launches the Next CLI directly. Independent review found no remaining
material issue, and the rebuilt stack passed the full procedure above.

Private drivers, responses and logs are under
`/home/daly/.local/state/kiln/kiln25-6yd7k0oz/compose`. They contain disposable
local evidence, not deployment credentials or release artifacts.

## Limits

Fake compute state is process-local. PostgreSQL preserves records; restarting
the API does not preserve simulated machines or run real project code. The
dashboard still uses a shared development token and has no production user
login. The stack requires no Proxmox access. Real Linux import/boot/cleanup
qualification remains KILN-26.
