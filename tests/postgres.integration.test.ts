import { randomUUID } from "node:crypto";
import { execFile, spawn } from "node:child_process";
import { once } from "node:events";
import { promisify } from "node:util";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { Pool } from "pg";
import { DrizzleStore, gatewayHealthAttestationMigration, gatewayIdentityMigration, gatewayMonitoringMigration, imageProvenanceMigration, providerOperationMigration } from "@kiln/database";
import type { Event, GatewayIdentity, Resource } from "@kiln/core";
import { GatewayMonitor, GatewayService } from "@kiln/core";
import { FakeComputeProvider } from "@kiln/providers";

const databaseUrl = process.env.KILN_TEST_DATABASE_URL;

describe.skipIf(!databaseUrl)("Postgres store", () => {
  it("persists a gateway health observation across a store restart", async () => {
    const store = new DrizzleStore(databaseUrl!);
    await store.migrate(await readFile(resolve("packages/database/drizzle/0000_initial.sql"), "utf8"));
    await store.migrate(await gatewayMonitoringMigration());
    await store.migrate(await gatewayHealthAttestationMigration());
    await store.migrate(await gatewayIdentityMigration());
    await store.migrate(await providerOperationMigration());
    await store.migrate(await imageProvenanceMigration());
    const node = `node_${randomUUID().replaceAll("-", "")}`;
    const provider = new FakeComputeProvider({ nodes: [{ id: node, online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] }], storage: [], resources: [] });
    const gateway = await new GatewayService(store, provider).createFakeGateway(node, `gateway_${node}`, "test");
    await new GatewayMonitor(store, provider).scan();
    await store.close();
    const restarted = new DrizzleStore(databaseUrl!);
    try {
      const records = await restarted.listGateways();
      expect(records).toEqual(expect.arrayContaining([expect.objectContaining({ resource: expect.objectContaining({ id: gateway.resource.id }), health: expect.objectContaining({ status: "READY" }) })]));
    } finally {
      await restarted.close();
    }
  });
  it("rolls back a gateway health update when its audit event cannot be stored", async () => {
    const store = new DrizzleStore(databaseUrl!);
    await store.migrate(await readFile(resolve("packages/database/drizzle/0000_initial.sql"), "utf8"));
    await store.migrate(await gatewayMonitoringMigration());
    await store.migrate(await gatewayHealthAttestationMigration());
    await store.migrate(await gatewayIdentityMigration());
    await store.migrate(await providerOperationMigration());
    await store.migrate(await imageProvenanceMigration());
    const node = `atomic_${randomUUID().replaceAll("-", "")}`;
    const provider = new FakeComputeProvider({ nodes: [{ id: node, online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] }], storage: [], resources: [] });
    try {
      const gateway = await new GatewayService(store, provider).createFakeGateway(node, `atomic_${node}`, "test");
      await new GatewayMonitor(store, provider).scan();
      const before = (await store.listGateways()).find((entry) => entry.resource.id === gateway.resource.id)!.health!;
      await expect(store.saveGatewayScan(
        { ...before, status: "NOT_READY" },
        [{ id: `inc_${node}`, node, gatewayId: gateway.resource.id, code: "TEST", severity: "warning", status: "OPEN", firstSeenAt: before.observedAt, lastSeenAt: before.observedAt, resolvedAt: null, message: "test", guidance: [] }],
        [{ installationId: gateway.resource.installationId, projectId: "infrastructure", resourceId: gateway.resource.id, type: "gateway.observed", timestamp: "not-a-date", payload: {} }],
      )).rejects.toBeTruthy();
      const after = (await store.listGateways()).find((entry) => entry.resource.id === gateway.resource.id)!.health!;
      expect(after.status).toBe(before.status);
      expect(await store.listGatewayIncidents(node)).toEqual([]);
    } finally { await store.close(); }
  });
  it("classifies concurrent same-key gateway requests from different nodes", async () => {
    const firstStore = new DrizzleStore(databaseUrl!);
    const secondStore = new DrizzleStore(databaseUrl!);
    await firstStore.migrate(await readFile(resolve("packages/database/drizzle/0000_initial.sql"), "utf8"));
    await firstStore.migrate(await gatewayMonitoringMigration());
    await firstStore.migrate(await gatewayHealthAttestationMigration());
    await firstStore.migrate(await gatewayIdentityMigration());
    await firstStore.migrate(await providerOperationMigration());
    await firstStore.migrate(await imageProvenanceMigration());
    const suffix = randomUUID().replaceAll("-", "");
    const firstNode = `idem_a_${suffix}`;
    const secondNode = `idem_b_${suffix}`;
    const provider = new FakeComputeProvider({ nodes: [
      { id: firstNode, online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] },
      { id: secondNode, online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] },
    ], storage: [], resources: [] });
    try {
      const results = await Promise.allSettled([
        new GatewayService(firstStore, provider).createFakeGateway(firstNode, `same_${suffix}`, "test"),
        new GatewayService(secondStore, provider).createFakeGateway(secondNode, `same_${suffix}`, "test"),
      ]);
      expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
      expect(results.find((result) => result.status === "rejected")).toMatchObject({ reason: { code: "IDEMPOTENCY_CONFLICT", status: 409 } });
    } finally {
      await firstStore.close();
      await secondStore.close();
    }
  });
  it("invalidates persisted fake gateway readiness before the API accepts requests after restart", async () => {
    const store = new DrizzleStore(databaseUrl!);
    await store.migrate(await readFile(resolve("packages/database/drizzle/0000_initial.sql"), "utf8"));
    await store.migrate(await gatewayMonitoringMigration());
    await store.migrate(await gatewayHealthAttestationMigration());
    await store.migrate(await gatewayIdentityMigration());
    await store.migrate(await providerOperationMigration());
    await store.migrate(await imageProvenanceMigration());
    const provider = new FakeComputeProvider();
    const existing = (await store.listGateways()).find((entry) => entry.metadata.node === "fake-node");
    const gateway = existing ?? { resource: (await new GatewayService(store, provider).createFakeGateway("fake-node", `startup_${randomUUID()}`, "test")).resource, metadata: null };
    if (existing) {
      await provider.create(existing.resource);
      await provider.registerGatewayAttestation(existing.resource, existing.metadata);
    }
    await new GatewayMonitor(store, provider).scan();
    await store.close();
    const port = 18000 + Math.floor(Math.random() * 1000);
    const child = spawn(process.execPath, ["--import", "tsx", "apps/api/src/server.ts"], {
      cwd: process.cwd(),
      env: { ...process.env, KILN_STORE: "postgres", KILN_DATABASE_URL: databaseUrl, KILN_API_TOKEN: "startup-monitor", KILN_PORT: String(port), KILN_HOST: "127.0.0.1" },
      stdio: "ignore",
    });
    try {
      let response: Response | null = null;
      for (let attempt = 0; attempt < 80; attempt += 1) {
        try {
          response = await fetch(`http://127.0.0.1:${port}/v1/doctor`, { headers: { Authorization: "Bearer startup-monitor" } });
          break;
        } catch { await new Promise<void>((resolve) => setTimeout(resolve, 50)); }
      }
      expect(response?.status).toBe(200);
      const doctor = await response!.json() as { nodes: Array<{ gatewayId: string; status: string }> };
      expect(doctor.nodes).toEqual(expect.arrayContaining([expect.objectContaining({ gatewayId: gateway.resource.id, status: "NOT_READY" })]));
    } finally {
      child.kill("SIGTERM");
      await Promise.race([once(child, "exit"), new Promise<void>((resolve) => setTimeout(resolve, 3000))]);
    }
  });
  it("rejects a mismatched installation before recovering another installation's resources", async () => {
    const store = new DrizzleStore(databaseUrl!);
    await store.migrate(
      await readFile(
        resolve("packages/database/drizzle/0000_initial.sql"),
        "utf8",
      ),
    );
    const id = `identity_${randomUUID().replaceAll("-", "")}`;
    const resource: Resource = {
      id,
      installationId: await store.installationId(),
      projectId: "postgres-integration",
      type: "development",
      ownership: "KILN_MANAGED",
      state: "PROVISIONING",
      providerId: "fake",
      providerResourceId: id,
      providerKind: "fake",
      node: null,
      pool: "kiln",
      createdBy: "test",
      createdAt: new Date().toISOString(),
      expiresAt: null,
      profile: null,
    };
    try {
      await store.createResource(resource, `key_${id}`, "identity");
      await expect(
        promisify(execFile)(
          process.execPath,
          ["--import", "tsx", "apps/api/src/server.ts"],
          {
            cwd: process.cwd(),
            timeout: 10000,
            env: {
              ...process.env,
              KILN_STORE: "postgres",
              KILN_DATABASE_URL: databaseUrl,
              KILN_API_TOKEN: "startup-regression-only",
              KILN_INSTALLATION_ID: randomUUID(),
              KILN_PORT: "0",
            },
          },
        ),
      ).rejects.toMatchObject({ code: 1 });
      expect((await store.getResource(id))?.state).toBe("PROVISIONING");
    } finally {
      await store.close();
    }
  });
  it("does not select expired external resources for lease cleanup", async () => {
    const pool = new Pool({ connectionString: databaseUrl });
    await pool.query(
      await readFile(
        resolve("packages/database/drizzle/0000_initial.sql"),
        "utf8",
      ),
    );
    await pool.end();

    const store = new DrizzleStore(databaseUrl!);
    const id = `external_${randomUUID().replaceAll("-", "")}`;
    const resource: Resource = {
      id,
      installationId: await store.installationId(),
      projectId: "postgres-integration",
      type: "development",
      ownership: "EXTERNAL",
      state: "READY",
      providerId: "fake",
      providerResourceId: id,
      providerKind: "fake",
      node: null,
      pool: "kiln",
      createdBy: "test",
      createdAt: "2026-01-01T00:00:00.000Z",
      expiresAt: "2026-01-01T00:01:00.000Z",
      profile: null,
    };

    await store.createResource(resource, `key_${id}`, "external");
    const expired = await store.expired("2026-01-01T00:02:00.000Z");
    await store.close();

    expect(expired.map((candidate) => candidate.id)).not.toContain(id);
  });
  it("does not let a stale intent operation overwrite a later ready resource", async () => {
    const pool = new Pool({ connectionString: databaseUrl });
    await pool.query(
      await readFile(
        resolve("packages/database/drizzle/0000_initial.sql"),
        "utf8",
      ),
    );
    await pool.end();
    const store = new DrizzleStore(databaseUrl!);
    const id = `stale_${randomUUID().replaceAll("-", "")}`;
    const resource: Resource = {
      id,
      installationId: await store.installationId(),
      projectId: "postgres-integration",
      type: "development",
      ownership: "KILN_MANAGED",
      state: "READY",
      providerId: "fake",
      providerResourceId: id,
      providerKind: "fake",
      node: null,
      pool: "kiln",
      createdBy: "test",
      createdAt: "2026-01-01T00:00:00.000Z",
      expiresAt: "2026-01-01T00:01:00.000Z",
      profile: null,
    };
    await store.createResource(resource, `key_${id}`, "stale");
    await store.beginOperation({ resourceId: id, kind: "destroy" });
    await store.recoverUnfinishedOperations();
    expect((await store.getResource(id))?.state).toBe("READY");
    await store.close();
  });
  it("marks provisioning records without a create intent as errored on recovery", async () => {
    const pool = new Pool({ connectionString: databaseUrl });
    await pool.query(
      await readFile(
        resolve("packages/database/drizzle/0000_initial.sql"),
        "utf8",
      ),
    );
    await pool.end();
    const store = new DrizzleStore(databaseUrl!);
    const id = `provisioning_${randomUUID().replaceAll("-", "")}`;
    const resource: Resource = {
      id,
      installationId: await store.installationId(),
      projectId: "postgres-integration",
      type: "development",
      ownership: "KILN_MANAGED",
      state: "PROVISIONING",
      providerId: "fake",
      providerResourceId: id,
      providerKind: "fake",
      node: null,
      pool: "kiln",
      createdBy: "test",
      createdAt: "2026-01-01T00:00:00.000Z",
      expiresAt: "2026-01-01T00:01:00.000Z",
      profile: null,
    };
    await store.createResource(resource, `key_${id}`, "provisioning");
    await store.recoverUnfinishedOperations();
    expect((await store.getResource(id))?.state).toBe("ERROR");
    await store.close();
  });
  it("persists an enrolled identity and admits only one concurrent heartbeat sequence", async () => {
    const store = new DrizzleStore(databaseUrl!);
    await store.migrate(await readFile(resolve("packages/database/drizzle/0000_initial.sql"), "utf8"));
    await store.migrate(await gatewayMonitoringMigration());
    await store.migrate(await gatewayHealthAttestationMigration());
    await store.migrate(await gatewayIdentityMigration());
    await store.migrate(await providerOperationMigration());
    await store.migrate(await imageProvenanceMigration());
    const node = `identity_gateway_${randomUUID().replaceAll("-", "")}`;
    const provider = new FakeComputeProvider({ nodes: [{ id: node, online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] }], storage: [], resources: [] });
    const gateway = await new GatewayService(store, provider).createFakeGateway(node, `identity_${node}`, "test");
    const now = new Date().toISOString();
    const identity: GatewayIdentity = {
      deviceId: `gwd_${randomUUID().replaceAll("-", "")}`, resourceId: gateway.resource.id, installationId: gateway.resource.installationId,
      generation: (await store.getGateway(gateway.resource.id))!.generation, publicKeyPem: "test-key", publicKeyFingerprint: "test-key-fingerprint", revokedAt: null, createdAt: now,
      currentCertificate: { fingerprint: `cert_${randomUUID()}`, certificatePem: "test-cert", issuedAt: now, expiresAt: new Date(Date.now() + 60_000).toISOString(), acceptedUntil: new Date(Date.now() + 60_000).toISOString() }, previousCertificate: null,
      nextSequence: 1, lastSeenAt: null, lastServices: null, lastPolicy: null, lastReservation: null,
    };
    const event = (type: string): Omit<Event, "id"> => ({ installationId: gateway.resource.installationId, projectId: "infrastructure", resourceId: gateway.resource.id, type, timestamp: now, payload: {} });
    try {
      await store.issueGatewayEnrollmentToken({ resourceId: gateway.resource.id, installationId: identity.installationId, generation: identity.generation, tokenHash: "token", expiresAt: new Date(Date.now() + 60_000).toISOString(), publicKeyFingerprint: null, deviceId: null, certificateFingerprint: null }, event("gateway.identity_token_issued"));
      await store.enrollGatewayIdentity({ tokenHash: "token", publicKeyPem: identity.publicKeyPem, publicKeyFingerprint: identity.publicKeyFingerprint, identity, event: event("gateway.identity_enrolled"), now });
      await store.close();
      const first = new DrizzleStore(databaseUrl!);
      const second = new DrizzleStore(databaseUrl!);
      try {
        expect((await first.getGatewayIdentity(gateway.resource.id))?.deviceId).toBe(identity.deviceId);
        const attempts = await Promise.allSettled([first.recordGatewayHeartbeat({ deviceId: identity.deviceId, certificateFingerprint: identity.currentCertificate.fingerprint, sequence: 1, services: "PASS", policy: "UNKNOWN", reservation: "UNKNOWN", receivedAt: now, event: event("gateway.heartbeat") }), second.recordGatewayHeartbeat({ deviceId: identity.deviceId, certificateFingerprint: identity.currentCertificate.fingerprint, sequence: 1, services: "PASS", policy: "UNKNOWN", reservation: "UNKNOWN", receivedAt: now, event: event("gateway.heartbeat") })]);
        expect(attempts.filter((attempt) => attempt.status === "fulfilled")).toHaveLength(1);
        await first.revokeGatewayIdentity(gateway.resource.id, now, event("gateway.identity_revoked"));
        expect(await first.getGatewayEnrollmentToken(gateway.resource.id)).toMatchObject({ tokenHash: "" });
      } finally { await first.close(); await second.close(); }
    } finally {
      try { await store.close(); } catch { /* already closed */ }
    }
  });
});
