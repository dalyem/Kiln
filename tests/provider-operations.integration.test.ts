import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { Pool } from "pg";
import { DrizzleStore, gatewayHealthAttestationMigration, gatewayIdentityMigration, gatewayMonitoringMigration, imageProvenanceMigration, initialMigration, networkProbeMigration, providerOperationMigration } from "@kiln/database";
import { ResourceService } from "@kiln/core";
import { FakeAsyncComputeProvider } from "@kiln/providers";
import { createApp } from "../apps/api/src/app.js";

const baselineUrl = process.env.KILN_TEST_DATABASE_URL;

describe.skipIf(!baselineUrl)("provider operation journal in PostgreSQL", () => {
  it("retains a submitted fake task across a store and API restart, then fences duplicate unresolved rows", async () => {
    const database = await createJournalDatabase(baselineUrl!);
    const provider = new FakeAsyncComputeProvider();
    let store: DrizzleStore | null = null;
    let restarted: DrizzleStore | null = null;
    let app: ReturnType<typeof createApp>["app"] | null = null;
    try {
      store = new DrizzleStore(database.url);
      await migrate(store);
      const service = new ResourceService(store, provider);
      const created = await service.create({ type: "development", projectId: "default", ttlSeconds: 60 }, "restart", "test");
      const operation = (await store.listOperations(created.resource.id))[0]!;
      await store.close();
      store = null;
      restarted = new DrizzleStore(database.url);
      await migrate(restarted);
      await restarted.recoverUnfinishedOperations();
      const pending = (await restarted.listOperations(created.resource.id))[0]!;
      expect(pending).toMatchObject({ id: operation.id, status: "SUBMITTED", taskHandle: operation.taskHandle });
      const duplicate = new Pool({ connectionString: database.url });
      try {
        await expect(duplicate.query("INSERT INTO operations (id, resource_id, kind, status, created_at) VALUES ($1, $2, 'destroy', 'UNKNOWN', now())", [`duplicate_${randomUUID().replaceAll("-", "")}`, created.resource.id])).rejects.toMatchObject({ code: "23505" });
      } finally {
        await duplicate.end();
      }
      app = createApp({ token: "secret", store: restarted, provider }).app;
      const history = await app.inject({ method: "GET", url: `/v1/resources/${created.resource.id}/operations`, headers: { authorization: "Bearer secret" } });
      expect(history.statusCode).toBe(200);
      expect(history.json()).toMatchObject({ operations: [expect.objectContaining({ id: operation.id, status: "SUBMITTED" })] });

      await provider.completeTask(operation.taskHandle!.taskId);
      await new ResourceService(restarted, provider).reconcileOperations();
      expect((await restarted.getResource(created.resource.id))?.state).toBe("READY");
      expect((await restarted.listOperations(created.resource.id))[0]).toMatchObject({ status: "COMPLETED" });
    } finally {
      await app?.close();
      await store?.close();
      await restarted?.close();
      await database.admin.query(`DROP DATABASE ${database.name}`);
      await database.admin.end();
    }
  });

  it("refuses migration when legacy unresolved rows duplicate a resource", async () => {
    const database = await createJournalDatabase(baselineUrl!);
    const store = new DrizzleStore(database.url);
    try {
      await store.migrate(await initialMigration());
      const installationId = await store.installationId();
      const resourceId = `legacy_${randomUUID().replaceAll("-", "")}`;
      await store.createResource({
        id: resourceId,
        installationId,
        projectId: "default",
        type: "development",
        ownership: "KILN_MANAGED",
        state: "PROVISIONING",
        providerId: "fake",
        providerResourceId: resourceId,
        providerKind: "fake",
        node: null,
        pool: "kiln",
        createdBy: "test",
        createdAt: new Date().toISOString(),
        expiresAt: null,
        profile: null,
      }, `legacy:${resourceId}`, "legacy");
      const pool = new Pool({ connectionString: database.url });
      try {
        await pool.query("INSERT INTO operations (id, resource_id, kind, status, created_at) VALUES ($1, $2, 'create', 'INTENT', now()), ($3, $2, 'destroy', 'UNKNOWN', now())", [`legacy_intent_${resourceId}`, resourceId, `legacy_unknown_${resourceId}`]);
      } finally {
        await pool.end();
      }
      await expect(store.migrate(await providerOperationMigration())).rejects.toThrow("legacy unresolved operations duplicate a resource");
    } finally {
      await store.close();
      await database.admin.query(`DROP DATABASE ${database.name}`);
      await database.admin.end();
    }
  });
});

async function migrate(store: DrizzleStore): Promise<void> {
  await store.migrate(await initialMigration());
  await store.migrate(await gatewayMonitoringMigration());
  await store.migrate(await gatewayHealthAttestationMigration());
  await store.migrate(await gatewayIdentityMigration());
  await store.migrate(await networkProbeMigration());
  await store.migrate(await providerOperationMigration());
  await store.migrate(await imageProvenanceMigration());
  await store.migrate(await providerOperationMigration());
  await store.migrate(await imageProvenanceMigration());
}

async function createJournalDatabase(url: string): Promise<{ url: string; name: string; admin: Pool }> {
  const parsed = new URL(url);
  const database = `kiln_journal_${randomUUID().replaceAll("-", "")}`;
  parsed.pathname = "/postgres";
  const admin = new Pool({ connectionString: parsed.toString() });
  try {
    await admin.query(`CREATE DATABASE ${database}`);
  } catch (error) {
    await admin.end();
    throw error;
  }
  parsed.pathname = `/${database}`;
  return { url: parsed.toString(), name: database, admin };
}
