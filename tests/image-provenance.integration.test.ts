import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { Pool } from "pg";
import {
  canonicalImageManifest,
  ImageProvenanceService,
  ResourceService,
  type ImageImportRequest,
  type TrustedImageKeys,
} from "@kiln/core";
import {
  DrizzleStore,
  gatewayHealthAttestationMigration,
  gatewayIdentityMigration,
  gatewayMonitoringMigration,
  imageProvenanceMigration,
  initialMigration,
  networkProbeMigration,
  providerOperationMigration,
} from "@kiln/database";
import { FakeAsyncComputeProvider, FakeComputeProvider } from "@kiln/providers";

const baselineUrl = process.env.KILN_TEST_DATABASE_URL;

function signedImport(version = "1.0.0"): { request: ImageImportRequest; keys: TrustedImageKeys } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const artifact = Buffer.from("postgres-stage1-artifact");
  const manifest = {
    schemaVersion: 1 as const,
    name: "postgres-image",
    version,
    arch: "amd64" as const,
    artifactSha256: createHash("sha256").update(artifact).digest("hex"),
    artifactSize: artifact.length,
    sourceBuild: "ci-pg",
    capabilities: ["development"],
    keyId: "pg-key",
  };
  return {
    request: {
      manifest,
      signature: sign(null, Buffer.from(canonicalImageManifest(manifest)), privateKey).toString("base64"),
      artifactBase64: artifact.toString("base64"),
    },
    keys: {
      "pg-key": {
        publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
        allowedNames: ["postgres-image"],
        allowedCapabilities: ["development"],
        allowedArchitectures: ["amd64"],
      },
    },
  };
}

describe.skipIf(!baselineUrl)("image provenance in PostgreSQL", () => {
  it("retains submitted template and clone lineage across restart, then completes safely", async () => {
    const database = await createDatabase(baselineUrl!);
    const provider = new FakeAsyncComputeProvider();
    let first: DrizzleStore | null = null;
    let restarted: DrizzleStore | null = null;
    try {
      first = new DrizzleStore(database.url);
      await migrate(first);
      const { request, keys } = signedImport();
      const images = new ImageProvenanceService(first, provider, keys);
      const imported = await images.importImage(request, "template-restart", "infra");
      const templateOperation = (await first.listOperations(imported.template.resourceId))[0]!;
      expect(templateOperation.status).toBe("SUBMITTED");

      await first.close();
      first = null;
      restarted = new DrizzleStore(database.url);
      await migrate(restarted);
      await restarted.recoverUnfinishedOperations();
      expect((await restarted.getTemplateImport(imported.template.resourceId))?.state).toBe("UNKNOWN");
      expect((await restarted.listOperations(imported.template.resourceId))[0]).toMatchObject({ id: templateOperation.id, status: "SUBMITTED" });

      await provider.completeTask(templateOperation.taskHandle!.taskId);
      const resources = new ResourceService(restarted, provider);
      await resources.reconcileOperations();
      expect((await restarted.getTemplateImport(imported.template.resourceId))?.state).toBe("READY");

      const clone = await resources.create({ type: "development", projectId: "default", ttlSeconds: 60, templateId: imported.template.resourceId }, "clone-restart", "test");
      const cloneOperation = (await restarted.listOperations(clone.resource.id))[0]!;
      const plan = await restarted.getProvisioningPlan(clone.resource.id);
      expect(plan).toMatchObject({ resourceId: clone.resource.id, templateResourceId: imported.template.resourceId, cloneMode: "FULL" });
      const children = new Pool({ connectionString: database.url });
      try {
        const rows = await children.query("SELECT attachment_id FROM provisioning_attachments WHERE resource_id = $1 ORDER BY attachment_id", [clone.resource.id]);
        expect(rows.rows).toHaveLength(plan!.attachments.length);
      } finally {
        await children.end();
      }

      await restarted.close();
      restarted = null;
      restarted = new DrizzleStore(database.url);
      await migrate(restarted);
      await restarted.recoverUnfinishedOperations();
      expect((await restarted.getProvisioningPlan(clone.resource.id))?.canonicalDigest).toBe(plan!.canonicalDigest);
      expect((await restarted.listOperations(clone.resource.id))[0]).toMatchObject({ id: cloneOperation.id, status: "SUBMITTED" });
      await provider.completeTask(cloneOperation.taskHandle!.taskId);
      await new ResourceService(restarted, provider).reconcileOperations();
      expect((await restarted.getResource(clone.resource.id))?.state).toBe("READY");
    } finally {
      await first?.close();
      await restarted?.close();
      await database.admin.query(`DROP DATABASE ${database.name}`);
      await database.admin.end();
    }
  });

  it("denies missing and foreign attachment rows, and rejects unresolved template retirement", async () => {
    const database = await createDatabase(baselineUrl!);
    const provider = new FakeComputeProvider();
    const store = new DrizzleStore(database.url);
    try {
      await migrate(store);
      const { request, keys } = signedImport();
      const images = new ImageProvenanceService(store, provider, keys);
      const imported = await images.importImage(request, "attachment-template", "infra");
      const resources = new ResourceService(store, provider);
      const missing = await resources.create({ type: "development", projectId: "default", ttlSeconds: 60, templateId: imported.template.resourceId }, "missing-child", "test");
      const pool = new Pool({ connectionString: database.url });
      try {
        await pool.query("DELETE FROM provisioning_attachments WHERE resource_id = $1 AND attachment_id = 'boot'", [missing.resource.id]);
      } finally {
        await pool.end();
      }
      await expect(resources.mutate(missing.resource.id, "stop", "default")).rejects.toMatchObject({ code: "SAFETY_DENIED" });
      expect(provider.mutations.filter((entry) => entry.operation === "stop")).toHaveLength(0);

      const foreign = await resources.create({ type: "development", projectId: "default", ttlSeconds: 60, templateId: imported.template.resourceId }, "foreign-child", "test");
      const pool2 = new Pool({ connectionString: database.url });
      try {
        await pool2.query("INSERT INTO provisioning_attachments (resource_id, attachment_id, native_id, attachment) VALUES ($1, 'foreign', 'foreign-child', $2::jsonb)", [foreign.resource.id, JSON.stringify({ id: "foreign", class: "NIC", ownership: "OWNED_CHILD", nativeId: "foreign-child", attributes: { model: "e1000" } })]);
      } finally {
        await pool2.end();
      }
      await expect(resources.mutate(foreign.resource.id, "stop", "default")).rejects.toMatchObject({ code: "SAFETY_DENIED" });

      const asyncStore = new DrizzleStore(database.url);
      await asyncStore.close();
      const pendingDatabase = await createDatabase(baselineUrl!);
      const pendingStore = new DrizzleStore(pendingDatabase.url);
      try {
        await migrate(pendingStore);
        const asyncProvider = new FakeAsyncComputeProvider();
        const pending = await new ImageProvenanceService(pendingStore, asyncProvider, keys).importImage(request, "pending-import", "infra");
        await expect(new ImageProvenanceService(pendingStore, asyncProvider, keys).retireTemplate(pending.template.resourceId)).rejects.toMatchObject({ code: "CONFLICT" });
      } finally {
        await pendingStore.close();
        await pendingDatabase.admin.query(`DROP DATABASE ${pendingDatabase.name}`);
        await pendingDatabase.admin.end();
      }
    } finally {
      await store.close();
      await database.admin.query(`DROP DATABASE ${database.name}`);
      await database.admin.end();
    }
  });

  it.each(["memory", "postgres"] as const)("serializes clone reservation against retirement in %s", async (kind) => {
    const provider = new FakeComputeProvider();
    const { request, keys } = signedImport();
    if (kind === "memory") {
      const { MemoryStore } = await import("@kiln/database");
      const store = new MemoryStore();
      await assertReservationRace(store, provider, request, keys);
      return;
    }
    const database = await createDatabase(baselineUrl!);
    const store = new DrizzleStore(database.url);
    try {
      await migrate(store);
      await assertReservationRace(store, provider, request, keys);
    } finally {
      await store.close();
      await database.admin.query(`DROP DATABASE ${database.name}`);
      await database.admin.end();
    }
  });

  it.each(["memory", "postgres"] as const)("serializes concurrent image import idempotency in %s", async (kind) => {
    const provider = new FakeComputeProvider();
    const { request, keys } = signedImport();
    if (kind === "memory") {
      const { MemoryStore } = await import("@kiln/database");
      const store = new MemoryStore();
      const images = new ImageProvenanceService(store, provider, keys);
      const results = await Promise.all([
        images.importImage(request, "same-import", "infra"),
        images.importImage(request, "same-import", "infra"),
      ]);
      expect(results.map((result) => result.replayed).sort()).toEqual([false, true]);
      expect(results[0].template.resourceId).toBe(results[1].template.resourceId);
      return;
    }
    const database = await createDatabase(baselineUrl!);
    const store = new DrizzleStore(database.url);
    try {
      await migrate(store);
      await store.initializeInstallation();
      const images = new ImageProvenanceService(store, provider, keys);
      const results = await Promise.all([
        images.importImage(request, "same-import", "infra"),
        images.importImage(request, "same-import", "infra"),
      ]);
      expect(results.map((result) => result.replayed).sort()).toEqual([false, true]);
      expect(results[0].template.resourceId).toBe(results[1].template.resourceId);
    } finally {
      await store.close();
      await database.admin.query(`DROP DATABASE ${database.name}`);
      await database.admin.end();
    }
  });

  it("fails closed when a submitted template import or its clone source changes", async () => {
    const database = await createDatabase(baselineUrl!);
    const provider = new FakeAsyncComputeProvider();
    const store = new DrizzleStore(database.url);
    try {
      await migrate(store);
      const { request, keys } = signedImport();
      const images = new ImageProvenanceService(store, provider, keys);
      const imported = await images.importImage(request, "tampered-template", "infra");
      const importOperation = (await store.listOperations(imported.template.resourceId))[0]!;
      const pool = new Pool({ connectionString: database.url });
      try {
        await pool.query("UPDATE provenance_images SET manifest = jsonb_set(manifest, '{sourceBuild}', '\"forged\"') WHERE id = $1", [imported.template.imageId]);
      } finally {
        await pool.end();
      }
      await provider.completeTask(importOperation.taskHandle!.taskId);
      await new ResourceService(store, provider).reconcileOperations();
      expect((await store.listOperations(imported.template.resourceId))[0]).toMatchObject({ status: "UNKNOWN", safeReason: "POSTCONDITION_FAILED" });

      const { request: cleanRequest, keys: cleanKeys } = signedImport("1.0.1");
      const cleanImages = new ImageProvenanceService(store, provider, cleanKeys);
      const clean = await cleanImages.importImage(cleanRequest, "source-template", "infra");
      const cleanOperation = (await store.listOperations(clean.template.resourceId))[0]!;
      await provider.completeTask(cleanOperation.taskHandle!.taskId);
      await new ResourceService(store, provider).reconcileOperations();
      const resources = new ResourceService(store, provider);
      const clone = await resources.create({ type: "development", projectId: "default", ttlSeconds: 60, templateId: clean.template.resourceId }, "source-clone", "test");
      const cloneOperation = (await store.listOperations(clone.resource.id))[0]!;
      provider.fixtures.delete(clean.template.providerResourceId);
      provider.attachmentGraphs.delete(clean.template.providerResourceId);
      await expect(provider.completeTask(cloneOperation.taskHandle!.taskId)).rejects.toMatchObject({ code: "SAFETY_DENIED" });
      await resources.reconcileOperations();
      expect((await store.getResource(clone.resource.id))?.state).toBe("PROVISIONING");
      expect((await store.listOperations(clone.resource.id))[0]).toMatchObject({ status: "SUBMITTED" });
    } finally {
      await store.close();
      await database.admin.query(`DROP DATABASE ${database.name}`);
      await database.admin.end();
    }
  });
});

async function assertReservationRace(store: DrizzleStore | import("@kiln/database").MemoryStore, provider: FakeComputeProvider, request: ImageImportRequest, keys: TrustedImageKeys): Promise<void> {
  const images = new ImageProvenanceService(store, provider, keys);
  const imported = await images.importImage(request, "race-template", "infra");
  const resources = new ResourceService(store, provider);
  const [clone, retirement] = await Promise.allSettled([
    resources.create({ type: "development", projectId: "default", ttlSeconds: 60, templateId: imported.template.resourceId }, "race-clone", "test"),
    images.retireTemplate(imported.template.resourceId),
  ]);
  expect([clone.status, retirement.status].filter((status) => status === "fulfilled")).toHaveLength(1);
  const template = await store.getTemplateImport(imported.template.resourceId);
  const clones = await store.listResources("default");
  if (template?.state === "RETIRED") expect(clones).toHaveLength(0);
  else expect(clones).toHaveLength(1);
}

async function migrate(store: DrizzleStore): Promise<void> {
  for (const migration of [initialMigration, gatewayMonitoringMigration, gatewayHealthAttestationMigration, gatewayIdentityMigration, networkProbeMigration, providerOperationMigration, imageProvenanceMigration]) await store.migrate(await migration());
}

async function createDatabase(url: string): Promise<{ url: string; name: string; admin: Pool }> {
  const parsed = new URL(url);
  const name = `kiln_provenance_${randomUUID().replaceAll("-", "")}`;
  parsed.pathname = "/postgres";
  const admin = new Pool({ connectionString: parsed.toString() });
  try { await admin.query(`CREATE DATABASE ${name}`); } catch (error) { await admin.end(); throw error; }
  parsed.pathname = `/${name}`;
  return { url: parsed.toString(), name, admin };
}
