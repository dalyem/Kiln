import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { Pool } from "pg";
import { DrizzleStore, imageProvenanceMigration, initialMigration, linuxImageImportMigration } from "@kiln/database";
import type { LinuxImportAllocation, LinuxImportRun, Resource } from "@kiln/core";

const base = process.env.KILN_TEST_DATABASE_URL;
describe.skipIf(!base)("Linux import PostgreSQL journal", () => {
  it("persists reservations and serializes phase intent across restart", async () => {
    const database = await fresh(); let store: DrizzleStore | null = new DrizzleStore(database.url);
    try {
      await store.migrate(await initialMigration()); await store.migrate(await imageProvenanceMigration()); await store.migrate(await linuxImageImportMigration()); const installationId = await store.initializeInstallation(); const run = fixture(installationId); const resources = resourceRows(run); const allocations = allocationRows(run);
      await store.createLinuxImportRun({ run, resources, allocations, event: event(run) });
      await expect(store.beginLinuxImportPhase({ runId: run.id, name: "IMPORT", intentDigest: "2".repeat(64), event: event(run) })).rejects.toMatchObject({ code: "SAFETY_DENIED" });
      const first = await store.beginLinuxImportPhase({ runId: run.id, name: "UPLOAD", intentDigest: "3".repeat(64), event: event(run) }); expect(first.dispatch).toBe(true);
      await store.close(); store = new DrizzleStore(database.url);
      const replay = await store.beginLinuxImportPhase({ runId: run.id, name: "UPLOAD", intentDigest: "3".repeat(64), event: event(run) }); expect(replay.dispatch).toBe(false); expect((await store.getLinuxImportProof(run.id)).children).toHaveLength(3);
      const phases = ["UPLOAD", "IMPORT", "TEMPLATE", "CLONE", "STAMP", "START", "STOP", "DESTROY_CLONE", "DESTROY_TEMPLATE"] as const;
      for (const [index, name] of phases.entries()) { await store.submitLinuxImportPhase(run.id, name, receipt(`${name[0]}`.repeat(64)), event(run)); await store.completeLinuxImportPhase(run.id, name, event(run)); const next = phases[index + 1]; if (next) await store.beginLinuxImportPhase({ runId: run.id, name: next, intentDigest: "3".repeat(64), event: event(run) }); }
      expect((await store.getLinuxImportRun(run.id))?.status).toBe("COMPLETED");
      const proof = await store.getLinuxImportProof(run.id);
      expect(proof.resources.map((resource) => resource.state).sort()).toEqual(["DESTROYED", "DESTROYED"]);
      expect(proof.allocations.map((allocation) => [allocation.kind, allocation.state]).sort()).toEqual([["CLONE_DISK", "DESTROYED"], ["STAGING", "RETAINED"], ["TEMPLATE_DISK", "DESTROYED"]]);
    } finally { await store?.close(); await database.admin.query(`DROP DATABASE ${database.name}`); await database.admin.end(); }
  });
  it("serializes fixed VM reservations for separate staged images", async () => {
    const database = await fresh(); const store = new DrizzleStore(database.url);
    try {
      await store.migrate(await initialMigration()); await store.migrate(await imageProvenanceMigration()); await store.migrate(await linuxImageImportMigration());
      const installationId = await store.initializeInstallation();
      const first = fixture(installationId);
      const second = fixture(installationId);
      second.plan.stageId = `lstg_${"b".repeat(32)}`;
      second.plan.targetStorage = "ceph-rbd";
      second.plan.cloneVmid = "903";
      second.idempotencyKey = `${second.idempotencyKey}-second`;
      second.normalizedPayload = `${second.normalizedPayload}-second`;
      const swapped = fixture(installationId);
      swapped.plan.stageId = `lstg_${"c".repeat(32)}`;
      [swapped.plan.templateVmid, swapped.plan.cloneVmid] = [swapped.plan.cloneVmid, swapped.plan.templateVmid];
      swapped.idempotencyKey = `${swapped.idempotencyKey}-swapped`;
      swapped.normalizedPayload = `${swapped.normalizedPayload}-swapped`;
      const results = await Promise.allSettled([
        store.createLinuxImportRun({ run: first, resources: resourceRows(first), allocations: allocationRows(first), event: event(first) }),
        store.createLinuxImportRun({ run: second, resources: resourceRows(second), allocations: allocationRows(second), event: event(second) }),
        store.createLinuxImportRun({ run: swapped, resources: resourceRows(swapped), allocations: allocationRows(swapped), event: event(swapped) }),
      ]);
      expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
      for (const rejected of results.filter((result): result is PromiseRejectedResult => result.status === "rejected")) expect(rejected.reason).toMatchObject({ code: "CONFLICT", status: 409 });
    } finally { await store.close(); await database.admin.query(`DROP DATABASE ${database.name}`); await database.admin.end(); }
  });
  it("quarantines the template and its allocation after an unknown import across restart", async () => {
    const database = await fresh(); let store: DrizzleStore | null = new DrizzleStore(database.url);
    try {
      await store.migrate(await initialMigration()); await store.migrate(await imageProvenanceMigration()); await store.migrate(await linuxImageImportMigration());
      const installationId = await store.initializeInstallation(); const run = fixture(installationId);
      await store.createLinuxImportRun({ run, resources: resourceRows(run), allocations: allocationRows(run), event: event(run) });
      await submitAndComplete(store, run, "UPLOAD");
      await submitOnly(store, run, "IMPORT");
      await store.markLinuxImportPhaseUnknown(run.id, "IMPORT", "TEST_UNKNOWN", event(run));
      await store.close(); store = new DrizzleStore(database.url);
      const proof = await store.getLinuxImportProof(run.id);
      expect(proof.resources.find((resource) => resource.id === run.plan.templateResourceId)?.state).toBe("QUARANTINED");
      expect(proof.allocations.find((allocation) => allocation.kind === "TEMPLATE_DISK")?.state).toBe("UNKNOWN");
    } finally { await store?.close(); await database.admin.query(`DROP DATABASE ${database.name}`); await database.admin.end(); }
  });
  it("quarantines the clone and its allocation after an unknown destroy across restart", async () => {
    const database = await fresh(); let store: DrizzleStore | null = new DrizzleStore(database.url);
    try {
      await store.migrate(await initialMigration()); await store.migrate(await imageProvenanceMigration()); await store.migrate(await linuxImageImportMigration());
      const installationId = await store.initializeInstallation(); const run = fixture(installationId);
      await store.createLinuxImportRun({ run, resources: resourceRows(run), allocations: allocationRows(run), event: event(run) });
      for (const name of ["UPLOAD", "IMPORT", "TEMPLATE", "CLONE", "STAMP", "START", "STOP"] as const) await submitAndComplete(store, run, name);
      await submitOnly(store, run, "DESTROY_CLONE");
      await store.markLinuxImportPhaseUnknown(run.id, "DESTROY_CLONE", "TEST_UNKNOWN", event(run));
      await store.close(); store = new DrizzleStore(database.url);
      const proof = await store.getLinuxImportProof(run.id);
      expect(proof.resources.find((resource) => resource.id === run.plan.cloneResourceId)?.state).toBe("QUARANTINED");
      expect(proof.allocations.find((allocation) => allocation.kind === "CLONE_DISK")?.state).toBe("UNKNOWN");
    } finally { await store?.close(); await database.admin.query(`DROP DATABASE ${database.name}`); await database.admin.end(); }
  });
});
async function submitAndComplete(store: DrizzleStore, run: LinuxImportRun, name: "UPLOAD" | "IMPORT" | "TEMPLATE" | "CLONE" | "STAMP" | "START" | "STOP") { await submitOnly(store, run, name); await store.completeLinuxImportPhase(run.id, name, event(run)); }
async function submitOnly(store: DrizzleStore, run: LinuxImportRun, name: "UPLOAD" | "IMPORT" | "TEMPLATE" | "CLONE" | "STAMP" | "START" | "STOP" | "DESTROY_CLONE") { await store.beginLinuxImportPhase({ runId: run.id, name, intentDigest: "3".repeat(64), event: event(run) }); await store.submitLinuxImportPhase(run.id, name, receipt(`${name[0]}`.repeat(64)), event(run)); }
function fixture(installationId: string): LinuxImportRun { const id = `limp_${randomUUID().replaceAll("-", "")}`; const plan = { schemaVersion: 1 as const, installationId, node: "node1", pool: "kiln", stageStorage: "local", targetStorage: "local-lvm", pveVersion: "9.2.2" as const, tokenIdentity: "root@pam!kiln", storageConfigDigest: "a".repeat(40), stageId: `lstg_${"a".repeat(32)}`, stagePath: "/private/stage", stageSha256: "b".repeat(64), templateVmid: "901", cloneVmid: "902", templateName: "template", cloneName: "clone", sourcePoolRunId: "qual_a", sourcePoolAllocationId: "alloc_a", sourcePoolNonce: "nonce", sourcePoolComment: "comment", templateResourceId: `img_template_${id.slice(-8)}`, cloneResourceId: `img_clone_${id.slice(-8)}`, templateNonce: "template", cloneNonce: "clone", image: { id: "img_a", manifest: { schemaVersion: 1 as const, name: "kiln-dev-base", version: "0.1.0", arch: "amd64" as const, artifactSha256: "b".repeat(64), artifactSize: 1, sourceBuild: `sha256:${"c".repeat(64)}`, capabilities: ["development"], keyId: "key" }, manifestDigest: "d".repeat(64), signerFingerprint: "e".repeat(64), policyDigest: "f".repeat(64) }, buildMetadataSha256: "c".repeat(64), canonicalDigest: "1".repeat(64) }; return { id, installationId, idempotencyKey: id, normalizedPayload: id, status: "ACTIVE", plan, createdAt: new Date().toISOString(), completedAt: null }; }
function resourceRows(run: LinuxImportRun): Resource[] { return [[run.plan.templateResourceId, run.plan.templateVmid, "image_template"], [run.plan.cloneResourceId, run.plan.cloneVmid, "execution"]].map(([id, vmid, type]) => ({ id: id!, installationId: run.installationId, projectId: "infrastructure", type: type as Resource["type"], ownership: "KILN_MANAGED", state: "PROVISIONING", providerId: "proxmox", providerResourceId: vmid!, providerKind: "qemu", node: run.plan.node, pool: run.plan.pool, createdBy: "test", createdAt: run.createdAt, expiresAt: null, profile: "proxmox-linux-image-import", provenanceRequired: true })); }
function allocationRows(run: LinuxImportRun): LinuxImportAllocation[] { return [["STAGING", run.plan.stageId], ["TEMPLATE_DISK", `${run.plan.targetStorage}:vm-${run.plan.templateVmid}-disk-0`], ["CLONE_DISK", `${run.plan.targetStorage}:vm-${run.plan.cloneVmid}-disk-0`]].map(([kind, identity]) => ({ id: `${kind!}_${run.id}`, runId: run.id, kind: kind! as LinuxImportAllocation["kind"], identity: identity!, intentDigest: "1".repeat(64), state: "RESERVED", createdAt: run.createdAt })); }
function event(run: LinuxImportRun) { return { installationId: run.installationId, projectId: "infrastructure", resourceId: null, type: "test", timestamp: run.createdAt, payload: {} }; }
function receipt(requestDigest: string) { return { taskId: null, tokenIdentity: "root@pam!kiln", workerType: null, sourceVmid: null, destinationVmid: null, requestDigest, dispatch: { method: "POST", path: "/test", body: null }, dispatchDigest: "a".repeat(64), responseDigest: "b".repeat(64), generatedUuid: null, generatedCtime: null, configDigest: null }; }
async function fresh() { const parsed = new URL(base!); const name = `kiln_linux_import_${randomUUID().replaceAll("-", "")}`; parsed.pathname = "/postgres"; const admin = new Pool({ connectionString: parsed.toString() }); await admin.query(`CREATE DATABASE ${name}`); parsed.pathname = `/${name}`; return { url: parsed.toString(), name, admin }; }
