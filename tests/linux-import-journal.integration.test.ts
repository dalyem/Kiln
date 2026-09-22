import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { Pool } from "pg";
import { DrizzleStore, gatewayHealthAttestationMigration, gatewayIdentityMigration, gatewayMonitoringMigration, imageProvenanceMigration, initialMigration, linuxImageImportMigration, networkProbeMigration, providerOperationMigration, proxmoxQualificationMigration } from "@kiln/database";
import { canonicalImageManifest, canonicalQualificationDispatch, LifecycleQualificationService, LinuxImageImportService, qualificationPhases, type LifecycleQualificationProvider, type LinuxImportAllocation, type LinuxImportProvider, type LinuxImportReceipt, type LinuxImportRun, type QualificationExecutionContext, type Resource } from "@kiln/core";

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
  it("leaves an active Linux import provisioning through generic startup recovery", async () => {
    const database = await fresh();
    let store: DrizzleStore | null = new DrizzleStore(database.url);
    try {
      await migrateLinux(store);
      const installationId = await store.initializeInstallation();
      const run = fixture(installationId);
      await store.createLinuxImportRun({
        run,
        resources: ownedResources(run),
        allocations: allocationRows(run),
        event: event(run),
      });
      await submitOnly(store, run, "UPLOAD");
      await store.close();
      store = new DrizzleStore(database.url);
      await store.recoverUnfinishedOperations();
      const proof = await store.getLinuxImportProof(run.id);
      expect(proof.resources.map((resource) => resource.state).sort()).toEqual([
        "PROVISIONING",
        "PROVISIONING",
      ]);
      expect(await store.getLinuxImportPhase(run.id, "UPLOAD")).toMatchObject({
        status: "SUBMITTED",
      });
    } finally {
      await store?.close();
      await database.admin.query(`DROP DATABASE ${database.name}`);
      await database.admin.end();
    }
  });
  it("still marks unbound or malformed Linux import resources ERROR", async () => {
    const database = await fresh();
    const sql = new Pool({ connectionString: database.url });
    let store: DrizzleStore | null = new DrizzleStore(database.url);
    try {
      await migrateLinux(store);
      const installationId = await store.initializeInstallation();
      const run = fixture(installationId);
      await store.createLinuxImportRun({
        run,
        resources: ownedResources(run),
        allocations: allocationRows(run),
        event: event(run),
      });
      await sql.query(
        `INSERT INTO resources (id, installation_id, project_id, type, ownership, state, provider_id, provider_resource_id, provider_kind, node, pool, created_by, created_at, profile, provenance_required)
         VALUES ($1, $2, 'infrastructure', 'execution', 'KILN_MANAGED', 'PROVISIONING', 'proxmox', '999', 'qemu', $3, $4, 'linux-image-import', now(), 'proxmox-linux-image-import', 1)`,
        ["img_stranger", installationId, run.plan.node, run.plan.pool],
      );
      await sql.query("UPDATE resources SET created_by='test' WHERE id=$1", [
        run.plan.cloneResourceId,
      ]);
      await sql.query(
        `INSERT INTO resources (id, installation_id, project_id, type, ownership, state, provider_id, provider_resource_id, provider_kind, node, pool, created_by, created_at, profile, provenance_required)
         VALUES ('img_unproven', $1, 'infrastructure', 'image_template', 'KILN_MANAGED', 'PROVISIONING', 'proxmox', '998', 'qemu', $2, $3, 'linux-image-import', now(), 'proxmox-linux-image-import', 0)`,
        [installationId, run.plan.node, run.plan.pool],
      );
      await store.close();
      store = new DrizzleStore(database.url);
      await store.recoverUnfinishedOperations();
      const proof = await store.getLinuxImportProof(run.id);
      expect(
        proof.resources.find((resource) => resource.id === run.plan.templateResourceId)
          ?.state,
      ).toBe("PROVISIONING");
      expect(
        proof.resources.find((resource) => resource.id === run.plan.cloneResourceId)
          ?.state,
      ).toBe("ERROR");
      expect((await store.getResource("img_stranger"))?.state).toBe("ERROR");
      expect((await store.getResource("img_unproven"))?.state).toBe("ERROR");
    } finally {
      await sql.end();
      await store?.close();
      await database.admin.query(`DROP DATABASE ${database.name}`);
      await database.admin.end();
    }
  });
  it("does not defer Linux import resources after the run leaves ACTIVE", async () => {
    const database = await fresh();
    const sql = new Pool({ connectionString: database.url });
    let store: DrizzleStore | null = new DrizzleStore(database.url);
    try {
      await migrateLinux(store);
      const installationId = await store.initializeInstallation();
      const run = fixture(installationId);
      await store.createLinuxImportRun({
        run,
        resources: ownedResources(run),
        allocations: allocationRows(run),
        event: event(run),
      });
      await sql.query("UPDATE linux_import_runs SET status='UNKNOWN' WHERE id=$1", [
        run.id,
      ]);
      await store.close();
      store = new DrizzleStore(database.url);
      await store.recoverUnfinishedOperations();
      const proof = await store.getLinuxImportProof(run.id);
      expect(proof.resources.map((resource) => resource.state).sort()).toEqual([
        "ERROR",
        "ERROR",
      ]);
    } finally {
      await sql.end();
      await store?.close();
      await database.admin.query(`DROP DATABASE ${database.name}`);
      await database.admin.end();
    }
  });
  it("inspects the saved upload once after generic startup recovery", async () => {
    const database = await fresh();
    const directory = await mkdtemp(join(tmpdir(), "kiln-linux-recovery-"));
    let store: DrizzleStore | null = new DrizzleStore(database.url);
    const qualification = new QualificationProvider();
    const linux = new LinuxProvider();
    try {
      await migrateLinux(store);
      await store.initializeInstallation();
      const sourceImage = signedQualification();
      const sourceService = new LifecycleQualificationService(
        store,
        qualification,
        sourceImage.keys,
        {
          node: "pve1",
          pool: "kiln",
          stageStorage: "local",
          targetStorage: "local-lvm",
          pveVersion: "9.2.2",
          storageConfigDigest: "a".repeat(40),
          templateVmid: "9100",
          probeVmid: "9101",
          tokenIdentity: "qual@pam!run",
        },
      );
      const source = await sourceService.createRun(sourceImage.request, "source");
      for (const _phase of qualificationPhases) {
        await sourceService.advance(source.run.id);
        await sourceService.advance(source.run.id);
      }
      const bytes = qcow();
      const path = join(directory, "image.qcow2");
      await writeFile(path, bytes, { mode: 0o600 });
      const linuxKeys = signedLinux(bytes);
      const stagingId = "lstg_0123456789abcdef0123456789abcdef";
      const service = new LinuxImageImportService(
        store,
        linux,
        linuxKeys.trusted,
        {
          node: "pve1",
          pool: "kiln",
          stageStorage: "local",
          targetStorage: "local-lvm",
          pveVersion: "9.2.2",
          tokenIdentity: "qual@pam!linux",
          storageConfigDigest: "a".repeat(40),
          templateVmid: "9200",
          cloneVmid: "9201",
          templateName: "kiln-image-9200",
          cloneName: "Copy-of-kiln-image-9200",
          sourcePoolRunId: source.run.id,
          sourcePoolAllocationId: `alloc_pool_${source.run.id}`,
          sourcePoolNonce: source.run.plan.poolNonce,
          sourcePoolComment: source.run.plan.poolComment,
        },
        {
          pathFor: () => path,
          describe: async () => ({
            id: stagingId,
            path,
            size: bytes.length,
            sha256: createHash("sha256").update(bytes).digest("hex"),
          }),
        },
      );
      const created = await service.createRun(
        {
          stagingId,
          manifest: linuxKeys.manifest,
          signature: linuxKeys.signature,
          buildMetadataBase64: linuxKeys.metadata.toString("base64"),
        },
        "linux-recovery",
      );
      await service.advance(created.run.id);
      expect(linux.executions).toEqual(["UPLOAD"]);
      expect(linux.inspections).toEqual(["UPLOAD"]);
      await store.close();
      store = new DrizzleStore(database.url);
      const resumed = new LinuxImageImportService(
        store,
        linux,
        linuxKeys.trusted,
        {
          node: "pve1",
          pool: "kiln",
          stageStorage: "local",
          targetStorage: "local-lvm",
          pveVersion: "9.2.2",
          tokenIdentity: "qual@pam!linux",
          storageConfigDigest: "a".repeat(40),
          templateVmid: "9200",
          cloneVmid: "9201",
          templateName: "kiln-image-9200",
          cloneName: "Copy-of-kiln-image-9200",
          sourcePoolRunId: source.run.id,
          sourcePoolAllocationId: `alloc_pool_${source.run.id}`,
          sourcePoolNonce: source.run.plan.poolNonce,
          sourcePoolComment: source.run.plan.poolComment,
        },
        {
          pathFor: () => path,
          describe: async () => ({
            id: stagingId,
            path,
            size: bytes.length,
            sha256: createHash("sha256").update(bytes).digest("hex"),
          }),
        },
      );
      await store.recoverUnfinishedOperations();
      await resumed.recoverInstallation();
      expect(linux.executions).toEqual(["UPLOAD"]);
      expect(linux.inspections).toEqual(["UPLOAD", "UPLOAD"]);
      expect(await store.getLinuxImportPhase(created.run.id, "UPLOAD")).toMatchObject({
        status: "SUBMITTED",
      });
      const proof = await store.getLinuxImportProof(created.run.id);
      expect(proof.resources.map((resource) => resource.state).sort()).toEqual([
        "PROVISIONING",
        "PROVISIONING",
      ]);
    } finally {
      await store?.close();
      await rm(directory, { recursive: true, force: true });
      await database.admin.query(`DROP DATABASE ${database.name}`);
      await database.admin.end();
    }
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
function ownedResources(run: LinuxImportRun): Resource[] { return resourceRows(run).map((resource) => ({ ...resource, createdBy: "linux-image-import" })); }
async function migrateLinux(store: DrizzleStore): Promise<void> { for (const migration of [initialMigration, gatewayMonitoringMigration, gatewayHealthAttestationMigration, gatewayIdentityMigration, networkProbeMigration, providerOperationMigration, imageProvenanceMigration, proxmoxQualificationMigration, linuxImageImportMigration]) await store.migrate(await migration()); }
function allocationRows(run: LinuxImportRun): LinuxImportAllocation[] { return [["STAGING", run.plan.stageId], ["TEMPLATE_DISK", `${run.plan.targetStorage}:vm-${run.plan.templateVmid}-disk-0`], ["CLONE_DISK", `${run.plan.targetStorage}:vm-${run.plan.cloneVmid}-disk-0`]].map(([kind, identity]) => ({ id: `${kind!}_${run.id}`, runId: run.id, kind: kind! as LinuxImportAllocation["kind"], identity: identity!, intentDigest: "1".repeat(64), state: "RESERVED", createdAt: run.createdAt })); }
function event(run: LinuxImportRun) { return { installationId: run.installationId, projectId: "infrastructure", resourceId: null, type: "test", timestamp: run.createdAt, payload: {} }; }
function receipt(requestDigest: string) { return { taskId: null, tokenIdentity: "root@pam!kiln", workerType: null, sourceVmid: null, destinationVmid: null, requestDigest, dispatch: { method: "POST", path: "/test", body: null }, dispatchDigest: "a".repeat(64), responseDigest: "b".repeat(64), generatedUuid: null, generatedCtime: null, configDigest: null }; }
class QualificationProvider implements LifecycleQualificationProvider {
  readonly mode = "proxmox-qualification" as const;
  async executeQualificationPhase(context: QualificationExecutionContext) {
    const dispatch = { method: "POST", path: `/mock/${context.phase}`, body: null };
    return {
      taskId: `task-${context.phase}`,
      workerType: "mock",
      sourceVmid: null,
      destinationVmid: null,
      tokenIdentity: "qual@pam!run",
      requestDigest: context.requestDigest,
      dispatch,
      dispatchDigest: canonicalQualificationDispatch(dispatch),
      responseDigest: "a".repeat(64),
      generatedUuid: null,
      generatedCtime: null,
    };
  }
  async inspectQualificationPhase() {
    return { status: "COMPLETED" as const };
  }
}
class LinuxProvider implements LinuxImportProvider {
  executions: string[] = [];
  inspections: string[] = [];
  async executeLinuxImportPhase(
    context: Parameters<LinuxImportProvider["executeLinuxImportPhase"]>[0],
  ): Promise<LinuxImportReceipt> {
    this.executions.push(context.phase);
    return {
      taskId: "UPID:pve1:00000001:00000002:00000003:imgcopy::qual@pam!linux:",
      tokenIdentity: "qual@pam!linux",
      workerType: "imgcopy",
      sourceVmid: null,
      destinationVmid: null,
      requestDigest: context.requestDigest,
      dispatch: { method: "POST", path: "/linux/UPLOAD", body: null },
      dispatchDigest: "b".repeat(64),
      responseDigest: "c".repeat(64),
      generatedUuid: null,
      generatedCtime: null,
      configDigest: null,
    };
  }
  async inspectLinuxImportPhase(
    context: Parameters<LinuxImportProvider["inspectLinuxImportPhase"]>[0],
  ) {
    this.inspections.push(context.phase);
    return { status: "RUNNING" as const };
  }
}
function qcow(): Buffer {
  const value = Buffer.alloc(112);
  value.write("QFI\u00fb", 0, "binary");
  value.writeUInt32BE(3, 4);
  value.writeBigUInt64BE(0n, 8);
  value.writeUInt32BE(0, 16);
  value.writeUInt32BE(16, 20);
  value.writeBigUInt64BE(8n * 1024n * 1024n * 1024n, 24);
  value.writeUInt32BE(0, 32);
  value.writeUInt32BE(0, 60);
  value.writeBigUInt64BE(0n, 64);
  value.writeBigUInt64BE(0n, 72);
  value.writeBigUInt64BE(0n, 80);
  value.writeBigUInt64BE(0n, 88);
  value.writeUInt32BE(4, 96);
  value.writeUInt32BE(112, 100);
  return value;
}
function signedQualification() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const bytes = Buffer.alloc(112);
  bytes.write("QFI\u00fb", 0, "binary");
  bytes.writeUInt32BE(3, 4);
  bytes.writeUInt32BE(9, 20);
  bytes.writeBigUInt64BE(4n * 1024n * 1024n, 24);
  bytes.writeUInt32BE(4, 96);
  bytes.writeUInt32BE(112, 100);
  const manifest = {
    schemaVersion: 1 as const,
    name: "qualification-image",
    version: "1",
    arch: "amd64" as const,
    artifactSha256: createHash("sha256").update(bytes).digest("hex"),
    artifactSize: bytes.length,
    sourceBuild: "pg",
    capabilities: ["network_probe"],
    keyId: "operator",
  };
  return {
    request: {
      manifest,
      signature: sign(null, Buffer.from(canonicalImageManifest(manifest)), privateKey).toString("base64"),
      artifactBase64: bytes.toString("base64"),
    },
    keys: {
      operator: {
        publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
        allowedNames: ["qualification-image"],
        allowedCapabilities: ["network_probe"],
        allowedArchitectures: ["amd64" as const],
      },
    },
  };
}
function signedLinux(bytes: Buffer) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const artifactSha256 = createHash("sha256").update(bytes).digest("hex");
  const metadata = Buffer.from(
    JSON.stringify({
      schemaVersion: 1,
      name: "kiln-dev-base",
      arch: "amd64",
      profile: "debian13-nic-free-development-v1",
      recipe: "images/dev/build.sh",
      recipeSha256: "1".repeat(64),
      baseSha512: "2".repeat(128),
      kilndSha256: "3".repeat(64),
      artifactSha256,
      packages: ["base-files\t13.0"],
      reproducible: false,
    }),
  );
  const manifest = {
    schemaVersion: 1 as const,
    name: "kiln-dev-base",
    version: "1",
    arch: "amd64" as const,
    artifactSha256,
    artifactSize: bytes.length,
    sourceBuild: `sha256:${createHash("sha256").update(metadata).digest("hex")}`,
    capabilities: ["development"],
    keyId: "operator",
  };
  return {
    metadata,
    manifest,
    signature: sign(null, Buffer.from(canonicalImageManifest(manifest)), privateKey).toString("base64"),
    trusted: {
      operator: {
        publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
        allowedNames: ["kiln-dev-base"],
        allowedCapabilities: ["development"],
        allowedArchitectures: ["amd64" as const],
      },
    },
  };
}
async function fresh() { const parsed = new URL(base!); const name = `kiln_linux_import_${randomUUID().replaceAll("-", "")}`; parsed.pathname = "/postgres"; const admin = new Pool({ connectionString: parsed.toString() }); await admin.query(`CREATE DATABASE ${name}`); parsed.pathname = `/${name}`; return { url: parsed.toString(), name, admin }; }
