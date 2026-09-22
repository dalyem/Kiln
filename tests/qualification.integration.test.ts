import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { Pool } from "pg";
import {
  canonicalImageManifest, canonicalQualificationDispatch,
  LifecycleQualificationService,
  qualificationPhases,
  type LifecycleQualificationProvider,
  type QualificationExecutionContext,
  type QualificationInspection,
  type QualificationReceipt,
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
  proxmoxQualificationMigration,
} from "@kiln/database";

const url = process.env.KILN_TEST_DATABASE_URL;

function qcow(): Buffer { const value = Buffer.alloc(112); value.write("QFI\u00fb", 0, "binary"); value.writeUInt32BE(3, 4); value.writeUInt32BE(9, 20); value.writeBigUInt64BE(4n * 1024n * 1024n, 24); value.writeUInt32BE(4, 96); value.writeUInt32BE(112, 100); return value; }
function signed() { const { privateKey, publicKey } = generateKeyPairSync("ed25519"); const bytes = qcow(); const manifest = { schemaVersion: 1 as const, name: "qualification-image", version: "1", arch: "amd64" as const, artifactSha256: createHash("sha256").update(bytes).digest("hex"), artifactSize: bytes.length, sourceBuild: "pg", capabilities: ["network_probe"], keyId: "operator" }; return { request: { manifest, signature: sign(null, Buffer.from(canonicalImageManifest(manifest)), privateKey).toString("base64"), artifactBase64: bytes.toString("base64") }, keys: { operator: { publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(), allowedNames: ["qualification-image"], allowedCapabilities: ["network_probe"], allowedArchitectures: ["amd64" as const] } } }; }
class Provider implements LifecycleQualificationProvider {
  readonly mode = "proxmox-qualification" as const;
  executeCalls: string[] = [];
  inspection = "COMPLETED" as QualificationInspection["status"];
  async executeQualificationPhase(context: QualificationExecutionContext): Promise<QualificationReceipt> { this.executeCalls.push(context.phase); const dispatch = { method: "POST", path: `/mock/${context.phase}`, body: null }; return { taskId: `task-${context.phase}`, workerType: "mock", sourceVmid: null, destinationVmid: null, tokenIdentity: "qual@pam!run", requestDigest: context.requestDigest, dispatch, dispatchDigest: canonicalQualificationDispatch(dispatch), responseDigest: "a".repeat(64), generatedUuid: null, generatedCtime: null }; }
  async inspectQualificationPhase(): Promise<QualificationInspection> { return { status: this.inspection }; }
}
function service(store: DrizzleStore, provider: Provider) { const image = signed(); return { image, service: new LifecycleQualificationService(store, provider, image.keys, { node: "pve1", pool: "kiln", stageStorage: "local", targetStorage: "local-lvm", pveVersion: "9.2.2", storageConfigDigest: "a".repeat(40), templateVmid: "9100", probeVmid: "9101", tokenIdentity: "qual@pam!run" }) }; }

describe.skipIf(!url)("qualification PostgreSQL journal", () => {
  it("persists one run, phases, resources, and retained allocations", async () => {
    const database = await freshDatabase(); const store = new DrizzleStore(database.url); const provider = new Provider();
    try {
      await migrate(store); await store.initializeInstallation(); const { image, service: qualification } = service(store, provider);
      const first = await qualification.createRun(image.request, "first");
      expect((await qualification.createRun(image.request, "first")).replayed).toBe(true);
      await expect(qualification.createRun(image.request, "other")).rejects.toMatchObject({ code: "CONFLICT" });
      for (const _phase of qualificationPhases) { await qualification.advance(first.run.id); await qualification.advance(first.run.id); }
      const status = await qualification.status(first.run.id);
      expect(provider.executeCalls).toEqual([...qualificationPhases]);
      expect(status?.run).toMatchObject({ status: "COMPLETED", completedAt: expect.any(String) });
      expect(status?.phases.every((phase) => phase.status === "COMPLETED")).toBe(true);
      expect(status?.allocations).toEqual(expect.arrayContaining([expect.objectContaining({ kind: "POOL", state: "RETAINED" }), expect.objectContaining({ kind: "STAGING", state: "RETAINED" })]));
      expect(await store.getResource(first.run.plan.templateResourceId)).toMatchObject({ providerResourceId: "9100", type: "image_template", state: "DESTROYED" });
      expect(await store.getResource(first.run.plan.probeResourceId)).toMatchObject({ providerResourceId: "9101", type: "network_probe", state: "DESTROYED" });
    } finally { await store.close(); await drop(database); }
  });

  it.each(["resource", "allocation", "child"])("denies dispatch with a missing %s proof", async (kind) => {
    const database = await freshDatabase(); const store = new DrizzleStore(database.url); const provider = new Provider();
    const sql = new Pool({ connectionString: database.url });
    try {
      await migrate(store); await store.initializeInstallation(); const { image, service: qualification } = service(store, provider);
      const { run } = await qualification.createRun(image.request, "proof");
      if (kind === "resource") await sql.query("UPDATE resources SET ownership='EXTERNAL' WHERE id=$1", [run.plan.probeResourceId]);
      if (kind === "allocation") await sql.query("DELETE FROM qualification_allocations WHERE run_id=$1 AND kind='STAGING'", [run.id]);
      if (kind === "child") await sql.query("DELETE FROM owned_attachment_identities WHERE resource_id=$1", [run.plan.probeResourceId]);
      await expect(qualification.advance(run.id)).rejects.toMatchObject({ code: "SAFETY_DENIED" });
      expect(provider.executeCalls).toEqual([]);
    } finally { await sql.end(); await store.close(); await drop(database); }
  });

  it("fences a dispatched phase whose receipt and failure event could not persist", async () => {
    const database = await freshDatabase(); let store = new DrizzleStore(database.url); const provider = new Provider(); const sql = new Pool({ connectionString: database.url });
    try {
      await migrate(store); await store.initializeInstallation(); const initial = service(store, provider); const { run } = await initial.service.createRun(initial.image.request, "crash");
      await sql.query(`CREATE FUNCTION reject_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.type IN ('qualification.phase_submitted','qualification.phase_unknown') THEN RAISE EXCEPTION 'injected persistence loss'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_receipt BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION reject_receipt()`);
      await expect(initial.service.advance(run.id)).rejects.toMatchObject({ cause: { message: "injected persistence loss" } });
      expect(provider.executeCalls).toEqual(["POOL_CREATE"]);
      expect(await store.getQualificationPhase(run.id, "POOL_CREATE")).toMatchObject({ status: "INTENT", receipt: null });
      await store.close(); await sql.query("DROP TRIGGER fail_receipt ON events");
      store = new DrizzleStore(database.url); await migrate(store); await store.initializeInstallation(); const recovered = service(store, provider).service;
      await recovered.recoverInstallation(); await recovered.advance(run.id);
      expect((await recovered.status(run.id))?.run.status).toBe("UNKNOWN");
      expect((await recovered.status(run.id))?.allocations).toContainEqual(expect.objectContaining({ kind: "POOL", state: "UNKNOWN" }));
      expect(await store.getQualificationPhase(run.id, "POOL_CREATE")).toMatchObject({ status: "UNKNOWN", safeReason: "RECOVERED_INTENT" });
      expect(provider.executeCalls).toEqual(["POOL_CREATE"]);
    } finally { await sql.end(); await store.close(); await drop(database); }
  });

  it("rolls back an unauditable dispatch intent and denies out-of-order phases", async () => {
    const database = await freshDatabase(); const store = new DrizzleStore(database.url); const provider = new Provider(); const sql = new Pool({ connectionString: database.url });
    try {
      await migrate(store); await store.initializeInstallation(); const initial = service(store, provider); const { run } = await initial.service.createRun(initial.image.request, "audit");
      const event = { installationId: run.installationId, projectId: "infrastructure", resourceId: null, type: "qualification.phase_intent", timestamp: new Date().toISOString(), payload: {} };
      await expect(store.beginQualificationPhase({ runId: run.id, name: "CLONE", intentDigest: "a".repeat(64), event })).rejects.toMatchObject({ code: "SAFETY_DENIED" });
      await sql.query(`CREATE FUNCTION reject_intent() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.type='qualification.phase_intent' THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_intent BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION reject_intent()`);
      await expect(initial.service.advance(run.id)).rejects.toMatchObject({ cause: { message: "injected audit failure" } });
      expect(await store.getQualificationPhase(run.id, "POOL_CREATE")).toBeNull();
      expect(provider.executeCalls).toEqual([]);
    } finally { await sql.end(); await store.close(); await drop(database); }
  });

  it("stops polling after the saved deadline and does not resubmit", async () => {
    const database = await freshDatabase(); const store = new DrizzleStore(database.url); const provider = new Provider(); const sql = new Pool({ connectionString: database.url });
    try {
      await migrate(store); await store.initializeInstallation(); const initial = service(store, provider); const { run } = await initial.service.createRun(initial.image.request, "deadline");
      await initial.service.advance(run.id);
      await sql.query("UPDATE qualification_phases SET reconciliation_deadline=now()-interval '1 second' WHERE run_id=$1", [run.id]);
      provider.inspectQualificationPhase = async () => { throw new Error("expired receipt must not be polled"); };
      await initial.service.advance(run.id);
      expect((await initial.service.status(run.id))?.run.status).toBe("UNKNOWN");
      expect(await store.getQualificationPhase(run.id, "POOL_CREATE")).toMatchObject({ status: "UNKNOWN", safeReason: "DEADLINE_EXCEEDED" });
      expect(provider.executeCalls).toEqual(["POOL_CREATE"]);
    } finally { await sql.end(); await store.close(); await drop(database); }
  });

  it("makes concurrent receipt completion idempotent", async () => {
    const database = await freshDatabase(); const store = new DrizzleStore(database.url); const provider = new Provider();
    try {
      await migrate(store); await store.initializeInstallation(); const initial = service(store, provider); const { run } = await initial.service.createRun(initial.image.request, "completion");
      await initial.service.advance(run.id);
      await Promise.all([initial.service.advance(run.id), initial.service.advance(run.id)]);
      expect(await store.getQualificationPhase(run.id, "POOL_CREATE")).toMatchObject({ status: "COMPLETED" });
      expect(provider.executeCalls).toEqual(["POOL_CREATE"]);
    } finally { await store.close(); await drop(database); }
  });

  it("claims one phase once and polls saved receipts after restart without resubmission", async () => {
    const database = await freshDatabase(); let first: DrizzleStore | null = new DrizzleStore(database.url); let restarted: DrizzleStore | null = null; const provider = new Provider();
    try {
      await migrate(first); await first.initializeInstallation(); const { image, service: qualification } = service(first, provider); const run = await qualification.createRun(image.request, "first");
      await Promise.all([qualification.advance(run.run.id), qualification.advance(run.run.id)]);
      expect(provider.executeCalls).toEqual(["POOL_CREATE"]);
      await first.close(); first = null;
      restarted = new DrizzleStore(database.url); await migrate(restarted); await restarted.initializeInstallation(); const resumed = service(restarted, provider).service;
      await restarted.recoverUnfinishedOperations();
      await resumed.recoverInstallation();
      expect((await resumed.status(run.run.id))?.phases[0]).toMatchObject({ name: "POOL_CREATE", status: "SUBMITTED" });
      await resumed.advance(run.run.id);
      expect(provider.executeCalls).toEqual(["POOL_CREATE"]);
      await restarted.close(); restarted = null;
    } finally { await restarted?.close(); await first?.close(); await drop(database); }
  });
});

async function migrate(store: DrizzleStore): Promise<void> { for (const migration of [initialMigration, gatewayMonitoringMigration, gatewayHealthAttestationMigration, gatewayIdentityMigration, networkProbeMigration, providerOperationMigration, imageProvenanceMigration, proxmoxQualificationMigration]) await store.migrate(await migration()); }
async function freshDatabase(): Promise<{ url: string; name: string; admin: Pool }> { const parsed = new URL(url!); const name = `kiln_qualification_${randomUUID().replaceAll("-", "")}`; parsed.pathname = "/postgres"; const admin = new Pool({ connectionString: parsed.toString() }); await admin.query(`CREATE DATABASE ${name}`); parsed.pathname = `/${name}`; return { url: parsed.toString(), name, admin }; }
async function drop(database: { name: string; admin: Pool }): Promise<void> { await database.admin.query(`DROP DATABASE ${database.name}`); await database.admin.end(); }
