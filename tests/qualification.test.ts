import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalImageManifest, canonicalQualificationDispatch, LifecycleQualificationService, type LifecycleQualificationProvider, type QualificationExecutionContext, type QualificationPhaseName, type QualificationReceipt } from "@kiln/core";
import { MemoryStore } from "@kiln/database";

function artifact(): Buffer {
  const value = Buffer.alloc(112);
  value.write("QFI\u00fb", 0, "binary"); value.writeUInt32BE(3, 4); value.writeBigUInt64BE(0n, 8); value.writeUInt32BE(0, 16); value.writeUInt32BE(9, 20); value.writeBigUInt64BE(4n * 1024n * 1024n, 24); value.writeUInt32BE(0, 32); value.writeBigUInt64BE(0n, 72); value.writeUInt32BE(4, 96); value.writeUInt32BE(112, 100);
  return value;
}
function request() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519"); const bytes = artifact(); const manifest = { schemaVersion: 1 as const, name: "qualification-image", version: "1", arch: "amd64" as const, artifactSha256: createHash("sha256").update(bytes).digest("hex"), artifactSize: bytes.length, sourceBuild: "test", capabilities: ["network_probe"], keyId: "operator" };
  return { request: { manifest, signature: sign(null, Buffer.from(canonicalImageManifest(manifest)), privateKey).toString("base64"), artifactBase64: bytes.toString("base64") }, keys: { operator: { publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(), allowedNames: ["qualification-image"], allowedCapabilities: ["network_probe"], allowedArchitectures: ["amd64" as const] } } };
}
class Provider implements LifecycleQualificationProvider {
  readonly mode = "proxmox-qualification" as const;
  calls: QualificationPhaseName[] = [];
  async executeQualificationPhase(context: QualificationExecutionContext): Promise<QualificationReceipt> { this.calls.push(context.phase); const dispatch = { method: "POST", path: `/mock/${context.phase}`, body: null }; return { taskId: null, workerType: null, sourceVmid: null, destinationVmid: null, tokenIdentity: "qual@pam!run", requestDigest: context.requestDigest, dispatch, dispatchDigest: canonicalQualificationDispatch(dispatch), responseDigest: "b".repeat(64), generatedUuid: null, generatedCtime: null }; }
  async inspectQualificationPhase() { return { status: "COMPLETED" as const }; }
}

describe("lifecycle qualification journal", () => {
  it("persists one installation-bound signed run and advances exactly one phase", async () => {
    const store = new MemoryStore(); const provider = new Provider(); const signed = request();
    const service = new LifecycleQualificationService(store, provider, signed.keys, { node: "pve1", pool: "kiln", stageStorage: "local", targetStorage: "local-lvm", pveVersion: "9.2.2", storageConfigDigest: "a".repeat(40), templateVmid: "9100", probeVmid: "9101", tokenIdentity: "qual@pam!run" });
    const created = await service.createRun(signed.request, "first");
    const replay = await service.createRun(signed.request, "first");
    expect(replay).toMatchObject({ replayed: true, run: { id: created.run.id } });
    await Promise.all([service.advance(created.run.id), service.advance(created.run.id)]);
    expect(provider.calls).toEqual(["POOL_CREATE"]);
    await service.advance(created.run.id);
    expect(await store.getQualificationPhase(created.run.id, "POOL_CREATE")).toMatchObject({ status: "COMPLETED" });
  });
});
