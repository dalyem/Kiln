import { describe, expect, it } from "vitest";
import { MemoryStore } from "@kiln/database";
import type { LinuxImportAllocation, LinuxImportRun, Resource } from "@kiln/core";

function run(installationId: string): LinuxImportRun {
  const plan = { schemaVersion: 1 as const, installationId, node: "node1", pool: "kiln", stageStorage: "local", targetStorage: "local-lvm", pveVersion: "9.2.2" as const, tokenIdentity: "root@pam!kiln", storageConfigDigest: "a".repeat(40), stageId: "lstg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", stagePath: "/private/lstg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", stageSha256: "b".repeat(64), templateVmid: "301", cloneVmid: "302", templateName: "kiln-linux-template", cloneName: "kiln-linux-probe", sourcePoolRunId: "qual_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", sourcePoolAllocationId: "alloc_pool_qual", sourcePoolNonce: "nonce", sourcePoolComment: "kiln-qualification-qual_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;nonce=nonce", templateResourceId: "img_template_a", cloneResourceId: "img_clone_a", templateNonce: "template-nonce", cloneNonce: "clone-nonce", image: { id: "img_a", manifest: { schemaVersion: 1 as const, name: "kiln-dev-base", version: "0.1.0", arch: "amd64" as const, artifactSha256: "b".repeat(64), artifactSize: 1, sourceBuild: "sha256:" + "c".repeat(64), capabilities: ["development"], keyId: "test" }, manifestDigest: "d".repeat(64), signerFingerprint: "e".repeat(64), policyDigest: "f".repeat(64) }, buildMetadataSha256: "c".repeat(64), canonicalDigest: "1".repeat(64) };
  return { id: "limp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", installationId, idempotencyKey: "key", normalizedPayload: "payload", status: "ACTIVE", plan, createdAt: new Date().toISOString(), completedAt: null };
}
describe("Linux import journal", () => {
  it("records reservations and denies an out-of-order phase", async () => {
    const store = new MemoryStore(); const installationId = await store.installationId(); const value = run(installationId);
    const resources: Resource[] = ["301", "302"].map((vmid, index) => ({ id: index ? value.plan.cloneResourceId : value.plan.templateResourceId, installationId, projectId: "infrastructure", type: index ? "execution" : "image_template", ownership: "KILN_MANAGED", state: "PROVISIONING", providerId: "proxmox", providerResourceId: vmid, providerKind: "qemu", node: "node1", pool: "kiln", createdBy: "test", createdAt: value.createdAt, expiresAt: null, profile: "proxmox-linux-image-import", provenanceRequired: true }));
    const allocations: LinuxImportAllocation[] = ["STAGING", "TEMPLATE_DISK", "CLONE_DISK"].map((kind, index) => ({ id: `alloc_${kind}`, runId: value.id, kind: kind as LinuxImportAllocation["kind"], identity: `id_${index}`, intentDigest: "1".repeat(64), state: "RESERVED", createdAt: value.createdAt }));
    await store.createLinuxImportRun({ run: value, resources, allocations, event: { installationId, projectId: "infrastructure", resourceId: null, type: "linux_import.run_intent", timestamp: value.createdAt, payload: {} } });
    await expect(store.beginLinuxImportPhase({ runId: value.id, name: "IMPORT", intentDigest: "2".repeat(64), event: { installationId, projectId: "infrastructure", resourceId: null, type: "test", timestamp: value.createdAt, payload: {} } })).rejects.toMatchObject({ code: "SAFETY_DENIED" });
    expect((await store.getLinuxImportProof(value.id)).children).toHaveLength(3);
    for (const name of ["UPLOAD", "IMPORT", "TEMPLATE", "CLONE", "STAMP", "START", "STOP", "DESTROY_CLONE", "DESTROY_TEMPLATE"] as const) {
      await store.beginLinuxImportPhase({ runId: value.id, name, intentDigest: `${name[0]}`.repeat(64), event: { installationId, projectId: "infrastructure", resourceId: null, type: "test", timestamp: value.createdAt, payload: {} } });
      await store.submitLinuxImportPhase(value.id, name, receipt(`${name[0]}`.repeat(64)), { installationId, projectId: "infrastructure", resourceId: null, type: "test", timestamp: value.createdAt, payload: {} });
      await store.completeLinuxImportPhase(value.id, name, { installationId, projectId: "infrastructure", resourceId: null, type: "test", timestamp: value.createdAt, payload: {} });
    }
    expect((await store.getLinuxImportRun(value.id))?.status).toBe("COMPLETED");
    const proof = await store.getLinuxImportProof(value.id);
    expect(proof.resources.map((resource) => resource.state)).toEqual(["DESTROYED", "DESTROYED"]);
    expect(proof.allocations.map((allocation) => [allocation.kind, allocation.state])).toEqual([["STAGING", "RETAINED"], ["TEMPLATE_DISK", "DESTROYED"], ["CLONE_DISK", "DESTROYED"]]);
  });
});
function receipt(digest: string) { return { taskId: null, tokenIdentity: "root@pam!kiln", workerType: null, sourceVmid: null, destinationVmid: null, requestDigest: digest, dispatch: { method: "POST", path: "/test", body: null }, dispatchDigest: "a".repeat(64), responseDigest: "b".repeat(64), generatedUuid: null, generatedCtime: null, configDigest: null }; }
