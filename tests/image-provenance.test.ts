import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  canonicalImageManifest,
  ImageProvenanceService,
  ResourceService,
  type ImageImportRequest,
  type TrustedImageKeys,
} from "@kiln/core";
import { MemoryStore } from "@kiln/database";
import { FakeAsyncComputeProvider, FakeComputeProvider } from "@kiln/providers";

function signedImport(capabilities = ["development", "execution"]): { request: ImageImportRequest; keys: TrustedImageKeys; signed: (manifest: ImageImportRequest["manifest"], artifact: Buffer) => ImageImportRequest } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const artifact = Buffer.from("fake-stage1-artifact");
  const manifest = {
    schemaVersion: 1 as const,
    name: "dev-image",
    version: "1.0.0",
    arch: "amd64" as const,
    artifactSha256: createHash("sha256").update(artifact).digest("hex"),
    artifactSize: artifact.length,
    sourceBuild: "ci-42",
    capabilities,
    keyId: "operator-dev",
  };
  return {
    request: {
      manifest,
      signature: sign(null, Buffer.from(canonicalImageManifest(manifest)), privateKey).toString("base64"),
      artifactBase64: artifact.toString("base64"),
    },
    keys: { "operator-dev": { publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(), allowedNames: ["dev-image"], allowedCapabilities: capabilities, allowedArchitectures: ["amd64"] } },
    signed: (nextManifest, nextArtifact) => ({ manifest: nextManifest, signature: sign(null, Buffer.from(canonicalImageManifest(nextManifest)), privateKey).toString("base64"), artifactBase64: nextArtifact.toString("base64") }),
  };
}

describe("image provenance", () => {
  it("imports a signed fake template and provisions a guarded full clone", async () => {
    const store = new MemoryStore();
    const provider = new FakeComputeProvider();
    const { request, keys, signed } = signedImport();
    const images = new ImageProvenanceService(store, provider, keys);
    const imported = await images.importImage(request, "image-import", "infra");
    const replay = await images.importImage(request, "image-import", "infra");
    expect(replay).toMatchObject({ replayed: true, template: { resourceId: imported.template.resourceId, state: "READY" } });

    const resources = new ResourceService(store, provider);
    const created = await resources.create({ type: "development", projectId: "default", ttlSeconds: 60, templateId: imported.template.resourceId }, "clone", "test");
    expect(created.resource).toMatchObject({ state: "READY", provenanceRequired: true });
    expect(await store.provenanceSummary(created.resource.id)).toMatchObject({ templateId: imported.template.resourceId, cloneMode: "FULL" });
    await expect(images.retireTemplate(imported.template.resourceId)).rejects.toMatchObject({ code: "CONFLICT" });
    await resources.mutate(created.resource.id, "stop", "default");
    await resources.mutate(created.resource.id, "destroy", "default");
    await images.retireTemplate(imported.template.resourceId);
  });

  it("denies a changed template and an injected destination NIC before a mutation", async () => {
    const store = new MemoryStore();
    const provider = new FakeComputeProvider();
    const { request, keys, signed } = signedImport();
    const images = new ImageProvenanceService(store, provider, keys);
    const imported = await images.importImage(request, "template-drift", "infra");
    const template = (await store.getTemplateImport(imported.template.resourceId))!;
    provider.attachmentGraphs.get(template.providerResourceId)!.push({ id: "foreign", class: "NIC", ownership: "OWNED_CHILD", nativeId: "foreign-nic", attributes: { model: "e1000" } });
    const resources = new ResourceService(store, provider);
    await expect(resources.create({ type: "development", projectId: "default", ttlSeconds: 60, templateId: template.resourceId }, "denied-clone", "test")).rejects.toMatchObject({ code: "SAFETY_DENIED" });
    provider.attachmentGraphs.set(template.providerResourceId, structuredClone(template.attachments));
    const created = await resources.create({ type: "development", projectId: "default", ttlSeconds: 60, templateId: template.resourceId }, "allowed-clone", "test");
    provider.attachmentGraphs.get(created.resource.providerResourceId)!.push({ id: "foreign", class: "NIC", ownership: "OWNED_CHILD", nativeId: "foreign-nic-2", attributes: { model: "e1000" } });
    await expect(resources.mutate(created.resource.id, "stop", "default")).rejects.toMatchObject({ code: "SAFETY_DENIED" });
    expect(provider.mutations.filter((mutation) => mutation.operation === "stop")).toHaveLength(0);
  });

  it("keeps a lost clone receipt fenced without a second provider submission", async () => {
    class LostReceipt extends FakeAsyncComputeProvider {
      submissions = 0;
      override async submitOperation(operation: Parameters<FakeAsyncComputeProvider["submitOperation"]>[0]) {
        if (operation.snapshot?.type === "image_template") return super.submitOperation(operation);
        this.submissions += 1;
        await super.submitOperation(operation);
        throw new Error("lost receipt");
      }
    }
    const store = new MemoryStore();
    const provider = new LostReceipt();
    const { request, keys } = signedImport();
    const images = new ImageProvenanceService(store, provider, keys);
    const imported = await images.importImage(request, "lost-template", "infra");
    const templateOperation = (await store.listOperations(imported.template.resourceId))[0]!;
    await provider.completeTask(templateOperation.taskHandle!.taskId);
    await new ResourceService(store, provider).reconcileOperations();
    const resources = new ResourceService(store, provider);
    await expect(resources.create({ type: "development", projectId: "default", ttlSeconds: 60, templateId: imported.template.resourceId }, "lost-clone", "test")).rejects.toThrow("lost receipt");
    const resource = (await store.listResources("default"))[0]!;
    expect(await store.unresolvedOperation(resource.id)).toMatchObject({ status: "UNKNOWN", safeReason: "DISPATCH_UNKNOWN" });
    expect(provider.submissions).toBe(1);
  });

  it("reconciles async template import and clone destroy without requiring a removed graph", async () => {
    const store = new MemoryStore();
    const provider = new FakeAsyncComputeProvider();
    const { request, keys } = signedImport();
    const images = new ImageProvenanceService(store, provider, keys);
    const imported = await images.importImage(request, "async-template", "infra");
    const resources = new ResourceService(store, provider);
    const importOperation = (await store.listOperations(imported.template.resourceId))[0]!;
    await provider.completeTask(importOperation.taskHandle!.taskId);
    await resources.reconcileOperations();
    expect((await store.getTemplateImport(imported.template.resourceId))?.state).toBe("READY");

    const created = await resources.create({ type: "development", projectId: "default", ttlSeconds: 60, templateId: imported.template.resourceId }, "async-clone", "test");
    const createOperation = (await store.listOperations(created.resource.id))[0]!;
    await provider.completeTask(createOperation.taskHandle!.taskId);
    await resources.reconcileOperations();
    await resources.mutate(created.resource.id, "destroy", "default");
    const destroyOperation = (await store.listOperations(created.resource.id)).find((operation) => operation.kind === "destroy")!;
    await provider.completeTask(destroyOperation.taskHandle!.taskId);
    await resources.reconcileOperations();
    expect((await store.getResource(created.resource.id))?.state).toBe("DESTROYED");
  });

  it("rejects a prepared clone plan substituted after its receipt", async () => {
    const store = new MemoryStore();
    const provider = new FakeAsyncComputeProvider();
    const { request, keys, signed } = signedImport();
    const images = new ImageProvenanceService(store, provider, keys);
    const first = await images.importImage(request, "template-a", "infra");
    const firstOperation = (await store.listOperations(first.template.resourceId))[0]!;
    await provider.completeTask(firstOperation.taskHandle!.taskId);
    const resources = new ResourceService(store, provider);
    await resources.reconcileOperations();
    const artifact = Buffer.from("fake-stage1-artifact-v2");
    const secondRequest = signed({ ...request.manifest, version: "1.0.1", sourceBuild: "ci-43", artifactSha256: createHash("sha256").update(artifact).digest("hex"), artifactSize: artifact.length }, artifact);
    const second = await images.importImage(secondRequest, "template-b", "infra");
    const secondOperation = (await store.listOperations(second.template.resourceId))[0]!;
    await provider.completeTask(secondOperation.taskHandle!.taskId);
    await resources.reconcileOperations();
    const cloneA = await resources.create({ type: "development", projectId: "default", ttlSeconds: 60, templateId: first.template.resourceId }, "clone-a", "test");
    const cloneB = await resources.create({ type: "development", projectId: "default", ttlSeconds: 60, templateId: second.template.resourceId }, "clone-b", "test");
    const operationA = (await store.listOperations(cloneA.resource.id))[0]!;
    const planB = structuredClone(provider.preparedPlans.get(cloneB.resource.id)!);
    planB.resourceId = cloneA.resource.id;
    planB.providerResourceId = cloneA.resource.providerResourceId;
    planB.canonicalDigest = operationA.snapshot!.provisioningPlanDigest!;
    provider.preparedPlans.set(cloneA.resource.id, planB);
    await expect(provider.completeTask(operationA.taskHandle!.taskId)).rejects.toMatchObject({ code: "SAFETY_DENIED" });
    expect(await provider.inspect(cloneA.resource.providerResourceId)).toBeNull();
    await resources.reconcileOperations();
    expect((await store.getResource(cloneA.resource.id))?.state).toBe("PROVISIONING");
    expect((await store.listOperations(cloneA.resource.id))[0]).toMatchObject({ status: "SUBMITTED" });
  });

  it("rejects completion when the durable source resource is retargeted", async () => {
    const store = new MemoryStore();
    const provider = new FakeAsyncComputeProvider();
    const { request, keys } = signedImport();
    const images = new ImageProvenanceService(store, provider, keys);
    const template = await images.importImage(request, "retarget-template", "infra");
    const templateOperation = (await store.listOperations(template.template.resourceId))[0]!;
    await provider.completeTask(templateOperation.taskHandle!.taskId);
    const resources = new ResourceService(store, provider);
    await resources.reconcileOperations();
    const clone = await resources.create({ type: "development", projectId: "default", ttlSeconds: 60, templateId: template.template.resourceId }, "retarget-clone", "test");
    const cloneOperation = (await store.listOperations(clone.resource.id))[0]!;
    await provider.completeTask(cloneOperation.taskHandle!.taskId);
    const source = (await store.getResource(template.template.resourceId))!;
    const replacementId = "replacement-template";
    provider.fixtures.set(replacementId, { ...provider.fixtures.get(source.providerResourceId)!, providerResourceId: replacementId });
    provider.attachmentGraphs.set(replacementId, structuredClone(provider.attachmentGraphs.get(source.providerResourceId)!));
    (store as unknown as { data: Map<string, typeof source> }).data.set(source.id, { ...source, providerResourceId: replacementId });
    await resources.reconcileOperations();
    expect((await store.getResource(clone.resource.id))?.state).toBe("PROVISIONING");
    expect((await store.listOperations(clone.resource.id))[0]).toMatchObject({ status: "UNKNOWN", safeReason: "POSTCONDITION_FAILED" });
  });

  it("rejects prepared template evidence changed after its receipt before any effect", async () => {
    const store = new MemoryStore();
    const provider = new FakeAsyncComputeProvider();
    const { request, keys } = signedImport();
    const imported = await new ImageProvenanceService(store, provider, keys).importImage(request, "prepared-template-tamper", "infra");
    const operation = (await store.listOperations(imported.template.resourceId))[0]!;
    const prepared = provider.preparedTemplateAttachments.get(imported.template.resourceId)!;
    prepared[0] = { ...prepared[0]!, nativeId: "foreign-boot" };
    await expect(provider.completeTask(operation.taskHandle!.taskId)).rejects.toMatchObject({ code: "SAFETY_DENIED" });
    expect(await provider.inspect(imported.template.providerResourceId)).toBeNull();
    expect(await provider.inspectAttachments({ id: imported.template.resourceId, installationId: "unused", projectId: "infrastructure", type: "image_template", ownership: "KILN_MANAGED", state: "PROVISIONING", providerId: "fake", providerResourceId: imported.template.providerResourceId, providerKind: "fake", node: imported.template.node, pool: imported.template.pool, createdBy: "test", createdAt: "", expiresAt: null, profile: null })).toBeNull();
  });

  it("denies a missing plan and an unresolved template import cannot retire", async () => {
    class MissingPlanStore extends MemoryStore {
      missing = false;
      override async getProvisioningPlan(resourceId: string) {
        return this.missing ? null : super.getProvisioningPlan(resourceId);
      }
    }
    const store = new MissingPlanStore();
    const provider = new FakeComputeProvider();
    const { request, keys } = signedImport();
    const images = new ImageProvenanceService(store, provider, keys);
    const imported = await images.importImage(request, "missing-plan-template", "infra");
    const resources = new ResourceService(store, provider);
    const created = await resources.create({ type: "development", projectId: "default", ttlSeconds: 60, templateId: imported.template.resourceId }, "missing-plan", "test");
    store.missing = true;
    await expect(resources.mutate(created.resource.id, "stop", "default")).rejects.toMatchObject({ code: "SAFETY_DENIED" });

    const asyncStore = new MemoryStore();
    const asyncProvider = new FakeAsyncComputeProvider();
    const asyncImages = new ImageProvenanceService(asyncStore, asyncProvider, keys);
    const pending = await asyncImages.importImage(request, "pending-template", "infra");
    await expect(asyncImages.retireTemplate(pending.template.resourceId)).rejects.toMatchObject({ code: "CONFLICT" });
  });

  it("denies clone mutation when its owned child registry entry is missing", async () => {
    const store = new MemoryStore();
    const provider = new FakeComputeProvider();
    const { request, keys } = signedImport();
    const imported = await new ImageProvenanceService(store, provider, keys).importImage(request, "registry-template", "infra");
    const resources = new ResourceService(store, provider);
    const clone = await resources.create({ type: "development", projectId: "default", ttlSeconds: 60, templateId: imported.template.resourceId }, "registry-clone", "test");
    const plan = await store.getProvisioningPlan(clone.resource.id);
    (store as unknown as { attachmentOwners: Map<string, string> }).attachmentOwners.delete(plan!.attachments.find((attachment) => attachment.ownership === "OWNED_CHILD")!.nativeId);
    await expect(resources.mutate(clone.resource.id, "stop", "default")).rejects.toMatchObject({ code: "SAFETY_DENIED" });
    expect(provider.mutations.filter((entry) => entry.operation === "stop")).toHaveLength(0);
  });

  it("rejects altered artifacts, unknown signers, and immutable version conflicts", async () => {
    const store = new MemoryStore();
    const provider = new FakeComputeProvider();
    const { request, keys, signed } = signedImport();
    const images = new ImageProvenanceService(store, provider, keys);
    await expect(images.importImage({ ...request, artifactBase64: Buffer.from("altered").toString("base64") }, "altered", "infra")).rejects.toMatchObject({ code: "INVALID_INPUT" });
    await expect(new ImageProvenanceService(store, provider, {}).importImage(request, "unknown", "infra")).rejects.toMatchObject({ code: "INVALID_INPUT" });
    await images.importImage(request, "version-one", "infra");
    const otherArtifact = Buffer.from("another-stage1-artifact");
    const conflictRequest = signed({ ...request.manifest, artifactSha256: createHash("sha256").update(otherArtifact).digest("hex"), artifactSize: otherArtifact.length, sourceBuild: "ci-43" }, otherArtifact);
    await expect(images.importImage(conflictRequest, "version-conflict", "infra")).rejects.toMatchObject({ code: "CONFLICT" });
  });
});
