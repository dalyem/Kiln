import { describe, expect, it } from "vitest";
import { ownershipTags, ResourceService, type Resource } from "@kiln/core";
import { MemoryStore } from "@kiln/database";
import { FakeComputeProvider } from "@kiln/providers";

async function fixture() {
  const store = new MemoryStore();
  const provider = new FakeComputeProvider();
  const service = new ResourceService(store, provider);
  const created = await service.create(
    { type: "development", projectId: "default", ttlSeconds: 3600 },
    "request-1",
    "test",
  );
  return { store, provider, service, resource: created.resource };
}
async function expectDenied(
  operation: "start" | "stop" | "destroy",
  change: (resource: Resource, provider: FakeComputeProvider) => void,
) {
  const { provider, service, resource, store } = await fixture();
  change(resource, provider);
  if (operation === "start") {
    const observed = provider.fixtures.get(resource.id)!;
    provider.fixtures.set(resource.id, {
      ...observed,
      providerResourceId: resource.id,
      tags: [
        "kiln",
        "kiln-managed",
        `kiln-installation-${resource.installationId}`,
        `kiln-resource-${resource.type}`,
        `kiln-resource-id-${resource.id}`,
      ],
    });
    await service.mutate(resource.id, "stop", "default");
    change(resource, provider);
  }
  await expect(
    service.mutate(resource.id, operation, "default"),
  ).rejects.toMatchObject({ code: "SAFETY_DENIED" });
  expect(
    provider.mutations.filter((m) => m.operation === operation),
  ).toHaveLength(0);
  expect((await store.getResource(resource.id))?.state).toBe("QUARANTINED");
}
describe("ownership safety boundary", () => {
  it.each(["start", "stop", "destroy"] as const)(
    "denies %s when a database record lacks an observed managed tag",
    async (operation) => {
      await expectDenied(operation, (resource, provider) => {
        provider.fixtures.set(resource.id, {
          providerId: "fake",
          providerResourceId: resource.id,
          providerKind: "fake",
          kind: resource.type,
          pool: "kiln",
          node: null,
          tags: ["kiln"],
        });
      });
    },
  );
  it.each(["start", "stop", "destroy"] as const)(
    "denies %s for wrong installation marker",
    async (operation) => {
      await expectDenied(operation, (resource, provider) => {
        const observed = provider.fixtures.get(resource.id)!;
        observed.tags = observed.tags.map((tag) =>
          tag.startsWith("kiln-installation-")
            ? "kiln-installation-other"
            : tag,
        );
      });
    },
  );
  it.each(["start", "stop", "destroy"] as const)(
    "denies %s for a provider identity mismatch",
    async (operation) => {
      await expectDenied(operation, (resource, provider) => {
        const observed = provider.fixtures.get(resource.id)!;
        observed.providerResourceId = "same-name-other-resource";
      });
    },
  );
  it("never targets a stopped external provider fixture", async () => {
    const { provider, service } = await fixture();
    provider.fixtures.set("dev-lookalike", {
      providerId: "fake",
      providerResourceId: "dev-lookalike",
      providerKind: "fake",
      kind: "development",
      pool: "kiln",
      node: null,
      tags: [],
    });
    await expect(
      service.mutate("dev-lookalike", "destroy", "default"),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
    expect(provider.mutations.some((m) => m.id === "dev-lookalike")).toBe(
      false,
    );
  });
  it("allows a correctly owned resource to stop and destroy", async () => {
    const { provider, service, resource } = await fixture();
    await service.mutate(resource.id, "stop", "default");
    await service.mutate(resource.id, "destroy", "default");
    expect(provider.mutations.map((m) => m.operation)).toEqual([
      "create",
      "stop",
      "destroy",
    ]);
  });
  it("fails closed and marks a missing resource lost", async () => {
    const { provider, service, resource, store } = await fixture();
    provider.fixtures.delete(resource.id);
    await expect(
      service.mutate(resource.id, "destroy", "default"),
    ).rejects.toMatchObject({ code: "SAFETY_DENIED" });
    expect((await store.getResource(resource.id))?.state).toBe("LOST");
  });
  it.each(["stop", "destroy"] as const)(
    "denies %s for a persisted EXTERNAL record even when tags match",
    async (operation) => {
      const { provider, resource, service, store } = await fixture();
      resource.ownership = "EXTERNAL";
      await store.updateResource(resource);
      await expect(
        service.mutate(resource.id, operation, "default"),
      ).rejects.toMatchObject({ code: "SAFETY_DENIED" });
      expect(
        provider.mutations.some((entry) => entry.operation === operation),
      ).toBe(false);
    },
  );
  it.each(["pool", "node", "providerKind", "type", "conflictingTags"] as const)(
    "denies destroy for a %s mismatch",
    async (mismatch) => {
      await expectDenied("destroy", (resource, provider) => {
        const observed = provider.fixtures.get(resource.id)!;
        if (mismatch === "pool") observed.pool = "other";
        if (mismatch === "node") observed.node = "pve2";
        if (mismatch === "providerKind") observed.providerKind = "qemu";
        if (mismatch === "type") observed.kind = "browser";
        if (mismatch === "conflictingTags")
          observed.tags.push("kiln-resource-browser");
      });
    },
  );
  it("denies destroy when the record installation differs from the active installation", async () => {
    await expectDenied("destroy", (resource, provider) => {
      resource.installationId = "different-installation";
      const observed = provider.fixtures.get(resource.id)!;
      observed.tags = ownershipTags(resource);
    });
  });
});
