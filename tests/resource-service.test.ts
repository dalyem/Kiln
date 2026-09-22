import { describe, expect, it } from "vitest";
import { ResourceService, chooseNode } from "@kiln/core";
import { MemoryStore } from "@kiln/database";
import { FakeComputeProvider } from "@kiln/providers";
describe("resource lifecycle", () => {
  it("returns the same resource for concurrent duplicate create requests", async () => {
    const provider = new FakeComputeProvider();
    const service = new ResourceService(new MemoryStore(), provider);
    const [first, second] = await Promise.all([
      service.create(
        { type: "execution", projectId: "default", ttlSeconds: 60 },
        "same",
        "agent",
      ),
      service.create(
        { type: "execution", projectId: "default", ttlSeconds: 60 },
        "same",
        "agent",
      ),
    ]);
    expect(first.resource.id).toBe(second.resource.id);
    expect(
      provider.mutations.filter((m) => m.operation === "create"),
    ).toHaveLength(1);
  });
  it("rejects reusing an idempotency key for a different request", async () => {
    const service = new ResourceService(
      new MemoryStore(),
      new FakeComputeProvider(),
    );
    await service.create(
      { type: "execution", projectId: "default", ttlSeconds: 60 },
      "same",
      "agent",
    );
    await expect(
      service.create(
        { type: "browser", projectId: "default", ttlSeconds: 60 },
        "same",
        "agent",
      ),
    ).rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
  });
  it("expires a lease only once and does not retry an already destroyed resource", async () => {
    let now = new Date("2026-01-01T00:00:00.000Z");
    const provider = new FakeComputeProvider();
    const service = new ResourceService(new MemoryStore(), provider, () => now);
    const created = await service.create(
      { type: "browser", projectId: "default", ttlSeconds: 60 },
      "lease",
      "agent",
    );
    now = new Date("2026-01-01T00:01:00.000Z");
    await service.expire();
    await service.expire();
    expect(
      provider.mutations.filter(
        (m) => m.operation === "destroy" && m.id === created.resource.id,
      ),
    ).toHaveLength(1);
  });
  it("extension wins when it holds the shared resource lock before expiry", async () => {
    let now = new Date("2026-01-01T00:00:00.000Z");
    const store = new MemoryStore();
    const service = new ResourceService(
      store,
      new FakeComputeProvider(),
      () => now,
    );
    const created = await service.create(
      { type: "browser", projectId: "default", ttlSeconds: 60 },
      "extend",
      "agent",
    );
    now = new Date("2026-01-01T00:01:00.000Z");
    await service.extend(created.resource.id, "default", 60);
    await service.expire();
    expect((await store.getResource(created.resource.id))?.state).toBe("READY");
  });
  it("does not accept a destroy retry without a completed destroy operation", async () => {
    const store = new MemoryStore();
    const service = new ResourceService(store, new FakeComputeProvider());
    const created = await service.create(
      { type: "browser", projectId: "default", ttlSeconds: 60 },
      "terminal",
      "agent",
    );
    created.resource.state = "DESTROYED";
    await store.updateResource(created.resource);
    await expect(
      service.mutate(created.resource.id, "destroy", "default"),
    ).rejects.toMatchObject({ code: "SAFETY_DENIED" });
  });
});
describe("scheduler", () => {
  it("excludes nodes missing a required storage, network, image, or headroom capability", () => {
    const selected = chooseNode(
      [
        {
          id: "missing-image",
          online: true,
          cpuFree: 8,
          memoryFree: 16,
          storage: ["local"],
          networks: ["sandbox"],
          images: [],
        },
        {
          id: "offline",
          online: false,
          cpuFree: 8,
          memoryFree: 16,
          storage: ["local"],
          networks: ["sandbox"],
          images: ["dev"],
        },
        {
          id: "eligible",
          online: true,
          cpuFree: 4,
          memoryFree: 8,
          storage: ["local"],
          networks: ["sandbox"],
          images: ["dev"],
        },
      ],
      { storage: "local", network: "sandbox", image: "dev", cpu: 2, memory: 4 },
    );
    expect(selected?.id).toBe("eligible");
  });
});
