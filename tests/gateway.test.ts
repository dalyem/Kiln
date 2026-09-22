import { describe, expect, it } from "vitest";
import type { ProviderInventory } from "@kiln/core";
import { DoctorService, GatewayMonitor, GatewayService, ResourceService } from "@kiln/core";
import { MemoryStore } from "@kiln/database";
import { FakeComputeProvider } from "@kiln/providers";

describe("protected gateways", () => {
  it("rejects gateway creation through the ordinary resource API", async () => {
    const service = new ResourceService(new MemoryStore(), new FakeComputeProvider());
    await expect(
      service.create({ type: "gateway", projectId: "default", ttlSeconds: 60 }, "gateway", "agent"),
    ).rejects.toMatchObject({ code: "SAFETY_DENIED" });
  });
  it("holds workload admission until the configured gateway has fresh ready evidence", async () => {
    let now = new Date("2026-01-01T00:00:00.000Z");
    const provider = new FakeComputeProvider({ nodes: [{ id: "node-a", online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] }], storage: [], resources: [] }, () => now);
    const store = new MemoryStore();
    const gateway = new GatewayService(store, provider, () => now);
    const resources = new ResourceService(store, provider, () => now);
    await gateway.createFakeGateway("node-a", "gateway-1", "infra");
    await expect(resources.create({ type: "execution", projectId: "default", ttlSeconds: 60 }, "work", "agent")).rejects.toMatchObject({ code: "NETWORK_NOT_READY" });
    await new GatewayMonitor(store, provider, () => now).scan();
    const created = await resources.create({ type: "execution", projectId: "default", ttlSeconds: 60 }, "work", "agent");
    expect(created.resource.node).toBe("node-a");
    now = new Date("2026-01-01T00:00:31.000Z");
    await expect(resources.create({ type: "browser", projectId: "default", ttlSeconds: 60 }, "stale", "agent")).rejects.toMatchObject({ code: "NETWORK_NOT_READY" });
  });
  it("deduplicates and resolves durable gateway incidents without mutating the gateway", async () => {
    let now = new Date("2026-01-01T00:00:00.000Z");
    const provider = new FakeComputeProvider({ nodes: [{ id: "node-a", online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] }], storage: [], resources: [] }, () => now);
    const store = new MemoryStore();
    const created = await new GatewayService(store, provider, () => now).createFakeGateway("node-a", "gateway-2", "infra");
    provider.gatewayEvidence.set(created.resource.id, { services: "FAIL" });
    const monitor = new GatewayMonitor(store, provider, () => now);
    await monitor.scan();
    await monitor.scan();
    expect((await store.listGatewayIncidents("node-a")).filter((incident) => incident.status === "OPEN")).toHaveLength(1);
    provider.gatewayEvidence.set(created.resource.id, { services: "PASS" });
    now = new Date("2026-01-01T00:00:01.000Z");
    await monitor.scan();
    expect((await store.listGatewayIncidents("node-a"))[0]).toMatchObject({ status: "RESOLVED" });
    expect(provider.mutations.filter((mutation) => mutation.operation !== "create")).toEqual([]);
  });
  it("reports unconfigured nodes as warnings without persisting a doctor query", async () => {
    const provider = new FakeComputeProvider({ nodes: [{ id: "node-a", online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] }], storage: [], resources: [] });
    const store = new MemoryStore();
    const doctor = await new DoctorService(store, provider).inspect();
    expect(doctor).toMatchObject({ overall: "DEGRADED", repairEnabled: false, nodes: [{ node: "node-a", status: "UNCONFIGURED" }] });
    expect(await store.listGatewayIncidents()).toEqual([]);
  });
  it("does not let expiry or workload lifecycle calls mutate a protected gateway", async () => {
    const provider = new FakeComputeProvider({ nodes: [{ id: "node-a", online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] }], storage: [], resources: [] });
    const store = new MemoryStore();
    const gateway = await new GatewayService(store, provider).createFakeGateway("node-a", "gateway-protected", "infra");
    const corrupt = (await store.getResource(gateway.resource.id))!;
    corrupt.expiresAt = "2020-01-01T00:00:00.000Z";
    await store.updateResource(corrupt);
    const resources = new ResourceService(store, provider);
    await expect(resources.mutate(gateway.resource.id, "stop", "infrastructure")).rejects.toMatchObject({ code: "SAFETY_DENIED" });
    await resources.expire();
    expect(provider.mutations.filter((mutation) => mutation.operation !== "create")).toEqual([]);
  });
  it("permits one protected gateway per fake node while replaying its idempotent request", async () => {
    const provider = new FakeComputeProvider({ nodes: [{ id: "node-a", online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] }], storage: [], resources: [] });
    const gateways = new GatewayService(new MemoryStore(), provider);
    const first = await gateways.createFakeGateway("node-a", "same", "infra");
    const replay = await gateways.createFakeGateway("node-a", "same", "infra");
    expect(replay).toMatchObject({ replayed: true, resource: { id: first.resource.id } });
    await expect(gateways.createFakeGateway("node-a", "different", "infra")).rejects.toMatchObject({ code: "CONFLICT" });
  });
  it("does not present stale ready evidence as a passing doctor check", async () => {
    let now = new Date("2026-01-01T00:00:00.000Z");
    const provider = new FakeComputeProvider({ nodes: [{ id: "node-a", online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] }], storage: [], resources: [] }, () => now);
    const store = new MemoryStore();
    await new GatewayService(store, provider, () => now).createFakeGateway("node-a", "gateway-stale", "infra");
    await new GatewayMonitor(store, provider, () => now).scan();
    now = new Date("2026-01-01T00:00:31.000Z");
    const doctor = await new DoctorService(store, provider, () => now).inspect("node-a") as { nodes: Array<{ status: string; checks: Array<{ code: string }> }> };
    expect(doctor.nodes[0]).toMatchObject({ status: "NOT_READY", checks: [{ code: "STALE_OBSERVATION" }] });
  });
  it("quarantines tag or gateway metadata drift and keeps quarantine sticky", async () => {
    const provider = new FakeComputeProvider({ nodes: [{ id: "node-a", online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] }], storage: [], resources: [] });
    const store = new MemoryStore();
    const created = await new GatewayService(store, provider).createFakeGateway("node-a", "gateway-drift", "infra");
    const monitor = new GatewayMonitor(store, provider);
    provider.fixtures.get(created.resource.id)!.tags = ["kiln"];
    await monitor.scan();
    expect((await store.listGateways())[0]?.health).toMatchObject({ status: "QUARANTINED" });
    expect(await new DoctorService(store, provider).inspect()).toMatchObject({
      overall: "DEGRADED", nodes: [{ status: "QUARANTINED" }],
    });
    provider.fixtures.get(created.resource.id)!.tags = ["kiln", "kiln-managed", `kiln-installation-${created.resource.installationId}`, "kiln-resource-gateway", `kiln-resource-id-${created.resource.id}`];
    await monitor.scan();
    expect((await store.listGateways())[0]?.health).toMatchObject({ status: "QUARANTINED" });
    const provider2 = new FakeComputeProvider({ nodes: [{ id: "node-b", online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] }], storage: [], resources: [] });
    const clean = new MemoryStore();
    const second = await new GatewayService(clean, provider2).createFakeGateway("node-b", "gateway-drift-2", "infra");
    const metadata = await clean.getGateway(second.resource.id);
    metadata!.generation = "wrong-generation";
    await new GatewayMonitor(clean, provider2).scan();
    expect((await clean.listGateways())[0]?.health).toMatchObject({ status: "QUARANTINED" });
    const provider3 = new FakeComputeProvider({ nodes: [{ id: "node-c", online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] }], storage: [], resources: [] });
    const fingerprintStore = new MemoryStore();
    const third = await new GatewayService(fingerprintStore, provider3).createFakeGateway("node-c", "gateway-drift-3", "infra");
    (await fingerprintStore.getGateway(third.resource.id))!.expectedFingerprint = "wrong-fingerprint";
    await new GatewayMonitor(fingerprintStore, provider3).scan();
    expect((await fingerprintStore.listGateways())[0]?.health).toMatchObject({ status: "QUARANTINED" });
  });
  it("serializes concurrent scans into one open incident episode", async () => {
    const provider = new FakeComputeProvider({ nodes: [{ id: "node-a", online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] }], storage: [], resources: [] });
    const store = new MemoryStore();
    const created = await new GatewayService(store, provider).createFakeGateway("node-a", "gateway-concurrent", "infra");
    provider.gatewayEvidence.set(created.resource.id, { policy: "FAIL" });
    const monitor = new GatewayMonitor(store, provider);
    await Promise.all([monitor.scan(), monitor.scan(), monitor.scan()]);
    expect((await store.listGatewayIncidents("node-a")).filter((incident) => incident.status === "OPEN")).toHaveLength(1);
  });
  it("rejects an admission when a monitor quarantines its selected gateway before provider creation", async () => {
    class AdmissionStore extends MemoryStore {
      armed = false;
      private first = true;
      private releaseGate!: () => void;
      private readonly gate = new Promise<void>((resolve) => { this.releaseGate = resolve; });
      private seenGate!: () => void;
      readonly seen = new Promise<void>((resolve) => { this.seenGate = resolve; });
      override async withResourceLock<T>(id: string, task: () => Promise<T>): Promise<T> {
        if (this.armed && this.first && id.startsWith("gateway-admission:")) {
          this.first = false;
          this.seenGate();
          await this.gate;
        }
        return super.withResourceLock(id, task);
      }
      release(): void { this.releaseGate(); }
    }
    const provider = new FakeComputeProvider({ nodes: [{ id: "node-a", online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] }], storage: [], resources: [] });
    const store = new AdmissionStore();
    const gateway = await new GatewayService(store, provider).createFakeGateway("node-a", "gateway-race", "infra");
    await new GatewayMonitor(store, provider).scan();
    store.armed = true;
    provider.gatewayEvidence.set(gateway.resource.id, { services: "FAIL" });
    const resources = new ResourceService(store, provider);
    const creating = resources.create({ type: "execution", projectId: "default", ttlSeconds: 60 }, "race", "agent");
    await store.seen;
    await new GatewayMonitor(store, provider).scan();
    store.release();
    await expect(creating).rejects.toMatchObject({ code: "NETWORK_NOT_READY" });
    expect(provider.mutations.filter((mutation) => mutation.operation === "create")).toHaveLength(1);
  });
  it("rejects future gateway health and replays an existing idempotent workload during a hold", async () => {
    let now = new Date("2026-01-01T00:00:00.000Z");
    const provider = new FakeComputeProvider({ nodes: [{ id: "node-a", online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] }], storage: [], resources: [] }, () => now);
    const store = new MemoryStore();
    const gateway = await new GatewayService(store, provider, () => now).createFakeGateway("node-a", "gateway-future", "infra");
    await new GatewayMonitor(store, provider, () => now).scan();
    const resources = new ResourceService(store, provider, () => now);
    const first = await resources.create({ type: "execution", projectId: "default", ttlSeconds: 60 }, "replay", "agent");
    (await store.listGateways())[0]!.health!.observedAt = "2030-01-01T00:00:00.000Z";
    await expect(resources.create({ type: "browser", projectId: "default", ttlSeconds: 60 }, "future", "agent")).rejects.toMatchObject({ code: "NETWORK_NOT_READY" });
    const replay = await resources.create({ type: "execution", projectId: "default", ttlSeconds: 60 }, "replay", "agent");
    expect(replay).toMatchObject({ replayed: true, resource: { id: first.resource.id } });
  });
  it("keeps service incidents open when provider evidence becomes unknown until health fully recovers", async () => {
    const provider = new FakeComputeProvider({ nodes: [{ id: "node-a", online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] }], storage: [], resources: [] });
    const store = new MemoryStore();
    const gateway = await new GatewayService(store, provider).createFakeGateway("node-a", "gateway-evidence", "infra");
    const monitor = new GatewayMonitor(store, provider);
    provider.gatewayEvidence.set(gateway.resource.id, { services: "FAIL" });
    await monitor.scan();
    const observation = provider.fixtures.get(gateway.resource.id)!;
    provider.fixtures.delete(gateway.resource.id);
    await monitor.scan();
    expect((await store.listGatewayIncidents("node-a")).filter((incident) => incident.status === "OPEN").map((incident) => incident.code)).toEqual(expect.arrayContaining(["GATEWAY_SERVICE", "PROVIDER_UNKNOWN"]));
    provider.fixtures.set(gateway.resource.id, observation);
    provider.gatewayEvidence.set(gateway.resource.id, { services: "PASS" });
    await monitor.scan();
    expect((await store.listGatewayIncidents("node-a")).filter((incident) => incident.status === "OPEN")).toEqual([]);
    expect((await store.events("infrastructure", 0)).filter((event) => event.type === "gateway.incident_resolved")).toHaveLength(2);
  });
  it("reports missing node visibility as unknown evidence, not proof that a gateway stopped", async () => {
    const provider = new FakeComputeProvider({ nodes: [{ id: "node-a", online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] }], storage: [], resources: [] });
    const store = new MemoryStore();
    const gateway = await new GatewayService(store, provider).createFakeGateway("node-a", "gateway-missing-node", "infra");
    (provider as unknown as { inventory: ProviderInventory }).inventory = { nodes: [], storage: [], resources: [] };
    await new GatewayMonitor(store, provider).scan();
    expect((await store.listGateways())[0]?.health).toMatchObject({ status: "NOT_READY", evidence: { power: "UNKNOWN", ownership: "UNKNOWN" } });
    expect((await store.listGatewayIncidents("node-a"))[0]).toMatchObject({ code: "PROVIDER_UNKNOWN" });
    expect(gateway.resource.type).toBe("gateway");
  });
  it("fails closed when a ready health snapshot no longer matches gateway metadata or resource state", async () => {
    const provider = new FakeComputeProvider({ nodes: [{ id: "node-a", online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] }], storage: [], resources: [] });
    const store = new MemoryStore();
    const gateway = await new GatewayService(store, provider).createFakeGateway("node-a", "gateway-attestation", "infra");
    await new GatewayMonitor(store, provider).scan();
    (await store.getGateway(gateway.resource.id))!.generation = "replacement";
    const resources = new ResourceService(store, provider);
    await expect(resources.create({ type: "execution", projectId: "default", ttlSeconds: 60 }, "generation", "agent")).rejects.toMatchObject({ code: "NETWORK_NOT_READY" });
    const resource = (await store.getResource(gateway.resource.id))!;
    resource.state = "ERROR";
    await store.updateResource(resource);
    const doctor = await new DoctorService(store, provider).inspect("node-a") as { nodes: Array<{ status: string; checks: Array<{ code: string }> }> };
    expect(doctor.nodes[0]).toMatchObject({ status: "NOT_READY", checks: [{ code: "GATEWAY_NOT_READY" }] });
  });
  it("keeps memory health and incidents unchanged when an event write fails", async () => {
    class FailingEventStore extends MemoryStore {
      failEvents = false;
      override async appendEvent(event: Parameters<MemoryStore["appendEvent"]>[0]) {
        const saved = await super.appendEvent(event);
        if (this.failEvents) throw new Error("event write failed");
        return saved;
      }
    }
    const provider = new FakeComputeProvider({ nodes: [{ id: "node-a", online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] }], storage: [], resources: [] });
    const store = new FailingEventStore();
    const gateway = await new GatewayService(store, provider).createFakeGateway("node-a", "gateway-atomic-memory", "infra");
    const monitor = new GatewayMonitor(store, provider);
    await monitor.scan();
    const ready = (await store.listGateways())[0]!.health!;
    provider.gatewayEvidence.set(gateway.resource.id, { services: "FAIL" });
    store.failEvents = true;
    await expect(monitor.scan()).rejects.toThrow("event write failed");
    expect((await store.listGateways())[0]!.health).toEqual(ready);
    expect(await store.listGatewayIncidents("node-a")).toEqual([]);
    store.failEvents = false;
    await monitor.scan();
    const failed = (await store.listGateways())[0]!.health!;
    provider.gatewayEvidence.set(gateway.resource.id, { services: "PASS" });
    store.failEvents = true;
    await expect(monitor.scan()).rejects.toThrow("event write failed");
    expect((await store.listGateways())[0]!.health).toEqual(failed);
    expect((await store.listGatewayIncidents("node-a")).filter((incident) => incident.status === "OPEN")).toHaveLength(1);
  });
  it("serializes provider discovery across concurrent monitor scans", async () => {
    class CountingProvider extends FakeComputeProvider {
      active = 0;
      maxActive = 0;
      override async discover() {
        this.active += 1;
        this.maxActive = Math.max(this.maxActive, this.active);
        await new Promise<void>((resolve) => setTimeout(resolve, 5));
        try { return await super.discover(); } finally { this.active -= 1; }
      }
    }
    const provider = new CountingProvider({ nodes: [{ id: "node-a", online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] }], storage: [], resources: [] });
    const store = new MemoryStore();
    await new GatewayService(store, provider).createFakeGateway("node-a", "gateway-scan-serialize", "infra");
    const monitor = new GatewayMonitor(store, provider);
    provider.active = 0;
    provider.maxActive = 0;
    await Promise.all([monitor.scan(), monitor.scan(), monitor.scan()]);
    expect(provider.maxActive).toBe(1);
  });
  it("never selects a corrupted gateway for the store expiry query", async () => {
    const provider = new FakeComputeProvider({ nodes: [{ id: "node-a", online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] }], storage: [], resources: [] });
    const store = new MemoryStore();
    const gateway = await new GatewayService(store, provider).createFakeGateway("node-a", "gateway-expiry-filter", "infra");
    const corrupt = (await store.getResource(gateway.resource.id))!;
    corrupt.expiresAt = "2020-01-01T00:00:00.000Z";
    await store.updateResource(corrupt);
    expect((await store.expired("2026-01-01T00:00:00.000Z")).map((resource) => resource.id)).not.toContain(gateway.resource.id);
  });
  it("treats partial attestation and unknown power as provider uncertainty", async () => {
    const provider = new FakeComputeProvider({ nodes: [{ id: "node-a", online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] }], storage: [], resources: [] });
    const store = new MemoryStore();
    const gateway = await new GatewayService(store, provider).createFakeGateway("node-a", "gateway-partial", "infra");
    const monitor = new GatewayMonitor(store, provider);
    provider.gatewayEvidence.set(gateway.resource.id, { generation: null });
    await monitor.scan();
    expect((await store.listGatewayIncidents("node-a"))[0]).toMatchObject({ code: "PROVIDER_UNKNOWN" });
    provider.gatewayEvidence.set(gateway.resource.id, { power: "UNKNOWN" });
    await monitor.scan();
    expect((await store.listGatewayIncidents("node-a")).filter((incident) => incident.status === "OPEN")).toEqual(expect.arrayContaining([expect.objectContaining({ code: "PROVIDER_UNKNOWN" })]));
  });
  it("retains incidents until both gateway lifecycle and provider evidence recover", async () => {
    const provider = new FakeComputeProvider();
    const store = new MemoryStore();
    const { resource } = await new GatewayService(store, provider).createFakeGateway("fake-node", "lifecycle-recovery", "infra");
    const monitor = new GatewayMonitor(store, provider);
    provider.gatewayEvidence.set(resource.id, { services: "FAIL" });
    await monitor.scan();
    resource.state = "ERROR";
    await store.updateResource(resource);
    provider.gatewayEvidence.set(resource.id, { services: "PASS" });
    await monitor.scan();
    expect((await store.listGateways())[0]?.health?.status).toBe("NOT_READY");
    expect(await store.listGatewayIncidents()).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "GATEWAY_SERVICE", status: "OPEN" }),
    ]));
    resource.state = "READY";
    await store.updateResource(resource);
    await monitor.scan();
    expect((await store.listGateways())[0]?.health?.status).toBe("READY");
    expect((await store.listGatewayIncidents()).every(incident => incident.status === "RESOLVED")).toBe(true);
  });
  it("selects another ready node when an earlier gateway has a stale attestation", async () => {
    const provider = new FakeComputeProvider({ nodes: [
      { id: "node-a", online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] },
      { id: "node-b", online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] },
    ], storage: [], resources: [] });
    const store = new MemoryStore();
    const gateways = new GatewayService(store, provider);
    const first = await gateways.createFakeGateway("node-a", "gateway-select-a", "infra");
    await gateways.createFakeGateway("node-b", "gateway-select-b", "infra");
    await new GatewayMonitor(store, provider).scan();
    (await store.getGateway(first.resource.id))!.generation = "old-generation";
    const created = await new ResourceService(store, provider).create({ type: "execution", projectId: "default", ttlSeconds: 60 }, "select-b", "agent");
    expect(created.resource.node).toBe("node-b");
  });
});
