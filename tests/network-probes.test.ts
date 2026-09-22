import { describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import { Pool } from "pg";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { DoctorService, GatewayMonitor, GatewayService, KilnError, NetworkProbeService, ResourceService, validateNetworkProbeProfiles, validateNetworkProbeRuntime } from "@kiln/core";
import { MemoryStore } from "@kiln/database";
import { DrizzleStore, gatewayHealthAttestationMigration, gatewayIdentityMigration, gatewayMonitoringMigration, imageProvenanceMigration, initialMigration, networkProbeMigration, providerOperationMigration } from "@kiln/database";
import { FakeComputeProvider } from "@kiln/providers";

const profiles = validateNetworkProbeProfiles([{ id: "controlled", ttlSeconds: 60, checks: [{ id: "dns", kind: "dns", hostname: "example.test", resolverAddress: "192.0.2.53", resolverPort: 53, timeoutMs: 500 }, { id: "blocked", kind: "tcp", address: "192.0.2.2", port: 443, expect: "blocked", timeoutMs: 500 }] }]);

async function fixture() {
  const store = new MemoryStore(); const provider = new FakeComputeProvider(); const resources = new ResourceService(store, provider);
  const gateway = await new GatewayService(store, provider).createFakeGateway("fake-node", "gateway", "test");
  await new GatewayMonitor(store, provider).scan();
  return { store, provider, resources, gateway, probes: new NetworkProbeService(store, provider, profiles, resources) };
}
async function job() {
  const value = await fixture();
  const created = await value.probes.create(value.gateway.resource.id, "controlled", "probe", "test");
  const issued = await value.probes.issueToken(created.resource.id);
  return { ...value, ...created, token: issued.token };
}
const results = [{ id: "dns", code: "DNS_ANSWER" as const, durationMs: 4 }, { id: "blocked", code: "TCP_FAILED" as const, durationMs: 3 }] as const;

describe("network probes", () => {
  it("only accepts the rotated token and does not expose token state", async () => {
    const value = await job();
    const rotated = await value.probes.issueToken(value.resource.id);
    await expect(value.probes.plan(value.resource.id, value.token)).rejects.toMatchObject({ code: "UNAUTHENTICATED" });
    expect((await value.probes.plan(value.resource.id, rotated.token)).plan.probeId).toBe(value.resource.id);
    expect((await value.store.getNetworkProbe(value.resource.id))?.tokenHash).not.toBe(rotated.token);
  });
  it("accepts one report and gives only an exact report replay", async () => {
    const value = await job();
    const plan = await value.probes.plan(value.resource.id, value.token);
    const first = await value.probes.result(value.resource.id, value.token, plan.planDigest, [...results]);
    const replay = await value.probes.result(value.resource.id, value.token, plan.planDigest, [...results]);
    expect(replay).toEqual(first);
    await expect(value.probes.result(value.resource.id, value.token, plan.planDigest, [{ ...results[0] }, { ...results[1], code: "TCP_CONNECTED" }])).rejects.toMatchObject({ code: "CONFLICT" });
  });
  it("serializes concurrent conflicting results", async () => {
    const value = await job(); const plan = await value.probes.plan(value.resource.id, value.token);
    const settled = await Promise.allSettled([value.probes.result(value.resource.id, value.token, plan.planDigest, [...results]), value.probes.result(value.resource.id, value.token, plan.planDigest, [{ ...results[0], code: "DNS_EMPTY" }, results[1]!])]);
    expect(settled.filter((item) => item.status === "fulfilled")).toHaveLength(1);
    expect(settled.filter((item) => item.status === "rejected")).toHaveLength(1);
  });
  it("denies a report after the bound gateway generation changes", async () => {
    const value = await job(); const plan = await value.probes.plan(value.resource.id, value.token);
    const metadata = await value.store.getGateway(value.gateway.resource.id);
    (value.store as unknown as { gatewayLog: Map<string, { generation: string }> }).gatewayLog.set(value.gateway.resource.id, { ...metadata!, generation: "changed" });
    await expect(value.probes.result(value.resource.id, value.token, plan.planDigest, [...results])).rejects.toMatchObject({ code: "SAFETY_DENIED" });
  });
  it("times out and destroys only its owned probe fixture", async () => {
    let now = new Date("2026-01-01T00:00:00.000Z");
    const store = new MemoryStore(); const provider = new FakeComputeProvider(); const resources = new ResourceService(store, provider, () => now);
    const gateway = await new GatewayService(store, provider, () => now).createFakeGateway("fake-node", "gateway", "test"); await new GatewayMonitor(store, provider, () => now).scan();
    const probes = new NetworkProbeService(store, provider, profiles, resources, () => now);
    const created = await probes.create(gateway.resource.id, "controlled", "probe", "test");
    now = new Date("2026-01-01T00:01:01.000Z"); await probes.expire();
    expect((await store.getNetworkProbe(created.resource.id))?.state).toBe("TIMED_OUT");
    expect((await store.getResource(created.resource.id))?.state).toBe("DESTROYED");
  });
  it("cleans a completed probe through the ownership guard while retaining its narrow acknowledgement replay", async () => {
    const value = await job(); const plan = await value.probes.plan(value.resource.id, value.token);
    const accepted = await value.probes.result(value.resource.id, value.token, plan.planDigest, [...results]);
    await value.probes.expire();
    expect((await value.store.getResource(value.resource.id))?.state).toBe("DESTROYED");
    expect(value.provider.fixtures.has(value.resource.id)).toBe(false);
    await expect(value.probes.result(value.resource.id, value.token, plan.planDigest, [...results])).resolves.toEqual(accepted);
  });
  it("quarantines a completed probe with changed tags instead of deleting it", async () => {
    const value = await job(); const plan = await value.probes.plan(value.resource.id, value.token);
    await value.probes.result(value.resource.id, value.token, plan.planDigest, [...results]);
    value.provider.fixtures.get(value.resource.id)!.tags = ["kiln"];
    await value.probes.expire();
    expect((await value.store.getResource(value.resource.id))?.state).toBe("QUARANTINED");
    expect(value.provider.fixtures.has(value.resource.id)).toBe(true);
    const events = await value.store.events("infrastructure", 0);
    await value.probes.expire();
    expect(await value.store.events("infrastructure", 0)).toHaveLength(events.length);
  });
  it("keeps completed cleanup blocked after a transient provider failure", async () => {
    class FlakyProvider extends FakeComputeProvider {
      failDestroy = true;
      override async destroy(resource: Parameters<FakeComputeProvider["destroy"]>[0]) {
        if (this.failDestroy) { this.failDestroy = false; throw new Error("temporary destroy failure"); }
        return super.destroy(resource);
      }
    }
    const store = new MemoryStore(); const provider = new FlakyProvider(); const resources = new ResourceService(store, provider);
    const gateway = await new GatewayService(store, provider).createFakeGateway("fake-node", "flaky-gateway", "test");
    const probes = new NetworkProbeService(store, provider, profiles, resources);
    const created = await probes.create(gateway.resource.id, "controlled", "flaky-probe", "test"); const issued = await probes.issueToken(created.resource.id); const plan = await probes.plan(created.resource.id, issued.token);
    await probes.result(created.resource.id, issued.token, plan.planDigest, [...results]);
    await probes.expire();
    expect((await store.getResource(created.resource.id))?.state).toBe("ERROR");
    await probes.expire();
    expect((await store.getResource(created.resource.id))?.state).toBe("ERROR");
  });
  it("rejects generic network probe creation", async () => {
    const { resources } = await fixture();
    await expect(resources.create({ type: "network_probe", projectId: "default", ttlSeconds: 60 }, "x", "test")).rejects.toMatchObject({ code: "SAFETY_DENIED" });
  });
  it("rejects malformed profiles before they can create jobs and requires TLS for configured profiles", () => {
    for (const hostname of ["-bad.test", "bad-.test", "two..labels", `${"a".repeat(64)}.test`, "example.test."])
      expect(() => validateNetworkProbeProfiles([{ id: "bad", ttlSeconds: 60, checks: [{ id: "dns", kind: "dns", hostname, resolverAddress: "192.0.2.53", resolverPort: 53, timeoutMs: 100 }] }])).toThrow();
    expect(() => validateNetworkProbeProfiles([{ id: "bundle", ttlSeconds: 60, checks: [{ id: "https", kind: "https", url: "https://example.test", expectedStatus: 200, caPem: "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----", timeoutMs: 100 }] }])).toThrow();
    expect(() => validateNetworkProbeRuntime(profiles, false)).toThrow("requires complete gateway TLS");
    expect(() => validateNetworkProbeRuntime([], false)).not.toThrow();
  });
  it("refuses server startup when profiles are configured without gateway TLS", async () => {
    const directory = await mkdtemp(join(tmpdir(), "kiln-probe-profile-"));
    const file = join(directory, "profiles.json");
    try {
      await writeFile(file, JSON.stringify(profiles), { mode: 0o600 });
      const child = spawnSync(process.execPath, ["--import", "tsx", "apps/api/src/server.ts"], { cwd: process.cwd(), env: { ...process.env, KILN_STORE: "memory", KILN_API_TOKEN: "test-token", KILN_PROBE_PROFILES_FILE: file, KILN_PORT: "0" }, encoding: "utf8", timeout: 5000 });
      expect(child.status).not.toBe(0);
      expect(`${child.stderr}${child.stdout}`).toContain("requires complete gateway TLS configuration");
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
  it("rejects a provider response that does not match the reserved probe identity", async () => {
    class MismatchedProvider extends FakeComputeProvider {
      override async create(resource: Parameters<FakeComputeProvider["create"]>[0]) { const observed = await super.create(resource); return resource.type === "network_probe" ? { ...observed, node: "other-node" } : observed; }
    }
    const store = new MemoryStore(); const provider = new MismatchedProvider(); const resources = new ResourceService(store, provider);
    const gateway = await new GatewayService(store, provider).createFakeGateway("fake-node", "mismatch-gateway", "test");
    const probes = new NetworkProbeService(store, provider, profiles, resources);
    await expect(probes.create(gateway.resource.id, "controlled", "mismatch-probe", "test")).rejects.toMatchObject({ code: "SAFETY_DENIED" });
    expect((await store.listResources("infrastructure")).find((resource) => resource.type === "network_probe")?.state).toBe("ERROR");
  });
  it("cancels a pending probe atomically with a guarded stop", async () => {
    const value = await job();
    await value.resources.mutate(value.resource.id, "stop", "infrastructure");
    expect((await value.store.getNetworkProbe(value.resource.id))?.state).toBe("CANCELLED");
    await expect(value.probes.plan(value.resource.id, value.token)).rejects.toMatchObject({ code: "NOT_FOUND" });
  });
  it("marks old diagnostic evidence stale unless the configured profile still matches", async () => {
    const value = await job(); const plan = await value.probes.plan(value.resource.id, value.token);
    await value.probes.result(value.resource.id, value.token, plan.planDigest, [...results]);
    const readyDoctor = await new DoctorService(value.store, value.provider, undefined, profiles).inspect("fake-node") as { nodes: Array<{ checks: Array<{ code: string }> }> };
    expect(readyDoctor.nodes[0]!.checks).toContainEqual(expect.objectContaining({ code: "PROBE_DIAGNOSTIC_UNVERIFIED" }));
    const staleDoctor = await new DoctorService(value.store, value.provider).inspect("fake-node") as { nodes: Array<{ checks: Array<{ code: string }> }> };
    expect(staleDoctor.nodes[0]!.checks).toContainEqual(expect.objectContaining({ code: "PROBE_STALE" }));
  });
  it("does not persist probe authority or evidence when the audit write fails", async () => {
    class FailingAuditStore extends MemoryStore {
      fail = false;
      override async appendEvent(event: Parameters<MemoryStore["appendEvent"]>[0]) {
        if (this.fail) throw new Error("audit unavailable");
        return super.appendEvent(event);
      }
    }
    const store = new FailingAuditStore(); const provider = new FakeComputeProvider(); const resources = new ResourceService(store, provider);
    const gateway = await new GatewayService(store, provider).createFakeGateway("fake-node", "gateway", "test");
    const probes = new NetworkProbeService(store, provider, profiles, resources);
    store.fail = true;
    await expect(probes.create(gateway.resource.id, "controlled", "audit-create", "test")).rejects.toThrow("audit unavailable");
    expect((await store.listResources("infrastructure")).map((resource) => resource.type)).toEqual(["gateway"]);
    store.fail = false;
    const created = await probes.create(gateway.resource.id, "controlled", "audit-result", "test"); const issued = await probes.issueToken(created.resource.id); const plan = await probes.plan(created.resource.id, issued.token);
    store.fail = true;
    await expect(probes.result(created.resource.id, issued.token, plan.planDigest, [...results])).rejects.toThrow("audit unavailable");
    expect((await store.getNetworkProbe(created.resource.id))?.resultDigest).toBeNull();
  });
});

const databaseUrl = process.env.KILN_TEST_DATABASE_URL;
describe.skipIf(!databaseUrl)("network probe PostgreSQL persistence", () => {
  it("keeps a durable probe job across repeated pre-release migrations", async () => {
    const database = `kiln_probe_persistence_${randomUUID().replaceAll("-", "")}`;
    const admin = new Pool({ connectionString: databaseUrl! });
    const isolated = new URL(databaseUrl!);
    isolated.pathname = `/${database}`;
    let store: DrizzleStore | undefined;
    let reopened: DrizzleStore | undefined;
    let createdDatabase = false;
    try {
      await admin.query(`CREATE DATABASE ${database}`);
      createdDatabase = true;
      store = new DrizzleStore(isolated.toString());
      for (const migration of [initialMigration, gatewayMonitoringMigration, gatewayHealthAttestationMigration, gatewayIdentityMigration, networkProbeMigration, providerOperationMigration, imageProvenanceMigration]) await store.migrate(await migration());
      const node = `pg-node-${randomUUID()}`;
      const provider = new FakeComputeProvider({ nodes: [{ id: node, online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] }], storage: [], resources: [] }); const resources = new ResourceService(store, provider);
      const gateway = await new GatewayService(store, provider).createFakeGateway(node, `pg-${randomUUID()}`, "test");
      const probes = new NetworkProbeService(store, provider, profiles, resources);
      const created = await probes.create(gateway.resource.id, "controlled", `pg-${randomUUID()}`, "test");
      await store.close();
      store = undefined;
      reopened = new DrizzleStore(isolated.toString());
      for (const migration of [initialMigration, gatewayMonitoringMigration, gatewayHealthAttestationMigration, gatewayIdentityMigration, networkProbeMigration, providerOperationMigration, imageProvenanceMigration]) await reopened.migrate(await migration());
      expect((await reopened.getNetworkProbe(created.resource.id))?.plan.probeId).toBe(created.resource.id);
    } finally {
      await store?.close();
      await reopened?.close();
      try {
        // Let closed pool connections finish their protocol shutdown. FORCE can
        // kill a backend before pg receives its close acknowledgement.
        if (createdDatabase) await admin.query(`DROP DATABASE ${database}`);
      } finally {
        await admin.end();
      }
    }
  });
});
