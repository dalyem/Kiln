import { describe, expect, it } from "vitest";
import { createApp } from "../apps/api/src/app.js";
import { FakeComputeProvider } from "@kiln/providers";

const provider = () => new FakeComputeProvider({
  nodes: [{ id: "node-a", online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] }],
  storage: [], resources: [],
});

describe("gateway HTTP contract", () => {
  it("requires a separate infrastructure credential to create or scan fake gateways", async () => {
    const { app } = createApp({ token: "normal", infrastructureToken: "infra", provider: provider() });
    const denied = await app.inject({ method: "POST", url: "/v1/gateways", headers: { authorization: "Bearer normal", "idempotency-key": "gw" }, payload: { node: "node-a" } });
    expect(denied.statusCode).toBe(403);
    const created = await app.inject({ method: "POST", url: "/v1/gateways", headers: { authorization: "Bearer infra", "idempotency-key": "gw" }, payload: { node: "node-a" } });
    expect(created.statusCode).toBe(201);
    const scan = await app.inject({ method: "POST", url: "/v1/monitor/scan", headers: { authorization: "Bearer infra" } });
    expect(scan.statusCode).toBe(200);
    const doctor = await app.inject({ method: "GET", url: "/v1/doctor?network=true", headers: { authorization: "Bearer normal" } });
    expect(doctor.statusCode).toBe(200);
    expect(doctor.json()).toMatchObject({ schemaVersion: 1, repairEnabled: false, nodes: [{ node: "node-a", status: "READY" }] });
  });
  it("keeps repair disabled before a provider action", async () => {
    const fake = provider();
    const { app } = createApp({ token: "normal", infrastructureToken: "infra", provider: fake });
    const response = await app.inject({ method: "POST", url: "/v1/doctor/repair", headers: { authorization: "Bearer infra" } });
    expect(response.statusCode).toBe(501);
    expect(fake.mutations).toEqual([]);
  });
  it("reports readiness without exposing database details", async () => {
    const { app } = createApp({ token: "normal", provider: provider() });
    const response = await app.inject({ method: "GET", url: "/readyz" });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ ok: true });
  });
});
