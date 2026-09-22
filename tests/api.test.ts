import { describe, expect, it } from "vitest";
import { createApp } from "../apps/api/src/app.js";
import { FakeComputeProvider } from "@kiln/providers";
import type { LinuxImageImportService, LinuxImageStaging } from "@kiln/core";
describe("HTTP contract", () => {
  it("does not serve v1 without a bearer credential", async () => {
    const { app } = createApp({ token: "secret" });
    const response = await app.inject({ method: "GET", url: "/v1/status" });
    expect(response.statusCode).toBe(401);
  });
  it("creates an owned fake resource and replays an idempotent request", async () => {
    const { app } = createApp({ token: "secret" });
    const options = {
      method: "POST" as const,
      url: "/v1/resources",
      headers: {
        authorization: "Bearer secret",
        "idempotency-key": "create-1",
      },
      payload: { type: "development", ttlSeconds: 60 },
    };
    const first = await app.inject(options);
    const replay = await app.inject(options);
    expect(first.statusCode).toBe(201);
    expect(replay.statusCode).toBe(200);
    expect(replay.json().id).toBe(first.json().id);
  });
  it("redacts unexpected provider errors", async () => {
    const { app } = createApp({ token: "secret" });
    const response = await app.inject({
      method: "POST",
      url: "/v1/resources",
      headers: { authorization: "Bearer secret", "idempotency-key": "x" },
      payload: { type: "development", ttlSeconds: "invalid" },
    });
    expect(response.statusCode).toBe(400);
    expect(response.body).not.toContain("stack");
  });
  it("classifies a record with changed live ownership tags as external", async () => {
    const provider = new FakeComputeProvider();
    const { app } = createApp({ token: "secret", provider });
    const created = await app.inject({
      method: "POST",
      url: "/v1/resources",
      headers: {
        authorization: "Bearer secret",
        "idempotency-key": "inventory",
      },
      payload: { type: "development", ttlSeconds: 60 },
    });
    const resource = created.json() as { id: string };
    provider.fixtures.get(resource.id)!.tags = ["kiln"];
    const inventory = await app.inject({
      method: "GET",
      url: "/v1/inventory",
      headers: { authorization: "Bearer secret" },
    });
    expect(inventory.statusCode).toBe(200);
    expect(inventory.json().resources[0]).toMatchObject({
      ownership: "EXTERNAL",
      diagnostic: "OWNERSHIP_MISMATCH",
    });
  });
  it("classifies a valid imported record and an unknown tagged record", async () => {
    const provider = new FakeComputeProvider();
    const { app, store } = createApp({ token: "secret", provider });
    const created = await app.inject({
      method: "POST",
      url: "/v1/resources",
      headers: {
        authorization: "Bearer secret",
        "idempotency-key": "imported",
      },
      payload: { type: "development", ttlSeconds: 60 },
    });
    const record = created.json() as { id: string };
    const imported = (await store.getResource(record.id))!;
    imported.ownership = "IMPORTED";
    await store.updateResource(imported);
    provider.fixtures.set("unknown-tagged", {
      providerId: "fake",
      providerResourceId: "unknown-tagged",
      providerKind: "fake",
      kind: "development",
      pool: "kiln",
      node: null,
      tags: ["kiln", "kiln-managed", "kiln-installation-other"],
    });
    const inventory = await app.inject({
      method: "GET",
      url: "/v1/inventory",
      headers: { authorization: "Bearer secret" },
    });
    expect(inventory.json().resources).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          providerResourceId: record.id,
          ownership: "IMPORTED",
        }),
        expect.objectContaining({
          providerResourceId: "unknown-tagged",
          ownership: "EXTERNAL",
          diagnostic: "ORPHANED",
        }),
      ]),
    );
  });
  it("returns a fixed 400 error for malformed JSON", async () => {
    const { app } = createApp({ token: "secret" });
    const response = await app.inject({
      method: "POST",
      url: "/v1/resources",
      headers: {
        authorization: "Bearer secret",
        "idempotency-key": "bad-json",
        "content-type": "application/json",
      },
      payload: "{",
    });
    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({
      error: { code: "INVALID_INPUT", message: "Request validation failed" },
    });
  });
  it("does not expose a Linux staging path while the guarded import is disabled", async () => {
    const { app } = createApp({ token: "secret", infrastructureToken: "infra" });
    const response = await app.inject({ method: "GET", url: "/v1/linux-imports/limp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", headers: { authorization: "Bearer infra", "x-kiln-linux-import-token": "separate" } });
    expect(response.statusCode).toBe(403);
    expect(response.body).not.toContain("stagePath");
  });
  it("returns only safe Linux import phase status to the separate operator credential", async () => {
    const run = { id: "limp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", status: "UNKNOWN", createdAt: "2026-01-01T00:00:00.000Z", completedAt: null, plan: { canonicalDigest: "a".repeat(64), stageId: "lstg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", stagePath: "/private/never-returned", templateResourceId: "img_template_a", cloneResourceId: "img_clone_a" } };
    const linuxImportService = { statusDetail: async () => ({ run, phases: [{ name: "IMPORT", status: "UNKNOWN", safeReason: "RECONCILIATION_DEADLINE_EXCEEDED", createdAt: run.createdAt, reconciliationDeadline: "2026-01-01T00:15:00.000Z", submittedAt: run.createdAt, completedAt: null }] }) } as unknown as LinuxImageImportService;
    const { app } = createApp({ token: "secret", infrastructureToken: "infra", linuxImportToken: "operator", linuxImportService, linuxImageStaging: {} as LinuxImageStaging });
    const denied = await app.inject({ method: "GET", url: `/v1/linux-imports/${run.id}`, headers: { authorization: "Bearer secret", "x-kiln-linux-import-token": "operator" } });
    expect(denied.statusCode).toBe(403);
    const response = await app.inject({ method: "GET", url: `/v1/linux-imports/${run.id}`, headers: { authorization: "Bearer infra", "x-kiln-linux-import-token": "operator" } });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ id: run.id, phases: [{ name: "IMPORT", status: "UNKNOWN", safeReason: "RECONCILIATION_DEADLINE_EXCEEDED" }] });
    expect(response.body).not.toContain("/private/never-returned");
  });
});
