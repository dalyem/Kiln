import { describe, expect, it } from "vitest";
import { GatewayService, ResourceService } from "@kiln/core";
import { MemoryStore } from "@kiln/database";
import { FakeAsyncComputeProvider, FakeComputeProvider } from "@kiln/providers";
import { createApp } from "../apps/api/src/app.js";

describe("provider operation journal", () => {
  it("keeps an async create unresolved until the recorded fake task and ownership check complete", async () => {
    const store = new MemoryStore();
    const provider = new FakeAsyncComputeProvider();
    const service = new ResourceService(store, provider);
    const created = await service.create({ type: "development", projectId: "default", ttlSeconds: 60 }, "async-create", "test");

    const operation = (await store.listOperations(created.resource.id))[0]!;
    expect(created.resource.state).toBe("PROVISIONING");
    expect(operation).toMatchObject({ status: "SUBMITTED", snapshot: { schemaVersion: 1, resourceId: created.resource.id, action: "create" } });
    await expect(service.extend(created.resource.id, "default", 60)).rejects.toMatchObject({ code: "OPERATION_UNRESOLVED" });

    await provider.completeTask(operation.taskHandle!.taskId);
    await service.reconcileOperations();

    expect((await store.getResource(created.resource.id))?.state).toBe("READY");
    expect((await store.listOperations(created.resource.id))[0]).toMatchObject({ status: "COMPLETED" });
  });

  it("records a failed task as unknown and does not dispatch a second mutation", async () => {
    const store = new MemoryStore();
    const provider = new FakeAsyncComputeProvider();
    const service = new ResourceService(store, provider);
    const created = await service.create({ type: "browser", projectId: "default", ttlSeconds: 60 }, "failed-create", "test");
    const operation = (await store.listOperations(created.resource.id))[0]!;

    await provider.completeTask(operation.taskHandle!.taskId, "FAILED");
    await service.reconcileOperations();

    expect((await store.listOperations(created.resource.id))[0]).toMatchObject({ status: "UNKNOWN", safeReason: "TASK_FAILED" });
    await expect(service.mutate(created.resource.id, "destroy", "default")).rejects.toMatchObject({ code: "OPERATION_UNRESOLVED" });
    expect(provider.mutations).toEqual([]);
  });

  it("returns only the safe history fields through the project-authorized API", async () => {
    const provider = new FakeAsyncComputeProvider();
    const { app, store } = createApp({ token: "secret", provider });
    const created = await app.inject({
      method: "POST",
      url: "/v1/resources",
      headers: { authorization: "Bearer secret", "idempotency-key": "history" },
      payload: { type: "development", ttlSeconds: 60 },
    });
    const resource = created.json() as { id: string };
    const response = await app.inject({ method: "GET", url: `/v1/resources/${resource.id}/operations`, headers: { authorization: "Bearer secret" } });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ operations: [expect.objectContaining({ status: "SUBMITTED", safeReason: null })] });
    expect(response.body).not.toContain("snapshot");
    expect(response.body).not.toContain("taskHandle");
    expect((await store.listOperations(resource.id))[0]?.snapshot).toBeTruthy();
  });

  it("attests an async gateway only after its operation completes", async () => {
    const store = new MemoryStore();
    const provider = new FakeAsyncComputeProvider();
    const gateways = new GatewayService(store, provider);
    const created = await gateways.createFakeGateway("fake-node", "async-gateway", "test");
    const operation = (await store.listOperations(created.resource.id))[0]!;

    expect((await provider.observeGateway(created.resource, (await store.getGateway(created.resource.id))!)).config).toBe("UNKNOWN");
    await provider.completeTask(operation.taskHandle!.taskId);
    await gateways.reconcileOperations();

    expect((await store.getResource(created.resource.id))?.state).toBe("READY");
    expect((await provider.observeGateway(created.resource, (await store.getGateway(created.resource.id))!)).config).toBe("VALID");
  });

  it("bounds public operation history to the newest 100 records", async () => {
    const store = new MemoryStore();
    const provider = new FakeComputeProvider();
    const service = new ResourceService(store, provider);
    const created = await service.create({ type: "development", projectId: "default", ttlSeconds: 60 }, "history-bound", "test");
    for (let index = 0; index < 101; index += 1) {
      const operation = await store.beginOperation({ resourceId: created.resource.id, kind: "stop" });
      await store.completeOperation(operation.id);
    }

    const history = await service.operationHistory(created.resource.id, "default");

    expect(history).toHaveLength(100);
    expect(history.every((operation) => "snapshot" in operation)).toBe(false);
  });

  it("does not dispatch or leak a resource transition when intent audit persistence fails", async () => {
    class FailingAuditStore extends MemoryStore {
      override async appendEvent(): Promise<never> { throw new Error("audit unavailable"); }
    }
    const store = new FailingAuditStore();
    const provider = new FakeAsyncComputeProvider();
    const service = new ResourceService(store, provider);

    await expect(service.create({ type: "development", projectId: "default", ttlSeconds: 60 }, "audit-failure", "test")).rejects.toThrow("audit unavailable");

    expect(provider.mutations).toEqual([]);
    expect(await store.listResources("default")).toHaveLength(1);
    expect((await store.listResources("default"))[0]?.state).toBe("PROVISIONING");
    expect(await store.listOperations((await store.listResources("default"))[0]!.id)).toEqual([]);
  });
});
