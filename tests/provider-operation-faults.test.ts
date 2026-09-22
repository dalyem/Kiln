import { describe, expect, it } from "vitest";
import {
  DoctorService,
  GatewayMonitor,
  GatewayService,
  NetworkProbeService,
  operationSnapshot,
  ResourceService,
} from "@kiln/core";
import type { Event, Operation, ProviderTaskHandle } from "@kiln/core";
import { MemoryStore } from "@kiln/database";
import { FakeAsyncComputeProvider, FakeComputeProvider } from "@kiln/providers";

class LostReceiptProvider extends FakeAsyncComputeProvider {
  submissions = 0;

  override async submitOperation(
    operation: Operation,
  ): Promise<ProviderTaskHandle> {
    this.submissions += 1;
    await super.submitOperation(operation);
    throw new Error("task receipt lost");
  }
}

class CompletionAuditFailureStore extends MemoryStore {
  override async appendEvent(
    event: Parameters<MemoryStore["appendEvent"]>[0],
  ): Promise<Event> {
    if (event.type === "resource.create_completed")
      throw new Error("completion audit unavailable");
    return super.appendEvent(event);
  }
}

class CompletionAcknowledgementLostStore extends MemoryStore {
  override async completeOperationTransition(
    operationId: string,
    resource: Parameters<MemoryStore["completeOperationTransition"]>[1],
    event: Parameters<MemoryStore["completeOperationTransition"]>[2],
  ): Promise<Event> {
    await super.completeOperationTransition(operationId, resource, event);
    throw new Error("completion acknowledgement lost");
  }
}

class CountingAsyncProvider extends FakeAsyncComputeProvider {
  inspections = 0;

  override async inspectOperation(handle: ProviderTaskHandle) {
    this.inspections += 1;
    return super.inspectOperation(handle);
  }
}

class ForgedSnapshotStore extends MemoryStore {
  override async unresolvedOperation(resourceId: string) {
    const operation = await super.unresolvedOperation(resourceId);
    if (!operation?.snapshot || !operation.taskHandle) return operation;
    return {
      ...operation,
      snapshot: { ...operation.snapshot, providerResourceId: "forged-native-id" },
      taskHandle: { ...operation.taskHandle, providerResourceId: "forged-native-id" },
    };
  }
}

class FalseSuccessProvider extends FakeAsyncComputeProvider {
  override async inspectOperation(handle: ProviderTaskHandle) {
    if (handle.action === "start" || handle.action === "stop")
      return { status: "SUCCEEDED" as const };
    return super.inspectOperation(handle);
  }
}

class MutatingSubmitProvider extends FakeAsyncComputeProvider {
  override async submitOperation(
    operation: Operation,
  ): Promise<ProviderTaskHandle> {
    const handle = await super.submitOperation(operation);
    operation.resourceId = "forged-resource-id";
    return handle;
  }
}

class MutatingInspectProvider extends FakeAsyncComputeProvider {
  override async inspectOperation(handle: ProviderTaskHandle) {
    const observation = await super.inspectOperation(handle);
    handle.providerResourceId = "forged-native-id";
    return observation;
  }
}

class MissingDeadlineStore extends MemoryStore {
  override async unresolvedOperation(resourceId: string) {
    const operation = await super.unresolvedOperation(resourceId);
    return operation ? { ...operation, reconciliationDeadline: null } : null;
  }
}

class MutatingAsyncPowerProvider extends FakeAsyncComputeProvider {
  override async inspectPower(resource: Parameters<FakeAsyncComputeProvider["inspectPower"]>[0]) {
    const providerResourceId = resource.providerResourceId;
    resource.providerResourceId = "forged-native-id";
    return this.power.get(providerResourceId) ?? "UNKNOWN";
  }
}

class MutatingSyncResourceProvider extends FakeComputeProvider {
  override async create(resource: Parameters<FakeComputeProvider["create"]>[0]) {
    const observation = await super.create(resource);
    resource.providerResourceId = "forged-native-id";
    return observation;
  }

  override async stop(resource: Parameters<FakeComputeProvider["stop"]>[0]) {
    await super.stop(resource);
    resource.providerResourceId = "forged-native-id";
  }

  override async inspectPower(resource: Parameters<FakeComputeProvider["inspectPower"]>[0]) {
    const providerResourceId = resource.providerResourceId;
    resource.providerResourceId = "forged-native-id";
    return this.power.get(providerResourceId) ?? "UNKNOWN";
  }
}

async function createReadyResource(
  store: MemoryStore,
  provider: FakeAsyncComputeProvider,
  key: string,
) {
  const service = new ResourceService(store, provider);
  const created = await service.create(
    { type: "development", projectId: "default", ttlSeconds: 60 },
    key,
    "test",
  );
  const operation = (await store.listOperations(created.resource.id))[0]!;
  await provider.completeTask(operation.taskHandle!.taskId);
  await service.reconcileOperations();
  return { service, resource: (await store.getResource(created.resource.id))! };
}

describe("provider operation fault boundaries", () => {
  it("does not let an async power inspection change the completed resource binding", async () => {
    const store = new MemoryStore();
    const provider = new MutatingAsyncPowerProvider();
    const service = new ResourceService(store, provider);
    const created = await service.create(
      { type: "development", projectId: "default", ttlSeconds: 60 },
      "mutating-async-power",
      "test",
    );
    const operation = (await store.listOperations(created.resource.id))[0]!;

    await provider.completeTask(operation.taskHandle!.taskId);
    await service.reconcileOperations();

    expect((await store.getResource(created.resource.id))!).toMatchObject({
      providerResourceId: created.resource.providerResourceId,
      state: "READY",
    });
  });

  it("uses the original resource binding for sync create and stop completion", async () => {
    const store = new MemoryStore();
    const provider = new MutatingSyncResourceProvider();
    const service = new ResourceService(store, provider);
    const created = await service.create(
      { type: "development", projectId: "default", ttlSeconds: 60 },
      "mutating-sync-resource",
      "test",
    );

    expect((await store.getResource(created.resource.id))!).toMatchObject({
      providerResourceId: created.resource.providerResourceId,
      state: "READY",
    });
    await service.mutate(created.resource.id, "stop", "default");
    expect((await store.getResource(created.resource.id))!).toMatchObject({
      providerResourceId: created.resource.providerResourceId,
      state: "STOPPED",
    });
    expect(await provider.inspect(created.resource.providerResourceId)).not.toBeNull();
  });

  it("keeps the stored fence when a provider mutates its submitted operation", async () => {
    const store = new MemoryStore();
    const provider = new MutatingSubmitProvider();
    const service = new ResourceService(store, provider);
    const created = await service.create(
      { type: "development", projectId: "default", ttlSeconds: 60 },
      "mutating-submit",
      "test",
    );

    expect(await store.unresolvedOperation(created.resource.id)).toMatchObject({
      resourceId: created.resource.id,
      status: "SUBMITTED",
    });
    expect(await store.unresolvedOperation("forged-resource-id")).toBeNull();
  });

  it("keeps the stored task receipt when an inspector mutates its input", async () => {
    const store = new MemoryStore();
    const provider = new MutatingInspectProvider();
    const service = new ResourceService(store, provider);
    const created = await service.create(
      { type: "development", projectId: "default", ttlSeconds: 60 },
      "mutating-inspect",
      "test",
    );
    const operation = (await store.listOperations(created.resource.id))[0]!;

    await service.reconcileOperations();

    expect((await store.getOperation(operation.id))?.taskHandle).toMatchObject({
      providerResourceId: created.resource.providerResourceId,
    });
  });

  it("fails closed when a submitted operation has no reconciliation deadline", async () => {
    const store = new MissingDeadlineStore();
    const provider = new CountingAsyncProvider();
    const service = new ResourceService(store, provider);
    const created = await service.create(
      { type: "development", projectId: "default", ttlSeconds: 60 },
      "missing-deadline",
      "test",
    );

    await service.reconcileOperations();

    expect((await store.listOperations(created.resource.id))[0]).toMatchObject({
      status: "UNKNOWN",
      safeReason: "TASK_UNKNOWN",
    });
    expect(provider.inspections).toBe(0);
  });

  it("returns copies of operation records from the in-memory store", async () => {
    const store = new MemoryStore();
    const operation = await store.beginOperation({ resourceId: "copied-operation", kind: "create" });
    operation.resourceId = "caller-mutation";

    const unresolved = await store.unresolvedOperation("copied-operation");
    expect(unresolved).toMatchObject({ resourceId: "copied-operation" });
    unresolved!.resourceId = "lookup-mutation";
    expect(await store.unresolvedOperation("copied-operation")).toMatchObject({
      resourceId: "copied-operation",
    });

    await store.completeOperation(operation.id);
    const completed = await store.completedOperation("copied-operation", "create");
    completed!.resourceId = "completed-mutation";
    expect(await store.completedOperation("copied-operation", "create")).toMatchObject({
      resourceId: "copied-operation",
    });
  });

  it("matches PostgreSQL source-state guards for operation transitions", async () => {
    const store = new MemoryStore();
    const unknown = await store.beginOperation({ resourceId: "unknown", kind: "create" });
    await store.markOperationUnknown(unknown.id);
    const event = {
      installationId: "test-installation",
      projectId: "default",
      resourceId: "unknown",
      type: "resource.create.submitted",
      timestamp: new Date().toISOString(),
      payload: {},
    };
    const handle: ProviderTaskHandle = {
      taskId: "task",
      providerId: "fake",
      providerResourceId: "native",
      providerKind: "fake",
      node: "fake-node",
      action: "create",
      snapshotDigest: "digest",
    };

    await expect(store.markOperationSubmitted(unknown.id, handle, event)).rejects.toThrow(
      "Operation was not ready to submit",
    );
    await expect(store.completeOperation(unknown.id)).rejects.toThrow(
      "Operation was not ready to complete",
    );

    const submitted = await store.beginOperation({ resourceId: "submitted", kind: "create" });
    await store.markOperationSubmitted(submitted.id, handle, { ...event, resourceId: "submitted" });
    const completed = await Promise.allSettled([
      store.completeOperation(submitted.id),
      store.completeOperation(submitted.id),
    ]);
    expect(completed.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(completed.filter((result) => result.status === "rejected")).toHaveLength(1);

    const competing = await Promise.allSettled([
      store.beginOperation({ resourceId: "single-fence", kind: "create" }),
      store.beginOperation({ resourceId: "single-fence", kind: "stop" }),
    ]);
    expect(competing.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(competing.filter((result) => result.status === "rejected")).toHaveLength(1);
  });

  it("publishes one direct completion transition after concurrent audit preflight", async () => {
    const store = new MemoryStore();
    const provider = new FakeAsyncComputeProvider();
    const service = new ResourceService(store, provider);
    const created = await service.create(
      { type: "development", projectId: "default", ttlSeconds: 60 },
      "concurrent-store-transition",
      "test",
    );
    const operation = (await store.listOperations(created.resource.id))[0]!;
    const resource = (await store.getResource(created.resource.id))!;
    resource.state = "READY";
    const event = {
      installationId: resource.installationId,
      projectId: resource.projectId,
      resourceId: resource.id,
      type: "resource.create_completed",
      timestamp: new Date().toISOString(),
      payload: { operationId: operation.id },
    };

    const results = await Promise.allSettled([
      store.completeOperationTransition(operation.id, resource, event),
      store.completeOperationTransition(operation.id, resource, event),
    ]);

    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    expect(
      (await store.events("default", 0)).filter(
        (saved) => saved.type === "resource.create_completed",
      ),
    ).toHaveLength(1);
  });

  it("keeps a lost task receipt unknown, blocks lease changes, and never dispatches it twice", async () => {
    const store = new MemoryStore();
    const provider = new LostReceiptProvider();
    const service = new ResourceService(store, provider);
    const input = {
      type: "development" as const,
      projectId: "default",
      ttlSeconds: 60,
    };

    await expect(service.create(input, "lost-receipt", "test")).rejects.toThrow(
      "task receipt lost",
    );
    const resource = (await store.listResources("default"))[0]!;
    const operation = (await store.listOperations(resource.id)).find((candidate) => candidate.kind === "create")!;

    expect(operation).toMatchObject({
      status: "UNKNOWN",
      safeReason: "DISPATCH_UNKNOWN",
      taskHandle: null,
    });
    await expect(
      service.extend(resource.id, "default", 60),
    ).rejects.toMatchObject({
      code: "OPERATION_UNRESOLVED",
    });
    await expect(
      service.create(input, "lost-receipt", "test"),
    ).resolves.toMatchObject({
      replayed: true,
      resource: { id: resource.id },
    });
    expect(provider.submissions).toBe(1);
  });

  it("keeps completion unknown when its audit event cannot be stored", async () => {
    const store = new CompletionAuditFailureStore();
    const provider = new FakeAsyncComputeProvider();
    const service = new ResourceService(store, provider);
    const created = await service.create(
      { type: "development", projectId: "default", ttlSeconds: 60 },
      "completion-audit",
      "test",
    );
    const operation = (await store.listOperations(created.resource.id))[0]!;

    await provider.completeTask(operation.taskHandle!.taskId);
    await service.reconcileOperations();

    expect((await store.listOperations(created.resource.id))[0]).toMatchObject({
      status: "UNKNOWN",
      safeReason: "POSTCONDITION_FAILED",
    });
    expect((await store.getResource(created.resource.id))?.state).toBe(
      "PROVISIONING",
    );
  });

  it("retains a completed resource when completion commits before its acknowledgement is lost", async () => {
    const store = new CompletionAcknowledgementLostStore();
    const provider = new FakeComputeProvider();
    const service = new ResourceService(store, provider);

    const created = await service.create(
      { type: "development", projectId: "default", ttlSeconds: 60 },
      "completion-acknowledgement",
      "test",
    );

    expect(created.resource.state).toBe("READY");
    expect((await store.listOperations(created.resource.id))[0]).toMatchObject({
      status: "COMPLETED",
    });
    expect((await store.getResource(created.resource.id))?.state).toBe("READY");
  });

  it("does not mark a destroy complete when a native ID has been reused", async () => {
    const store = new MemoryStore();
    const provider = new FakeAsyncComputeProvider();
    const { service, resource } = await createReadyResource(
      store,
      provider,
      "destroy-reuse",
    );

    await service.mutate(resource.id, "destroy", "default");
    const operation = (await store.listOperations(resource.id)).find((candidate) => candidate.kind === "destroy")!;
    await provider.completeTask(operation.taskHandle!.taskId);
    provider.fixtures.set(resource.providerResourceId, {
      providerId: "fake",
      providerResourceId: resource.providerResourceId,
      providerKind: "fake",
      kind: "browser",
      pool: "foreign",
      node: resource.node,
      tags: [],
    });

    await service.reconcileOperations();

    expect((await store.listOperations(resource.id)).find((candidate) => candidate.kind === "destroy")).toMatchObject({
      status: "UNKNOWN",
      safeReason: "POSTCONDITION_FAILED",
    });
    expect((await store.getResource(resource.id))?.state).not.toBe("DESTROYED");
  });

  it("rejects a recorded task when the current resource binding no longer matches its snapshot", async () => {
    const store = new MemoryStore();
    const provider = new FakeAsyncComputeProvider();
    const service = new ResourceService(store, provider);
    const created = await service.create(
      { type: "development", projectId: "default", ttlSeconds: 60 },
      "binding-drift",
      "test",
    );
    const changed = (await store.getResource(created.resource.id))!;
    changed.providerResourceId = "rebound-native-id";
    await store.updateResource(changed);

    await service.reconcileOperations();

    expect((await store.listOperations(created.resource.id))[0]).toMatchObject({
      status: "UNKNOWN",
      safeReason: "POSTCONDITION_FAILED",
    });
  });

  it("rejects a forged snapshot field even when the forged handle matches it", async () => {
    const store = new ForgedSnapshotStore();
    const provider = new CountingAsyncProvider();
    const service = new ResourceService(store, provider);
    const created = await service.create(
      { type: "development", projectId: "default", ttlSeconds: 60 },
      "forged-snapshot",
      "test",
    );

    await service.reconcileOperations();

    expect((await store.listOperations(created.resource.id))[0]).toMatchObject({
      status: "UNKNOWN",
      safeReason: "POSTCONDITION_FAILED",
    });
    expect(provider.inspections).toBe(0);
  });

  it.each(["stop", "start"] as const)(
    "does not complete an async %s from task success without a power postcondition",
    async (kind) => {
      const store = new MemoryStore();
      const provider = new FalseSuccessProvider();
      const { service, resource } = await createReadyResource(
        store,
        provider,
        `power-${kind}`,
      );
      if (kind === "start") {
        await provider.stop(resource);
        resource.state = "STOPPED";
        await store.updateResource(resource);
      }

      await service.mutate(resource.id, kind, "default");
      await service.reconcileOperations();

      expect((await store.listOperations(resource.id)).find((candidate) => candidate.kind === kind)).toMatchObject({
        status: "SUBMITTED",
        safeReason: null,
      });
      expect((await store.getResource(resource.id))?.state).not.toBe(
        kind === "stop" ? "STOPPED" : "READY",
      );
    },
  );

  it("stops polling after a deadline turns a running task unknown", async () => {
    let now = new Date("2026-01-01T00:00:00.000Z");
    const store = new MemoryStore();
    const provider = new CountingAsyncProvider();
    const service = new ResourceService(store, provider, () => now);
    const created = await service.create(
      { type: "development", projectId: "default", ttlSeconds: 60 },
      "deadline",
      "test",
    );

    await service.reconcileOperations();

    now = new Date("2026-01-01T00:15:00.000Z");
    await service.reconcileOperations();
    await service.reconcileOperations();

    expect((await store.listOperations(created.resource.id))[0]).toMatchObject({
      status: "UNKNOWN",
      safeReason: "TASK_UNKNOWN",
    });
    expect(provider.inspections).toBe(1);
  });

  it("stops polling after a terminal failed task", async () => {
    const store = new MemoryStore();
    const provider = new CountingAsyncProvider();
    const service = new ResourceService(store, provider);
    const created = await service.create(
      { type: "development", projectId: "default", ttlSeconds: 60 },
      "terminal-failure",
      "test",
    );
    const operation = (await store.listOperations(created.resource.id))[0]!;
    await provider.completeTask(operation.taskHandle!.taskId, "FAILED");

    await service.reconcileOperations();
    await service.reconcileOperations();

    expect((await store.listOperations(created.resource.id))[0]).toMatchObject({
      status: "UNKNOWN",
      safeReason: "TASK_FAILED",
    });
    expect(provider.inspections).toBe(1);
  });

  it("serializes concurrent reconciliation ticks into one completion event", async () => {
    const store = new MemoryStore();
    const provider = new FakeAsyncComputeProvider();
    const service = new ResourceService(store, provider);
    const created = await service.create(
      { type: "development", projectId: "default", ttlSeconds: 60 },
      "concurrent-reconcile",
      "test",
    );
    const operation = (await store.listOperations(created.resource.id))[0]!;
    await provider.completeTask(operation.taskHandle!.taskId);

    await Promise.all([
      service.reconcileOperations(),
      service.reconcileOperations(),
      service.reconcileOperations(),
    ]);

    expect((await store.listOperations(created.resource.id))[0]).toMatchObject({
      status: "COMPLETED",
    });
    expect(
      (await store.events("default", 0)).filter(
        (event) => event.type === "resource.create_completed",
      ),
    ).toHaveLength(1);
  });

  it("holds workload admission and doctor readiness when a ready gateway has an unresolved operation", async () => {
    const store = new MemoryStore();
    const provider = new FakeComputeProvider();
    const gateway = await new GatewayService(store, provider).createFakeGateway(
      "fake-node",
      "gateway-hold",
      "infra",
    );
    await new GatewayMonitor(store, provider).scan();
    const pending = await store.beginOperation({
      resourceId: gateway.resource.id,
      kind: "stop",
      snapshot: operationSnapshot(gateway.resource, "stop"),
    });
    await store.markOperationSubmitted(
      pending.id,
      {
        taskId: "pending-gateway-task",
        providerId: "fake",
        providerResourceId: gateway.resource.providerResourceId,
        providerKind: "fake",
        node: gateway.resource.node,
        action: "stop",
        snapshotDigest: pending.snapshot!.canonicalDigest,
      },
      {
        installationId: gateway.resource.installationId,
        projectId: "infrastructure",
        resourceId: gateway.resource.id,
        type: "gateway.stop.submitted",
        timestamp: new Date().toISOString(),
        payload: {},
      },
    );

    await expect(
      new ResourceService(store, provider).create(
        { type: "execution", projectId: "default", ttlSeconds: 60 },
        "held-workload",
        "test",
      ),
    ).rejects.toMatchObject({ code: "NETWORK_NOT_READY" });
    await expect(
      new DoctorService(store, provider).inspect("fake-node"),
    ).resolves.toMatchObject({
      nodes: [
        expect.objectContaining({
          checks: expect.arrayContaining([
            expect.objectContaining({ code: "OPERATION_UNRESOLVED" }),
          ]),
        }),
      ],
    });
  });

  it("blocks new probe authority while an async stop is unresolved and cancels the pending job on completion", async () => {
    const store = new MemoryStore();
    const provider = new FakeAsyncComputeProvider();
    const resources = new ResourceService(store, provider);
    const gateways = new GatewayService(store, provider);
    const gateway = await gateways.createFakeGateway("fake-node", "probe-gateway", "test");
    const gatewayOperation = (await store.listOperations(gateway.resource.id))[0]!;
    await provider.completeTask(gatewayOperation.taskHandle!.taskId);
    await gateways.reconcileOperations();
    const profiles = [{ id: "probe", ttlSeconds: 60, checks: [{ id: "dns", kind: "dns" as const, hostname: "example.test", resolverAddress: "192.0.2.53", resolverPort: 53, timeoutMs: 500 }] }];
    const probes = new NetworkProbeService(store, provider, profiles, resources);
    const created = await probes.create(gateway.resource.id, "probe", "probe-stop", "test");
    const createOperation = (await store.listOperations(created.resource.id)).find((operation) => operation.kind === "create")!;
    await provider.completeTask(createOperation.taskHandle!.taskId);
    await resources.reconcileOperations();
    const issued = await probes.issueToken(created.resource.id);
    const plan = await probes.plan(created.resource.id, issued.token);

    await resources.mutate(created.resource.id, "stop", "infrastructure");

    await expect(probes.issueToken(created.resource.id)).rejects.toMatchObject({ code: "OPERATION_UNRESOLVED" });
    await expect(probes.plan(created.resource.id, issued.token)).rejects.toMatchObject({ code: "OPERATION_UNRESOLVED" });
    await expect(probes.result(created.resource.id, issued.token, plan.planDigest, [{ id: "dns", code: "DNS_ANSWER", durationMs: 1 }])).rejects.toMatchObject({ code: "OPERATION_UNRESOLVED" });
    const stopOperation = (await store.listOperations(created.resource.id)).find((operation) => operation.kind === "stop")!;
    await provider.completeTask(stopOperation.taskHandle!.taskId);
    await resources.reconcileOperations();

    expect((await store.getNetworkProbe(created.resource.id))?.state).toBe("CANCELLED");
  });
});
