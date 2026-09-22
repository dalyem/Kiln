import type {
  ComputeProvider,
  OwnershipObservation,
  ProviderInventory,
  ProviderMetrics,
  Resource,
  GatewayEvidence,
  GatewayMetadata,
  Operation,
  ProviderTaskHandle,
  ProviderTaskObservation,
  ProvisioningAttachment,
  ProvisioningPlan,
} from "@kiln/core";
import { canonicalAttachmentGraph, canonicalPlanDigest, canonicalTemplateImportDigest, KilnError, ownershipTags, validateOwnership } from "@kiln/core";

export class FakeComputeProvider implements ComputeProvider {
  readonly id = "fake";
  readonly mode = "fake" as const;
  readonly fixtures = new Map<string, OwnershipObservation>();
  readonly power = new Map<string, "RUNNING" | "STOPPED">();
  readonly mutations: Array<{ operation: string; id: string }> = [];
  readonly gatewayEvidence = new Map<string, Partial<GatewayEvidence>>();
  readonly gatewayAttestations = new Map<string, { generation: string; configFingerprint: string }>();
  readonly attachmentGraphs = new Map<string, ProvisioningAttachment[]>();
  readonly preparedPlans = new Map<string, ProvisioningPlan>();
  readonly preparedTemplateAttachments = new Map<string, ProvisioningAttachment[]>();
  readonly preparedTemplateEvidence = new Map<string, import("@kiln/core").TemplateImport>();
  readonly preparedTemplateDigests = new Map<string, string>();
  constructor(
    private inventory: ProviderInventory = {
      nodes: [{ id: "fake-node", online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] }],
      storage: [],
      resources: [],
    },
    private readonly clock = () => new Date(),
  ) {}
  async discover(): Promise<ProviderInventory> {
    return {
      ...this.inventory,
      resources: [...this.fixtures.values(), ...this.inventory.resources],
    };
  }
  async inspect(id: string): Promise<OwnershipObservation | null> {
    return this.fixtures.get(id) ?? null;
  }
  async metrics(): Promise<ProviderMetrics[]> {
    return this.inventory.nodes.map((node) => ({
      nodeId: node.id,
      cpuFree: node.cpuFree,
      memoryFree: node.memoryFree,
      observedAt: new Date().toISOString(),
    }));
  }
  async create(resource: Resource): Promise<OwnershipObservation> {
    const observation: OwnershipObservation = {
      providerId: this.id,
      providerResourceId: resource.providerResourceId,
      providerKind: "fake",
      kind: resource.type,
      pool: "kiln",
      node: resource.node,
      tags: ownershipTags(resource),
    };
    this.fixtures.set(resource.providerResourceId, observation);
    this.power.set(resource.providerResourceId, "RUNNING");
    this.mutations.push({
      operation: "create",
      id: resource.providerResourceId,
    });
    return observation;
  }
  async importTemplate(resource: Resource, attachments: ProvisioningAttachment[]): Promise<OwnershipObservation> {
    const observation = await this.create(resource);
    this.attachmentGraphs.set(resource.providerResourceId, structuredClone(attachments));
    return observation;
  }
  async prepareTemplateImport(resource: Resource, template: import("@kiln/core").TemplateImport, templateImportDigest: string): Promise<void> {
    this.preparedTemplateAttachments.set(resource.id, structuredClone(template.attachments));
    this.preparedTemplateEvidence.set(resource.id, structuredClone(template));
    this.preparedTemplateDigests.set(resource.id, templateImportDigest);
  }
  async prepareProvisioning(resource: Resource, plan: ProvisioningPlan): Promise<void> {
    if (plan.resourceId !== resource.id || plan.providerResourceId !== resource.providerResourceId || plan.cloneMode !== "FULL")
      throw new KilnError("SAFETY_DENIED", 403, "Fake provisioning plan does not match its destination");
    this.preparedPlans.set(resource.id, structuredClone(plan));
  }
  async provision(resource: Resource, plan: ProvisioningPlan): Promise<OwnershipObservation> {
    const prepared = this.preparedPlans.get(resource.id);
    if (!prepared || prepared.canonicalDigest !== plan.canonicalDigest)
      throw new KilnError("SAFETY_DENIED", 403, "Fake provisioning plan was not prepared");
    const source = this.fixtures.get(plan.templateProviderResourceId);
    const sourceGraph = this.attachmentGraphs.get(plan.templateProviderResourceId);
    if (!source || source.providerId !== plan.templateProviderId || source.providerKind !== plan.templateProviderKind || source.providerResourceId !== plan.templateProviderResourceId || source.node !== plan.templateNode || source.pool !== plan.templatePool || !sourceGraph || canonicalAttachmentGraph(sourceGraph) !== canonicalAttachmentGraph(plan.templateAttachments))
      throw new KilnError("SAFETY_DENIED", 403, "Fake provisioning source does not match its plan");
    const observation = await this.create(resource);
    this.attachmentGraphs.set(resource.providerResourceId, structuredClone(plan.attachments));
    return observation;
  }
  async inspectAttachments(resource: Resource): Promise<ProvisioningAttachment[] | null> {
    const graph = this.attachmentGraphs.get(resource.providerResourceId);
    return graph ? structuredClone(graph) : null;
  }
  async start(resource: Resource): Promise<void> {
    await this.guarded("start", resource);
    this.power.set(resource.providerResourceId, "RUNNING");
  }
  async stop(resource: Resource): Promise<void> {
    await this.guarded("stop", resource);
    this.power.set(resource.providerResourceId, "STOPPED");
  }
  async destroy(resource: Resource): Promise<void> {
    await this.guarded("destroy", resource);
    this.fixtures.delete(resource.providerResourceId);
    this.power.delete(resource.providerResourceId);
    this.attachmentGraphs.delete(resource.providerResourceId);
  }
  async inspectPower(resource: Resource): Promise<"RUNNING" | "STOPPED" | "UNKNOWN"> {
    return this.power.get(resource.providerResourceId) ?? "UNKNOWN";
  }
  async observeGateway(resource: Resource, metadata: GatewayMetadata): Promise<GatewayEvidence> {
    const override = this.gatewayEvidence.get(resource.id) ?? {};
    const observation = await this.inspect(resource.providerResourceId);
    const attestation = this.gatewayAttestations.get(resource.id);
    let ownership: GatewayEvidence["ownership"] = "INVALID";
    try {
      if (observation) validateOwnership(resource, resource.installationId, observation);
      else ownership = "UNKNOWN";
      if (observation) ownership = "VALID";
    } catch { ownership = "INVALID"; }
    return {
      power: "RUNNING",
      ownership,
      config: !attestation ? "UNKNOWN" : attestation.configFingerprint === metadata.expectedFingerprint && resource.node === metadata.node ? "VALID" : "INVALID",
      heartbeat: "PASS",
      policy: "PASS",
      reservation: "PASS",
      services: "PASS",
      canary: "PASS",
      generation: attestation?.generation ?? null,
      configFingerprint: attestation?.configFingerprint ?? null,
      observedAt: this.clock().toISOString(),
      ...override,
    };
  }
  async registerGatewayAttestation(resource: Resource, metadata: GatewayMetadata): Promise<void> {
    this.gatewayAttestations.set(resource.id, {
      generation: metadata.generation,
      configFingerprint: metadata.expectedFingerprint,
    });
  }
  private async guarded(operation: string, resource: Resource): Promise<void> {
    const observed = await this.inspect(resource.providerResourceId);
    if (!observed)
      throw new KilnError("SAFETY_DENIED", 403, "Provider resource is missing");
    validateOwnership(resource, resource.installationId, observed);
    this.mutations.push({ operation, id: resource.providerResourceId });
  }
}

export class FakeAsyncComputeProvider extends FakeComputeProvider {
  private readonly tasks = new Map<string, { operation: Operation; status: ProviderTaskObservation["status"] }>();
  async submitOperation(operation: Operation): Promise<ProviderTaskHandle> {
    if (!operation.snapshot) throw new KilnError("SAFETY_DENIED", 403, "Async operation has no immutable snapshot");
    const taskId = `fake-task-${operation.id}`;
    this.tasks.set(taskId, { operation: structuredClone(operation), status: "RUNNING" });
    return {
      taskId,
      providerId: operation.snapshot.providerId,
      providerResourceId: operation.snapshot.providerResourceId,
      providerKind: operation.snapshot.providerKind,
      node: operation.snapshot.node,
      action: operation.kind,
      snapshotDigest: operation.snapshot.canonicalDigest,
    };
  }
  async inspectOperation(handle: ProviderTaskHandle): Promise<ProviderTaskObservation> {
    const task = this.tasks.get(handle.taskId);
    if (!task) return { status: "MISSING" };
    if (handle.providerId !== this.id || handle.providerResourceId !== task.operation.snapshot?.providerResourceId || handle.action !== task.operation.kind || handle.snapshotDigest !== task.operation.snapshot?.canonicalDigest)
      return { status: "UNKNOWN" };
    return { status: task.status };
  }
  async completeTask(taskId: string, status: Extract<ProviderTaskObservation["status"], "SUCCEEDED" | "FAILED"> = "SUCCEEDED"): Promise<void> {
    const task = this.tasks.get(taskId);
    if (!task) throw new Error("Fake task not found");
    task.status = status;
    if (status !== "SUCCEEDED") return;
    const snapshot = task.operation.snapshot!;
    const resource: Resource = {
      id: snapshot.resourceId,
      installationId: snapshot.installationId,
      projectId: snapshot.projectId,
      type: snapshot.type,
      ownership: snapshot.ownership,
      state: "PROVISIONING",
      providerId: snapshot.providerId,
      providerResourceId: snapshot.providerResourceId,
      providerKind: snapshot.providerKind,
      node: snapshot.node,
      pool: snapshot.pool,
      createdBy: "async-task",
      createdAt: new Date().toISOString(),
      expiresAt: null,
      profile: null,
    };
    if (task.operation.kind === "create" && resource.type === "image_template") {
      const attachments = this.preparedTemplateAttachments.get(resource.id);
      const evidence = this.preparedTemplateEvidence.get(resource.id);
      if (!attachments || !evidence || !snapshot.templateImportDigest || this.preparedTemplateDigests.get(resource.id) !== snapshot.templateImportDigest || canonicalTemplateImportDigest(evidence) !== snapshot.templateImportDigest || canonicalAttachmentGraph(attachments) !== canonicalAttachmentGraph(evidence.attachments)) throw new KilnError("SAFETY_DENIED", 403, "Fake template import receipt does not match prepared evidence");
      await super.importTemplate(resource, attachments);
    } else if (task.operation.kind === "create") {
      const plan = this.preparedPlans.get(resource.id);
      if (plan) {
        if (!snapshot.provisioningPlanDigest || canonicalPlanDigest({ ...plan, canonicalDigest: undefined } as Omit<ProvisioningPlan, "canonicalDigest">) !== plan.canonicalDigest || plan.canonicalDigest !== snapshot.provisioningPlanDigest) throw new KilnError("SAFETY_DENIED", 403, "Fake provisioning receipt does not match prepared plan");
        await super.provision(resource, plan);
      }
      else await super.create(resource);
    }
    else if (task.operation.kind === "start") await super.start(resource);
    else if (task.operation.kind === "stop") await super.stop(resource);
    else await super.destroy(resource);
  }
}
