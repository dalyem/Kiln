import { createHash } from "node:crypto";
import { canonicalAttachmentGraph, canonicalImageManifest, canonicalPlanDigest, canonicalTemplateImportDigest, sha256, validAttachmentGraph, type ProvisioningAttachment, type ProvisioningPlan, type SafeProvenanceSummary, type TemplateImport, type VerifiedImage } from "./provenance.js";
export * from "./provenance.js";
export * from "./image-file.js";
export * from "./linux-image-staging.js";
export * from "./linux-build-metadata.js";
export * from "./linux-import.js";
export * from "./qualification.js";

export type Ownership = "KILN_MANAGED" | "IMPORTED" | "EXTERNAL";
export type ResourceType = "development" | "execution" | "browser" | "gateway" | "network_probe" | "image_template";
export type ResourceState =
  | "REQUESTED"
  | "PROVISIONING"
  | "READY"
  | "STOPPING"
  | "STOPPED"
  | "DESTROYING"
  | "DESTROYED"
  | "ERROR"
  | "LOST"
  | "QUARANTINED";

export interface Resource {
  id: string;
  installationId: string;
  projectId: string;
  type: ResourceType;
  ownership: Ownership;
  state: ResourceState;
  providerId: string;
  providerResourceId: string;
  providerKind: string;
  node: string | null;
  pool: string;
  createdBy: string;
  createdAt: string;
  expiresAt: string | null;
  profile: string | null;
  provenanceRequired?: boolean;
}

export type GatewayCheckStatus = "PASS" | "WARN" | "FAIL" | "UNKNOWN";
export type GatewayNodeStatus = "READY" | "NOT_READY" | "QUARANTINED" | "UNCONFIGURED";
export interface GatewayMetadata {
  resourceId: string;
  node: string;
  generation: string;
  expectedFingerprint: string;
  createdAt: string;
}
export interface GatewayEvidence {
  power: "RUNNING" | "STOPPED" | "UNKNOWN";
  ownership: "VALID" | "INVALID" | "UNKNOWN";
  config: "VALID" | "INVALID" | "UNKNOWN";
  heartbeat: "PASS" | "FAIL" | "UNKNOWN";
  policy: "PASS" | "FAIL" | "UNKNOWN";
  reservation: "PASS" | "FAIL" | "UNKNOWN";
  services: "PASS" | "FAIL" | "UNKNOWN";
  canary: "PASS" | "FAIL" | "UNKNOWN";
  generation: string | null;
  configFingerprint: string | null;
  observedAt: string;
}
export interface GatewayHealth {
  resourceId: string;
  node: string;
  status: GatewayNodeStatus;
  observedAt: string;
  generation: string | null;
  expectedFingerprint: string | null;
  evidence: GatewayEvidence;
}
export interface GatewayIncident {
  id: string;
  node: string;
  gatewayId: string | null;
  code: string;
  severity: "warning" | "critical";
  status: "OPEN" | "RESOLVED";
  firstSeenAt: string;
  lastSeenAt: string;
  resolvedAt: string | null;
  message: string;
  guidance: string[];
}
export type GatewaySignal = "PASS" | "FAIL" | "UNKNOWN";
export interface GatewayCertificate {
  fingerprint: string;
  certificatePem: string;
  issuedAt: string;
  expiresAt: string;
  acceptedUntil: string;
}
export interface GatewayIdentity {
  deviceId: string;
  resourceId: string;
  installationId: string;
  generation: string;
  publicKeyPem: string;
  publicKeyFingerprint: string;
  revokedAt: string | null;
  createdAt: string;
  currentCertificate: GatewayCertificate;
  previousCertificate: GatewayCertificate | null;
  nextSequence: number;
  lastSeenAt: string | null;
  lastServices: GatewaySignal | null;
  lastPolicy: GatewaySignal | null;
  lastReservation: GatewaySignal | null;
}
export interface GatewayEnrollmentTokenRecord {
  resourceId: string;
  installationId: string;
  generation: string;
  tokenHash: string;
  expiresAt: string;
  publicKeyFingerprint: string | null;
  deviceId: string | null;
  certificateFingerprint: string | null;
}
export interface GatewayChallenge {
  deviceId: string;
  challengeId: string;
  nonce: string;
  expiresAt: string;
}
export type NetworkProbeJobState = "PENDING" | "COMPLETED" | "TIMED_OUT" | "INVALIDATED" | "CANCELLED";
export type NetworkProbeResultCode = "DNS_ANSWER" | "DNS_EMPTY" | "DNS_ERROR" | "HTTPS_EXPECTED" | "HTTPS_UNEXPECTED" | "HTTPS_REDIRECT" | "HTTPS_ERROR" | "TCP_CONNECTED" | "TCP_FAILED" | "TIMEOUT";
export interface NetworkProbeDnsCheck { id: string; kind: "dns"; hostname: string; resolverAddress: string; resolverPort: number; timeoutMs: number; }
export interface NetworkProbeHttpsCheck { id: string; kind: "https"; url: string; expectedStatus: number; caPem?: string; timeoutMs: number; }
export interface NetworkProbeTcpCheck { id: string; kind: "tcp"; address: string; port: number; expect: "reachable" | "blocked"; timeoutMs: number; }
export type NetworkProbeCheck = NetworkProbeDnsCheck | NetworkProbeHttpsCheck | NetworkProbeTcpCheck;
export interface NetworkProbeProfile { id: string; ttlSeconds: number; checks: NetworkProbeCheck[]; }
export interface NetworkProbePlan { schemaVersion: 1; probeId: string; installationId: string; gatewayId: string; gatewayGeneration: string; gatewayConfigFingerprint: string; profileId: string; profileDigest: string; expiresAt: string; checks: NetworkProbeCheck[]; }
export interface NetworkProbeResult { id: string; code: NetworkProbeResultCode; durationMs: number; }
export interface NetworkProbeRecord { resourceId: string; installationId: string; gatewayId: string; gatewayGeneration: string; gatewayConfigFingerprint: string; node: string; profileId: string; profileDigest: string; plan: NetworkProbePlan; planDigest: string; state: NetworkProbeJobState; tokenHash: string | null; tokenExpiresAt: string | null; resultDigest: string | null; results: NetworkProbeResult[] | null; receivedAt: string | null; createdAt: string; }

export interface OwnershipObservation {
  providerId: string;
  providerResourceId: string;
  providerKind: string;
  kind: ResourceType | null;
  pool: string | null;
  node: string | null;
  tags: string[];
}

export interface Event {
  id: number;
  installationId: string;
  projectId: string | null;
  resourceId: string | null;
  type: string;
  timestamp: string;
  payload: Record<string, unknown>;
}
export interface Operation {
  id: string;
  resourceId: string;
  kind: "create" | "start" | "stop" | "destroy";
  status: "INTENT" | "SUBMITTED" | "COMPLETED" | "UNKNOWN";
  snapshot: OperationSnapshot | null;
  taskHandle: ProviderTaskHandle | null;
  safeReason: OperationSafeReason | null;
  createdAt: string;
  submittedAt: string | null;
  reconciliationDeadline: string | null;
  completedAt: string | null;
}
export type OperationSafeReason = "DISPATCH_UNKNOWN" | "TASK_FAILED" | "TASK_MISSING" | "TASK_UNKNOWN" | "POSTCONDITION_FAILED" | "LEGACY_UNRESOLVED" | "RECOVERED_INTENT";
export interface OperationSnapshot {
  schemaVersion: 1 | 2;
  installationId: string;
  projectId: string;
  resourceId: string;
  type: ResourceType;
  ownership: Ownership;
  providerId: string;
  providerResourceId: string;
  providerKind: string;
  node: string | null;
  pool: string;
  expectedTags: string[];
  action: Operation["kind"];
  provisioningPlanDigest?: string;
  templateImportDigest?: string;
  canonicalDigest: string;
}
export interface ProviderTaskHandle {
  taskId: string;
  providerId: string;
  providerResourceId: string;
  providerKind: string;
  node: string | null;
  action: Operation["kind"];
  workerType?: string;
  snapshotDigest: string;
}
export type ProviderTaskStatus = "RUNNING" | "SUCCEEDED" | "FAILED" | "MISSING" | "MISMATCH" | "UNKNOWN";
export interface ProviderTaskObservation { status: ProviderTaskStatus; }
export interface PublicOperation {
  id: string;
  kind: Operation["kind"];
  status: Operation["status"];
  createdAt: string;
  submittedAt: string | null;
  completedAt: string | null;
  safeReason: OperationSafeReason | null;
}

export function operationSnapshot(resource: Resource, action: Operation["kind"], provisioningPlanDigest?: string, templateImportDigest?: string): OperationSnapshot {
  const binding = {
    schemaVersion: (provisioningPlanDigest || templateImportDigest ? 2 : 1) as 1 | 2,
    installationId: resource.installationId,
    projectId: resource.projectId,
    resourceId: resource.id,
    type: resource.type,
    ownership: resource.ownership,
    providerId: resource.providerId,
    providerResourceId: resource.providerResourceId,
    providerKind: resource.providerKind,
    node: resource.node,
    pool: resource.pool,
    expectedTags: ownershipTags(resource),
    action,
    ...(provisioningPlanDigest ? { provisioningPlanDigest } : {}),
    ...(templateImportDigest ? { templateImportDigest } : {}),
  };
  return { ...binding, canonicalDigest: canonicalSnapshotDigest(binding) };
}
function canonicalSnapshotDigest(binding: Omit<OperationSnapshot, "canonicalDigest">): string {
  return createHash("sha256").update(JSON.stringify({
    schemaVersion: binding.schemaVersion,
    installationId: binding.installationId,
    projectId: binding.projectId,
    resourceId: binding.resourceId,
    type: binding.type,
    ownership: binding.ownership,
    providerId: binding.providerId,
    providerResourceId: binding.providerResourceId,
    providerKind: binding.providerKind,
    node: binding.node,
    pool: binding.pool,
    expectedTags: binding.expectedTags,
    action: binding.action,
    ...(binding.schemaVersion === 2 ? { provisioningPlanDigest: binding.provisioningPlanDigest, templateImportDigest: binding.templateImportDigest } : {}),
  })).digest("hex");
}

export class KilnError extends Error {
  constructor(
    public readonly code: string,
    public readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

const terminal = new Set<ResourceState>(["DESTROYED", "LOST", "QUARANTINED"]);
export function canTransition(from: ResourceState, to: ResourceState): boolean {
  if (from === to || terminal.has(from)) return false;
  return (
    (from === "REQUESTED" && ["PROVISIONING", "ERROR"].includes(to)) ||
    (from === "PROVISIONING" && ["READY", "ERROR", "LOST"].includes(to)) ||
    (from === "READY" &&
      ["STOPPING", "DESTROYING", "LOST", "QUARANTINED"].includes(to)) ||
    (from === "STOPPING" && ["STOPPED", "LOST", "QUARANTINED"].includes(to)) ||
    (from === "STOPPED" &&
      ["READY", "DESTROYING", "LOST", "QUARANTINED"].includes(to)) ||
    (from === "ERROR" && ["DESTROYING", "LOST", "QUARANTINED"].includes(to)) ||
    (from === "DESTROYING" && ["DESTROYED", "LOST", "QUARANTINED"].includes(to))
  );
}

export function ownershipTags(
  resource: Pick<Resource, "installationId" | "type" | "id">,
): string[] {
  return [
    "kiln",
    "kiln-managed",
    `kiln-installation-${resource.installationId}`,
    `kiln-resource-${resource.type}`,
    `kiln-resource-id-${resource.id}`,
  ];
}

function oneTag(
  tags: string[],
  prefix: string,
  expected: string,
  ignoredPrefixes: string[] = [],
): boolean {
  const values = tags.filter(
    (tag) =>
      tag.startsWith(prefix) &&
      !ignoredPrefixes.some((ignored) => tag.startsWith(ignored)),
  );
  return values.length === 1 && values[0] === expected;
}

export function validateOwnership(
  resource: Resource,
  currentInstallationId: string,
  observed: OwnershipObservation,
): void {
  const expected = ownershipTags(resource);
  if (
    (resource.ownership !== "KILN_MANAGED" &&
      resource.ownership !== "IMPORTED") ||
    resource.installationId !== currentInstallationId ||
    resource.pool !== "kiln" ||
    observed.providerId !== resource.providerId ||
    observed.providerResourceId !== resource.providerResourceId ||
    observed.providerKind !== resource.providerKind ||
    observed.kind !== resource.type ||
    observed.pool !== resource.pool ||
    observed.node !== resource.node ||
    !observed.tags.includes("kiln") ||
    !observed.tags.includes("kiln-managed") ||
    !oneTag(observed.tags, "kiln-installation-", expected[2]!) ||
    !oneTag(observed.tags, "kiln-resource-", expected[3]!, [
      "kiln-resource-id-",
    ]) ||
    !oneTag(observed.tags, "kiln-resource-id-", expected[4]!)
  ) {
    throw new KilnError(
      "SAFETY_DENIED",
      403,
      "Resource ownership validation failed",
    );
  }
}

export interface ComputeNode {
  id: string;
  online: boolean;
  cpuFree: number;
  memoryFree: number;
  storage: string[];
  networks: string[];
  images: string[];
}
export interface StorageTarget {
  id: string;
  shared: boolean;
  supportsSnapshots: boolean;
  supportsClones: boolean;
  nodes: string[];
}
export interface ProviderInventory {
  nodes: ComputeNode[];
  storage: StorageTarget[];
  resources: OwnershipObservation[];
}
export interface ProviderMetrics {
  nodeId: string;
  cpuFree: number;
  memoryFree: number;
  observedAt: string;
}

export interface ComputeProvider {
  readonly id: string;
  readonly mode: "fake" | "proxmox-read-only";
  discover(): Promise<ProviderInventory>;
  inspect(providerResourceId: string): Promise<OwnershipObservation | null>;
  metrics(): Promise<ProviderMetrics[]>;
  create(resource: Resource): Promise<OwnershipObservation>;
  start(resource: Resource): Promise<void>;
  stop(resource: Resource): Promise<void>;
  destroy(resource: Resource): Promise<void>;
  submitOperation?(operation: Operation): Promise<ProviderTaskHandle>;
  inspectOperation?(handle: ProviderTaskHandle): Promise<ProviderTaskObservation>;
  inspectPower?(resource: Resource): Promise<"RUNNING" | "STOPPED" | "UNKNOWN">;
  observeGateway?(resource: Resource, metadata: GatewayMetadata): Promise<GatewayEvidence>;
  registerGatewayAttestation?(resource: Resource, metadata: GatewayMetadata): Promise<void>;
  prepareProvisioning?(resource: Resource, plan: ProvisioningPlan): Promise<void>;
  provision?(resource: Resource, plan: ProvisioningPlan): Promise<OwnershipObservation>;
  inspectAttachments?(resource: Resource): Promise<ProvisioningAttachment[] | null>;
  importTemplate?(resource: Resource, attachments: ProvisioningAttachment[]): Promise<OwnershipObservation>;
  prepareTemplateImport?(resource: Resource, template: TemplateImport, templateImportDigest: string): Promise<void>;
}

export interface Store {
  installationId(): Promise<string>;
  initializeInstallation(configuredId?: string): Promise<string>;
  getResource(id: string): Promise<Resource | null>;
  listResources(projectId: string): Promise<Resource[]>;
  createResource(
    resource: Resource,
    idempotencyKey: string,
    normalizedPayload: string,
  ): Promise<{ resource: Resource; replayed: boolean }>;
  importVerifiedImage(input: { image: VerifiedImage; template: TemplateImport; resource: Resource; operation: Operation; attachments: ProvisioningAttachment[]; idempotencyKey: string; normalizedPayload: string; event: Omit<Event, "id"> }): Promise<{ template: TemplateImport; replayed: boolean }>;
  getVerifiedImage(id: string): Promise<VerifiedImage | null>;
  getTemplateImport(resourceId: string): Promise<TemplateImport | null>;
  completeTemplateImport(resource: Resource, templateId: string, operationId: string, event: Omit<Event, "id">): Promise<void>;
  createProvenancedResource(input: { resource: Resource; plan: ProvisioningPlan; idempotencyKey: string; normalizedPayload: string; operation: Operation; event: Omit<Event, "id"> }): Promise<{ resource: Resource; operation: Operation; replayed: boolean }>;
  getProvisioningPlan(resourceId: string): Promise<ProvisioningPlan | null>;
  provenanceSummary(resourceId: string): Promise<SafeProvenanceSummary | null>;
  retireTemplate(resourceId: string, event: Omit<Event, "id">): Promise<void>;
  createNetworkProbe(
    resource: Resource,
    probe: NetworkProbeRecord,
    idempotencyKey: string,
    normalizedPayload: string,
    event: Omit<Event, "id">,
  ): Promise<{ resource: Resource; probe: NetworkProbeRecord; replayed: boolean }>;
  getNetworkProbe(resourceId: string): Promise<NetworkProbeRecord | null>;
  listNetworkProbes(gatewayId?: string): Promise<NetworkProbeRecord[]>;
  issueNetworkProbeToken(resourceId: string, tokenHash: string, tokenExpiresAt: string, event: Omit<Event, "id">): Promise<void>;
  acceptNetworkProbeResult(input: { resourceId: string; planDigest: string; resultDigest: string; results: NetworkProbeResult[]; receivedAt: string; event: Omit<Event, "id"> }): Promise<{ probe: NetworkProbeRecord; replayed: boolean }>;
  timeoutNetworkProbe(resourceId: string, state: Extract<NetworkProbeJobState, "TIMED_OUT" | "INVALIDATED" | "CANCELLED">, event: Omit<Event, "id">): Promise<NetworkProbeRecord | null>;
  completeNetworkProbeOperationTransition(operationId: string, resource: Resource, event: Omit<Event, "id">): Promise<Event>;
  expiredNetworkProbes(now: string): Promise<NetworkProbeRecord[]>;
  idempotentResource(
    idempotencyKey: string,
    normalizedPayload: string,
  ): Promise<Resource | null>;
  updateResource(resource: Resource): Promise<void>;
  appendEvent(event: Omit<Event, "id">): Promise<Event>;
  commitTransition(
    resource: Resource,
    event: Omit<Event, "id">,
  ): Promise<Event>;
  events(projectId: string, after: number): Promise<Event[]>;
  expired(now: string): Promise<Resource[]>;
  beginOperation(operation: { resourceId: string; kind: Operation["kind"]; snapshot?: OperationSnapshot; reconciliationDeadline?: string; event?: Omit<Event, "id"> }): Promise<Operation>;
  listOperations(resourceId: string, limit?: number): Promise<Operation[]>;
  getOperation(id: string): Promise<Operation | null>;
  unresolvedOperation(resourceId: string): Promise<Operation | null>;
  submittedOperations(): Promise<Operation[]>;
  markOperationSubmitted(id: string, handle: ProviderTaskHandle, event: Omit<Event, "id">): Promise<void>;
  completeOperation(id: string): Promise<void>;
  completeOperationTransition(
    id: string,
    resource: Resource,
    event: Omit<Event, "id">,
  ): Promise<Event>;
  markOperationUnknown(id: string, reason?: OperationSafeReason, event?: Omit<Event, "id">): Promise<void>;
  completedOperation(
    resourceId: string,
    kind: Operation["kind"],
  ): Promise<Operation | null>;
  upsertLease(resourceId: string, expiresAt: string): Promise<void>;
  createGateway(
    resource: Resource,
    metadata: GatewayMetadata,
    idempotencyKey: string,
    normalizedPayload: string,
  ): Promise<{ resource: Resource; replayed: boolean }>;
  getGateway(resourceId: string): Promise<GatewayMetadata | null>;
  listGateways(): Promise<Array<{ resource: Resource; metadata: GatewayMetadata; health: GatewayHealth | null }>>;
  saveGatewayScan(
    health: GatewayHealth,
    incidents: GatewayIncident[],
    events: Array<Omit<Event, "id">>,
  ): Promise<void>;
  listGatewayIncidents(node?: string): Promise<GatewayIncident[]>;
  bindGatewayCaFingerprint(fingerprint: string): Promise<void>;
  issueGatewayEnrollmentToken(token: GatewayEnrollmentTokenRecord, event: Omit<Event, "id">): Promise<void>;
  getGatewayEnrollmentToken(resourceId: string): Promise<GatewayEnrollmentTokenRecord | null>;
  getGatewayIdentity(resourceId: string): Promise<GatewayIdentity | null>;
  getGatewayCertificate(fingerprint: string): Promise<GatewayCertificate | null>;
  gatewayIdentityRequired(resourceId: string): Promise<boolean>;
  enrollGatewayIdentity(input: {
    tokenHash: string;
    publicKeyPem: string;
    publicKeyFingerprint: string;
    identity: GatewayIdentity;
    event: Omit<Event, "id">;
    now: string;
  }): Promise<{ identity: GatewayIdentity; certificate: GatewayCertificate; replayed: boolean }>;
  issueGatewayChallenge(input: GatewayChallenge, now: string): Promise<GatewayChallenge>;
  renewGatewayIdentity(input: {
    identity: GatewayIdentity;
    challengeId: string;
    nonce: string;
    event: Omit<Event, "id">;
    now: string;
  }): Promise<GatewayIdentity>;
  revokeGatewayIdentity(resourceId: string, revokedAt: string, event: Omit<Event, "id">): Promise<void>;
  recordGatewayHeartbeat(input: {
    deviceId: string;
    certificateFingerprint: string;
    sequence: number;
    services: GatewaySignal;
    policy: GatewaySignal;
    reservation: GatewaySignal;
    receivedAt: string;
    event: Omit<Event, "id">;
  }): Promise<GatewayIdentity>;
  persistenceKind(): "memory" | "postgres";
  withResourceLock<T>(id: string, task: () => Promise<T>): Promise<T>;
}

export class ProviderOperationExecutor {
  constructor(
    private readonly store: Store,
    private readonly provider: ComputeProvider,
    private readonly clock = () => new Date(),
  ) {}

  async dispatch(
    resource: Resource,
    kind: Operation["kind"],
    eventType: string,
    invoke: () => Promise<void>,
    complete: (operation: Operation) => Promise<void>,
    persistedIntent?: Operation,
  ): Promise<Operation> {
    const provenancePlan = resource.provenanceRequired ? await this.store.getProvisioningPlan(resource.id) : null;
    const template = resource.type === "image_template" ? await this.store.getTemplateImport(resource.id) : null;
    const intent = persistedIntent ?? await this.store.beginOperation({
      resourceId: resource.id,
      kind,
      snapshot: operationSnapshot(resource, kind, provenancePlan?.canonicalDigest, template ? canonicalTemplateImportDigest(template) : undefined),
      reconciliationDeadline: new Date(this.clock().getTime() + 15 * 60_000).toISOString(),
      event: operationEvent(resource, `${eventType}.intent`, { action: kind }, this.clock),
    });
    if (this.provider.submitOperation) {
      try {
        const handle = structuredClone(await this.provider.submitOperation(structuredClone(intent)));
        if (!intent.snapshot || !taskHandleMatches(handle, intent.snapshot))
          throw new KilnError("SAFETY_DENIED", 403, "Provider task receipt does not match the operation binding");
        await this.store.markOperationSubmitted(intent.id, handle, operationEvent(resource, `${eventType}.submitted`, { action: kind, operationId: intent.id }, this.clock));
        return { ...intent, status: "SUBMITTED", taskHandle: structuredClone(handle), submittedAt: this.clock().toISOString() };
      } catch (error) {
        await this.store.markOperationUnknown(intent.id, "DISPATCH_UNKNOWN", operationEvent(resource, `${eventType}.unknown`, { action: kind, operationId: intent.id, reason: "DISPATCH_UNKNOWN" }, this.clock));
        throw error;
      }
    }
    try {
      await invoke();
      await complete(intent);
      return { ...intent, status: "COMPLETED", completedAt: this.clock().toISOString() };
    } catch (error) {
      const persisted = await this.store.getOperation(intent.id);
      if (persisted?.status === "COMPLETED") return persisted;
      await this.store.markOperationUnknown(intent.id, "DISPATCH_UNKNOWN", operationEvent(resource, `${eventType}.unknown`, { action: kind, operationId: intent.id, reason: "DISPATCH_UNKNOWN" }, this.clock));
      resource.state = "ERROR";
      await this.store.commitTransition(resource, operationEvent(resource, "resource.operation_unknown", { action: kind, operationId: intent.id, reason: "DISPATCH_UNKNOWN" }, this.clock));
      throw error;
    }
  }

  async reconcile(
    resourceId: string,
    completeTransition?: (operation: Operation, resource: Resource, event: Omit<Event, "id">) => Promise<void>,
  ): Promise<Operation | null> {
    const operation = await this.store.unresolvedOperation(resourceId);
    if (!operation || operation.status !== "SUBMITTED" || !operation.taskHandle) return operation;
    const resource = await this.store.getResource(resourceId);
    if (!resource || !operation.snapshot || !(await snapshotMatchesCurrent(operation.snapshot, resource, operation.kind, this.store, this.provider)) || !taskHandleMatches(operation.taskHandle, operation.snapshot)) {
      await this.store.markOperationUnknown(operation.id, "POSTCONDITION_FAILED", resource ? operationEvent(resource, "resource.operation_unknown", { operationId: operation.id, reason: "POSTCONDITION_FAILED" }, this.clock) : undefined);
      return this.store.unresolvedOperation(resourceId);
    }
    if (!operation.reconciliationDeadline || Number.isNaN(Date.parse(operation.reconciliationDeadline)) || operation.reconciliationDeadline <= this.clock().toISOString()) {
      await this.store.markOperationUnknown(operation.id, "TASK_UNKNOWN", operationEvent(resource, "resource.operation_unknown", { operationId: operation.id, reason: "TASK_UNKNOWN" }, this.clock));
      return this.store.unresolvedOperation(resourceId);
    }
    if (!this.provider.inspectOperation) return operation;
    let observation: ProviderTaskObservation;
    try {
      observation = await this.provider.inspectOperation(structuredClone(operation.taskHandle));
    } catch {
      return operation;
    }
    if (observation.status === "RUNNING" || observation.status === "UNKNOWN") return operation;
    if (observation.status === "MISMATCH") {
      await this.store.markOperationUnknown(operation.id, "POSTCONDITION_FAILED", operationEvent(resource, "resource.operation_unknown", { operationId: operation.id, reason: "POSTCONDITION_FAILED" }, this.clock));
      return this.store.unresolvedOperation(resourceId);
    }
    if (observation.status !== "SUCCEEDED") {
      const reason: OperationSafeReason = observation.status === "FAILED" ? "TASK_FAILED" : "TASK_MISSING";
      await this.store.markOperationUnknown(operation.id, reason, operationEvent(resource, "resource.operation_unknown", { operationId: operation.id, reason }, this.clock));
      return this.store.unresolvedOperation(resourceId);
    }
    if (this.provider.mode !== "fake") {
      await this.store.markOperationUnknown(operation.id, "POSTCONDITION_FAILED", operationEvent(resource, "resource.operation_unknown", { operationId: operation.id, reason: "POSTCONDITION_FAILED" }, this.clock));
      return this.store.unresolvedOperation(resourceId);
    }
    try {
      const current = await this.provider.inspect(resource.providerResourceId);
      if (operation.kind === "destroy") {
        if (current) {
          try { validateOwnership(resource, await this.store.installationId(), current); } catch {
            await this.store.markOperationUnknown(operation.id, "POSTCONDITION_FAILED", operationEvent(resource, "resource.operation_unknown", { operationId: operation.id, reason: "POSTCONDITION_FAILED" }, this.clock));
            return this.store.unresolvedOperation(resourceId);
          }
          return operation;
        }
        resource.state = "DESTROYED";
      } else {
        if (!current) return operation;
        try { validateOwnership(resource, await this.store.installationId(), current); } catch {
          await this.store.markOperationUnknown(operation.id, "POSTCONDITION_FAILED", operationEvent(resource, "resource.operation_unknown", { operationId: operation.id, reason: "POSTCONDITION_FAILED" }, this.clock));
          return this.store.unresolvedOperation(resourceId);
        }
        const expectedPower = operation.kind === "stop" ? "STOPPED" : "RUNNING";
        if (!this.provider.inspectPower || await this.provider.inspectPower(structuredClone(resource)) !== expectedPower) return operation;
        resource.state = operation.kind === "stop" ? "STOPPED" : "READY";
      }
    } catch {
      return operation;
    }
    const plan = resource.provenanceRequired && resource.type !== "image_template" ? await this.store.getProvisioningPlan(resource.id) : null;
    if (!await operationBindingMatches(operation, resource, this.store, this.provider) || (resource.type === "image_template" && !await templateImportBindingMatches(resource, this.store, this.provider)) || (plan && !await templateSourceMatchesPlan(plan, this.store, this.provider)) || (operation.kind !== "destroy" && !await provenanceGraphMatches(resource, this.store, this.provider))) {
      await this.store.markOperationUnknown(operation.id, "POSTCONDITION_FAILED", operationEvent(resource, "resource.operation_unknown", { operationId: operation.id, reason: "POSTCONDITION_FAILED" }, this.clock));
      return this.store.unresolvedOperation(resourceId);
    }
    const event = operationEvent(resource, `resource.${operation.kind}_completed`, { operationId: operation.id }, this.clock);
    try {
      if (completeTransition) await completeTransition(operation, resource, event);
      else await this.store.completeOperationTransition(operation.id, resource, event);
    } catch {
      await this.store.markOperationUnknown(operation.id, "POSTCONDITION_FAILED", operationEvent(resource, "resource.operation_unknown", { operationId: operation.id, reason: "POSTCONDITION_FAILED" }, this.clock));
    }
    return this.store.unresolvedOperation(resourceId);
  }
}

function taskHandleMatches(handle: ProviderTaskHandle, snapshot: OperationSnapshot): boolean {
  return handle.providerId === snapshot.providerId && handle.providerResourceId === snapshot.providerResourceId && handle.providerKind === snapshot.providerKind && handle.node === snapshot.node && handle.action === snapshot.action && handle.snapshotDigest === snapshot.canonicalDigest;
}

async function snapshotMatchesCurrent(snapshot: OperationSnapshot, resource: Resource, kind: Operation["kind"], store: Store, provider: ComputeProvider): Promise<boolean> {
  const plan = resource.provenanceRequired ? await store.getProvisioningPlan(resource.id) : null;
  const template = resource.type === "image_template" ? await store.getTemplateImport(resource.id) : null;
  const expected = operationSnapshot(resource, kind, plan?.canonicalDigest, template ? canonicalTemplateImportDigest(template) : undefined);
  const { canonicalDigest, ...binding } = snapshot;
  return snapshot.schemaVersion === expected.schemaVersion && resource.installationId === await store.installationId() && resource.providerId === provider.id && canonicalDigest === canonicalSnapshotDigest(binding) && snapshot.installationId === expected.installationId && snapshot.projectId === expected.projectId && snapshot.resourceId === expected.resourceId && snapshot.type === expected.type && snapshot.ownership === expected.ownership && snapshot.providerId === expected.providerId && snapshot.providerResourceId === expected.providerResourceId && snapshot.providerKind === expected.providerKind && snapshot.node === expected.node && snapshot.pool === expected.pool && snapshot.action === expected.action && snapshot.provisioningPlanDigest === expected.provisioningPlanDigest && snapshot.templateImportDigest === expected.templateImportDigest && snapshot.expectedTags.length === expected.expectedTags.length && snapshot.expectedTags.every((tag, index) => tag === expected.expectedTags[index]);
}

export async function operationBindingMatches(
  operation: Operation,
  resource: Resource,
  store: Store,
  provider: ComputeProvider,
): Promise<boolean> {
  return Boolean(
    operation.snapshot &&
      await snapshotMatchesCurrent(
        operation.snapshot,
        resource,
        operation.kind,
        store,
        provider,
      ),
  );
}

export async function provenanceGraphMatches(
  resource: Resource,
  store: Store,
  provider: ComputeProvider,
): Promise<boolean> {
  if (!resource.provenanceRequired) return true;
  if (resource.type === "image_template") {
    const template = await store.getTemplateImport(resource.id);
    if (!template || !validAttachmentGraph(template.attachments) || !provider.inspectAttachments) return false;
    const observed = await provider.inspectAttachments(structuredClone(resource));
    return Boolean(observed && canonicalAttachmentGraph(observed) === canonicalAttachmentGraph(template.attachments));
  }
  const plan = await store.getProvisioningPlan(resource.id);
  if (!plan || !validAttachmentGraph(plan.attachments) || plan.canonicalDigest !== canonicalPlanDigest({ ...plan, canonicalDigest: undefined } as Omit<ProvisioningPlan, "canonicalDigest">)) return false;
  if (plan.resourceId !== resource.id || plan.providerId !== resource.providerId || plan.providerKind !== resource.providerKind || plan.providerResourceId !== resource.providerResourceId || plan.node !== resource.node || plan.pool !== resource.pool || plan.cloneMode !== "FULL") return false;
  if (!provider.inspectAttachments) return false;
  const observed = await provider.inspectAttachments(structuredClone(resource));
  if (!observed || !validAttachmentGraph(observed)) return false;
  return canonicalAttachmentGraph(observed) === canonicalAttachmentGraph(plan.attachments);
}

async function templateImportBindingMatches(
  resource: Resource,
  store: Store,
  provider: ComputeProvider,
): Promise<boolean> {
  const template = await store.getTemplateImport(resource.id);
  if (!template || template.resourceId !== resource.id || template.providerId !== resource.providerId || template.providerKind !== resource.providerKind || template.providerResourceId !== resource.providerResourceId || template.node !== resource.node || template.pool !== resource.pool || !validAttachmentGraph(template.attachments)) return false;
  const image = await store.getVerifiedImage(template.imageId);
  if (!image || image.manifestDigest !== template.imageManifestDigest || sha256(canonicalImageManifest(image.manifest)) !== image.manifestDigest) return false;
  if (image.manifest.capabilities.length !== template.capabilities.length || image.manifest.capabilities.some((capability, index) => capability !== template.capabilities[index])) return false;
  const observed = provider.inspectAttachments ? await provider.inspectAttachments(structuredClone(resource)) : null;
  return Boolean(observed && validAttachmentGraph(observed) && canonicalAttachmentGraph(observed) === canonicalAttachmentGraph(template.attachments));
}

async function templateSourceMatchesPlan(
  plan: ProvisioningPlan,
  store: Store,
  provider: ComputeProvider,
): Promise<boolean> {
  const template = await store.getTemplateImport(plan.templateResourceId);
  const source = await store.getResource(plan.templateResourceId);
  if (!template || !source || source.id !== plan.templateResourceId || source.type !== "image_template" || source.ownership !== "KILN_MANAGED" || source.installationId !== await store.installationId() || source.providerId !== plan.templateProviderId || source.providerKind !== plan.templateProviderKind || source.providerResourceId !== plan.templateProviderResourceId || source.node !== plan.templateNode || source.pool !== plan.templatePool || template.state !== "READY" || template.nonce !== plan.templateNonce || canonicalTemplateImportDigest(template) !== plan.templateIntentDigest || template.imageManifestDigest !== plan.imageManifestDigest || template.providerId !== plan.templateProviderId || template.providerKind !== plan.templateProviderKind || template.providerResourceId !== plan.templateProviderResourceId || template.node !== plan.templateNode || template.pool !== plan.templatePool || canonicalAttachmentGraph(template.attachments) !== canonicalAttachmentGraph(plan.templateAttachments)) return false;
  const observed = await provider.inspect(source.providerResourceId);
  if (!observed || !provider.inspectAttachments) return false;
  try { validateOwnership(source, await store.installationId(), observed); } catch { return false; }
  const graph = await provider.inspectAttachments(structuredClone(source));
  return Boolean(graph && validAttachmentGraph(graph) && canonicalAttachmentGraph(graph) === canonicalAttachmentGraph(plan.templateAttachments));
}

export class ImageProvenanceService {
  constructor(
    private readonly store: Store,
    private readonly provider: ComputeProvider,
    private readonly trustedKeys: import("./provenance.js").TrustedImageKeys,
    private readonly clock = () => new Date(),
  ) {}
  async importImage(request: import("./provenance.js").ImageImportRequest, idempotencyKey: string, createdBy: string, requestedNode?: string): Promise<{ template: TemplateImport; replayed: boolean }> {
    if (this.provider.mode !== "fake") throw new KilnError("UNSUPPORTED", 501, "Image import is only available with the fake provider in Stage 1");
    const now = this.clock().toISOString();
    let image: VerifiedImage;
    try { image = (await import("./provenance.js")).verifyImageImport(request, this.trustedKeys, now); }
    catch (error) { throw new KilnError("INVALID_INPUT", 400, error instanceof Error ? error.message : "Image import is invalid"); }
    const installationId = await this.store.installationId();
    const importKey = `${installationId}:image-import:${idempotencyKey}`;
    const normalizedPayload = JSON.stringify({ manifest: image.manifest, signature: request.signature, artifactDigest: image.manifest.artifactSha256, node: requestedNode ?? null });
    const replay = await this.store.idempotentResource(importKey, normalizedPayload);
    if (replay) {
      const template = await this.store.getTemplateImport(replay.id);
      if (!template) throw new Error("Image import idempotency record is incomplete");
      return { template, replayed: true };
    }
    const inventory = await this.provider.discover();
    const node = requestedNode ?? inventory.nodes[0]?.id;
    if (!node || !inventory.nodes.some((candidate) => candidate.id === node && candidate.online)) throw new KilnError("SAFETY_DENIED", 403, "Template node is unavailable");
    const resourceId = `tmpl_${crypto.randomUUID().replaceAll("-", "")}`;
    const nonce = crypto.randomUUID();
    const resource: Resource = { id: resourceId, installationId, projectId: "infrastructure", type: "image_template", ownership: "KILN_MANAGED", state: "PROVISIONING", providerId: this.provider.id, providerResourceId: `template_${resourceId}`, providerKind: "fake", node, pool: "kiln", createdBy, createdAt: now, expiresAt: null, profile: null, provenanceRequired: true };
    const attachments: ProvisioningAttachment[] = [
      { id: "boot", class: "BOOT_VOLUME", ownership: "OWNED_CHILD", nativeId: `template-boot-${resourceId}`, attributes: { role: "boot", writable: true } },
      { id: "cloud-init", class: "CLOUD_INIT", ownership: "OWNED_CHILD", nativeId: `template-cloud-${resourceId}`, attributes: { writable: true } },
      { id: "efi", class: "EFI", ownership: "OWNED_CHILD", nativeId: `template-efi-${resourceId}`, attributes: { writable: true } },
      { id: "tpm", class: "TPM", ownership: "OWNED_CHILD", nativeId: `template-tpm-${resourceId}`, attributes: { writable: true } },
      { id: "nic0", class: "NIC", ownership: "OWNED_CHILD", nativeId: `template-nic-${resourceId}`, attributes: { model: "virtio" } },
      { id: "firewall", class: "FIREWALL", ownership: "EXTERNAL_REFERENCE", nativeId: "firewall:enabled", attributes: { enabled: true } },
      { id: "ha", class: "HA", ownership: "EXTERNAL_REFERENCE", nativeId: "ha:none", attributes: { enabled: false } },
      { id: "storage", class: "STORAGE_REFERENCE", ownership: "EXTERNAL_REFERENCE", nativeId: "storage:kiln", attributes: { writable: false } },
      { id: "bridge", class: "BRIDGE_REFERENCE", ownership: "EXTERNAL_REFERENCE", nativeId: "bridge:fake0", attributes: { writable: false } },
    ];
    if (!validAttachmentGraph(attachments)) throw new Error("Generated template attachment graph is invalid");
    const template: TemplateImport = { resourceId, imageId: image.id, imageManifestDigest: image.manifestDigest, capabilities: image.manifest.capabilities, nonce, providerId: resource.providerId, providerKind: resource.providerKind, providerResourceId: resource.providerResourceId, node, pool: resource.pool, attachments, state: "UNKNOWN", createdAt: now };
    const operation: Operation = { id: crypto.randomUUID(), resourceId, kind: "create", status: "INTENT", snapshot: operationSnapshot(resource, "create", undefined, canonicalTemplateImportDigest(template)), taskHandle: null, safeReason: null, createdAt: now, submittedAt: null, reconciliationDeadline: new Date(this.clock().getTime() + 15 * 60_000).toISOString(), completedAt: null };
    const saved = await this.store.importVerifiedImage({ image, template, resource, operation, attachments, idempotencyKey: importKey, normalizedPayload, event: { installationId, projectId: "infrastructure", resourceId, type: "image.template_import_intent", timestamp: now, payload: { imageManifestDigest: image.manifestDigest, signerFingerprint: image.signerFingerprint, policyDigest: image.policyDigest } } });
    if (saved.replayed) return saved;
    try { await this.provider.prepareTemplateImport?.(structuredClone(resource), structuredClone(template), canonicalTemplateImportDigest(template)); }
    catch (error) { await this.store.markOperationUnknown(operation.id, "DISPATCH_UNKNOWN"); throw error; }
    const executor = new ProviderOperationExecutor(this.store, this.provider, this.clock);
    await executor.dispatch(resource, "create", "image.template_import", async () => {
      if (!this.provider.importTemplate) throw new KilnError("UNSUPPORTED", 501, "Provider does not support template import");
      await this.provider.importTemplate(structuredClone(resource), structuredClone(attachments));
    }, async (current) => {
      if (!await templateImportBindingMatches(resource, this.store, this.provider)) throw new KilnError("SAFETY_DENIED", 403, "Template import binding changed before completion");
      const observed = await this.provider.inspect(resource.providerResourceId);
      const graph = this.provider.inspectAttachments ? await this.provider.inspectAttachments(structuredClone(resource)) : null;
      if (!observed || !graph || canonicalAttachmentGraph(graph) !== canonicalAttachmentGraph(attachments)) throw new KilnError("SAFETY_DENIED", 403, "Template import observation does not match its intent");
      validateOwnership(resource, installationId, observed);
      resource.state = "READY";
      await this.store.completeTemplateImport(resource, resourceId, current.id, { installationId, projectId: "infrastructure", resourceId, type: "image.template_imported", timestamp: this.clock().toISOString(), payload: { imageManifestDigest: image.manifestDigest } });
    }, operation);
    return { template: (await this.store.getTemplateImport(resourceId))!, replayed: false };
  }
  async retireTemplate(resourceId: string): Promise<void> {
    const template = await this.store.getTemplateImport(resourceId);
    if (!template) throw new KilnError("NOT_FOUND", 404, "Template was not found");
    await this.store.retireTemplate(resourceId, { installationId: await this.store.installationId(), projectId: "infrastructure", resourceId, type: "image.template_retired", timestamp: this.clock().toISOString(), payload: {} });
  }
}

function operationEvent(resource: Resource, type: string, payload: Record<string, unknown>, clock: () => Date): Omit<Event, "id"> {
  return { installationId: resource.installationId, projectId: resource.projectId, resourceId: resource.id, type, timestamp: clock().toISOString(), payload };
}

function managedAttachmentGraph(resourceId: string): ProvisioningAttachment[] {
  const attachments: ProvisioningAttachment[] = [
    { id: "boot", class: "BOOT_VOLUME", ownership: "OWNED_CHILD", nativeId: `disk-${resourceId}`, attributes: { role: "boot", writable: true } },
    { id: "cloud-init", class: "CLOUD_INIT", ownership: "OWNED_CHILD", nativeId: `cloud-${resourceId}`, attributes: { writable: true } },
    { id: "efi", class: "EFI", ownership: "OWNED_CHILD", nativeId: `efi-${resourceId}`, attributes: { writable: true } },
    { id: "tpm", class: "TPM", ownership: "OWNED_CHILD", nativeId: `tpm-${resourceId}`, attributes: { writable: true } },
    { id: "unused", class: "UNUSED_VOLUME", ownership: "OWNED_CHILD", nativeId: `unused-${resourceId}`, attributes: { writable: true } },
    { id: "nic0", class: "NIC", ownership: "OWNED_CHILD", nativeId: `nic-${resourceId}`, attributes: { model: "virtio" } },
    { id: "firewall", class: "FIREWALL", ownership: "EXTERNAL_REFERENCE", nativeId: "firewall:enabled", attributes: { enabled: true } },
    { id: "ha", class: "HA", ownership: "EXTERNAL_REFERENCE", nativeId: "ha:none", attributes: { enabled: false } },
    { id: "storage", class: "STORAGE_REFERENCE", ownership: "EXTERNAL_REFERENCE", nativeId: "storage:kiln", attributes: { writable: false } },
    { id: "bridge", class: "BRIDGE_REFERENCE", ownership: "EXTERNAL_REFERENCE", nativeId: "bridge:fake0", attributes: { writable: false } },
  ];
  if (!validAttachmentGraph(attachments)) throw new Error("Generated provisioning attachment graph is invalid");
  return attachments;
}

export class ResourceService {
  constructor(
    private readonly store: Store,
    private readonly provider: ComputeProvider,
    private readonly clock = () => new Date(),
  ) {}
  async create(
    input: {
      type: ResourceType;
      projectId: string;
      ttlSeconds: number;
      profile?: string;
      templateId?: string;
    },
    key: string,
    createdBy: string,
  ): Promise<{ resource: Resource; replayed: boolean }> {
    if (input.type === "gateway" || input.type === "network_probe" || input.type === "image_template")
      throw new KilnError(
        "SAFETY_DENIED",
        403,
        "Protected infrastructure resources require the dedicated administration API",
      );
    if (this.provider.mode !== "fake")
      throw new KilnError(
        "UNSUPPORTED",
        501,
        "Live provider mutations are disabled in Phase 1",
      );
    return this.store.withResourceLock(`create:${key}`, async () =>
      this.createLocked(input, key, createdBy),
    );
  }
  private async createLocked(
    input: {
      type: ResourceType;
      projectId: string;
      ttlSeconds: number;
      profile?: string;
      templateId?: string;
    },
    key: string,
    createdBy: string,
  ): Promise<{ resource: Resource; replayed: boolean }> {
    const installationId = await this.store.installationId();
    const normalized = JSON.stringify({
      installationId,
      projectId: input.projectId,
      type: input.type,
      ttlSeconds: input.ttlSeconds,
      profile: input.profile ?? null,
      templateId: input.templateId ?? null,
    });
    const idempotencyKey = `${installationId}:${input.projectId}:${key}`;
    const replay = await this.store.idempotentResource(idempotencyKey, normalized);
    if (replay) return { resource: replay, replayed: true };
    const now = this.clock();
    const gateways = await this.store.listGateways();
    const configuredGateways = gateways.filter(
      (gateway) => gateway.resource.providerId === this.provider.id,
    );
    if (await Promise.all(configuredGateways.map((gateway) => this.store.unresolvedOperation(gateway.resource.id))).then((operations) => operations.some(Boolean)))
      throw new KilnError("NETWORK_NOT_READY", 409, "A configured gateway has an unresolved provider operation");
    const inventory = configuredGateways.length ? await this.provider.discover() : null;
    const identityRequired = new Map(await Promise.all(configuredGateways.map(async (gateway) => [gateway.resource.id, await this.store.gatewayIdentityRequired(gateway.resource.id)] as const)));
    const eligibleGateway = configuredGateways.find(
      (gateway) => !identityRequired.get(gateway.resource.id) && gatewayReady(gateway, inventory?.nodes ?? [], now),
    );
    if (configuredGateways.length > 0 && !eligibleGateway)
      throw new KilnError(
        "NETWORK_NOT_READY",
        409,
        "No configured node has a fresh ready gateway",
      );
    if (!eligibleGateway) return this.createWithNode(input, idempotencyKey, normalized, createdBy, installationId, now, null);
    return this.store.withResourceLock(`gateway-admission:${eligibleGateway.resource.id}`, async () => {
      const current = (await this.store.listGateways()).find(
        (gateway) => gateway.resource.id === eligibleGateway.resource.id,
      );
      const currentInventory = await this.provider.discover();
      if (!current || await this.store.gatewayIdentityRequired(current.resource.id) || !gatewayReady(current, currentInventory.nodes, this.clock()))
        throw new KilnError("NETWORK_NOT_READY", 409, "No configured node has a fresh ready gateway");
      const replayInsideLock = await this.store.idempotentResource(idempotencyKey, normalized);
      if (replayInsideLock) return { resource: replayInsideLock, replayed: true };
      return this.createWithNode(input, idempotencyKey, normalized, createdBy, installationId, now, current.metadata.node);
    });
  }
  private async createWithNode(
    input: { type: ResourceType; projectId: string; ttlSeconds: number; profile?: string; templateId?: string },
    idempotencyKey: string,
    normalized: string,
    createdBy: string,
    installationId: string,
    now: Date,
    node: string | null,
  ): Promise<{ resource: Resource; replayed: boolean }> {
    const id = `${input.type === "development" ? "dev" : input.type === "execution" ? "run" : "br"}_${crypto.randomUUID().replaceAll("-", "")}`;
    const resource: Resource = {
      id,
      installationId,
      projectId: input.projectId,
      type: input.type,
      ownership: "KILN_MANAGED",
      state: "PROVISIONING",
      providerId: this.provider.id,
      providerResourceId: id,
      providerKind: "fake",
      node,
      pool: "kiln",
      createdBy,
      createdAt: now.toISOString(),
      expiresAt: new Date(
        now.getTime() + input.ttlSeconds * 1000,
      ).toISOString(),
      profile: input.profile ?? null,
      ...(input.templateId ? { provenanceRequired: true } : {}),
    };
    if (input.templateId) {
      return this.createFromTemplate(resource, input.templateId, idempotencyKey, normalized, installationId, now);
    }
    const result = await this.store.createResource(
      resource,
      idempotencyKey,
      normalized,
    );
    if (!result.replayed) {
      const executor = new ProviderOperationExecutor(this.store, this.provider, this.clock);
      let createdObservation: OwnershipObservation | null = null;
      await executor.dispatch(
        result.resource,
        "create",
        "resource.create",
        async () => { createdObservation = await this.provider.create(structuredClone(result.resource)); },
        async (operation) => {
          const observed = createdObservation ?? await this.provider.inspect(result.resource.providerResourceId);
          if (!observed) throw new KilnError("SAFETY_DENIED", 403, "Provider resource is missing after create");
          validateOwnership(result.resource, installationId, observed);
          if (!await operationBindingMatches(operation, result.resource, this.store, this.provider))
            throw new KilnError("SAFETY_DENIED", 403, "Provider operation binding changed before completion");
          result.resource.state = "READY";
          await this.completeTransition(operation.id, result.resource, "resource.created", { operationId: operation.id });
        },
      );
    }
    return result;
  }
  private async createFromTemplate(resource: Resource, templateId: string, idempotencyKey: string, normalized: string, installationId: string, now: Date): Promise<{ resource: Resource; replayed: boolean }> {
    const template = await this.store.getTemplateImport(templateId);
    const templateResource = await this.store.getResource(templateId);
    if (!template || template.state !== "READY" || !templateResource || templateResource.type !== "image_template" || !template.capabilities.includes(resource.type)) throw new KilnError("SAFETY_DENIED", 403, "Template is not eligible for this provisioning request");
    const sourceObservation = await this.provider.inspect(template.providerResourceId);
    const sourceAttachments = this.provider.inspectAttachments ? await this.provider.inspectAttachments(structuredClone(templateResource)) : null;
    if (!sourceObservation || !sourceAttachments || canonicalAttachmentGraph(sourceAttachments) !== canonicalAttachmentGraph(template.attachments)) throw new KilnError("SAFETY_DENIED", 403, "Template configuration no longer matches its import");
    validateOwnership(templateResource, installationId, sourceObservation);
    const attachments = managedAttachmentGraph(resource.id);
    const planWithoutDigest: Omit<ProvisioningPlan, "canonicalDigest"> = { schemaVersion: 1, resourceId: resource.id, templateResourceId: template.resourceId, templateNonce: template.nonce, templateIntentDigest: canonicalTemplateImportDigest(template), imageManifestDigest: template.imageManifestDigest, templateProviderId: template.providerId, templateProviderKind: template.providerKind, templateProviderResourceId: template.providerResourceId, templateNode: template.node, templatePool: template.pool, templateAttachments: structuredClone(template.attachments), destinationNonce: crypto.randomUUID(), providerId: resource.providerId, providerKind: resource.providerKind, providerResourceId: resource.providerResourceId, node: resource.node, pool: resource.pool, cloneMode: "FULL", attachments, createdAt: now.toISOString() };
    const plan: ProvisioningPlan = { ...planWithoutDigest, canonicalDigest: canonicalPlanDigest(planWithoutDigest) };
    const operation: Operation = { id: crypto.randomUUID(), resourceId: resource.id, kind: "create", status: "INTENT", snapshot: operationSnapshot(resource, "create", plan.canonicalDigest), taskHandle: null, safeReason: null, createdAt: now.toISOString(), submittedAt: null, reconciliationDeadline: new Date(this.clock().getTime() + 15 * 60_000).toISOString(), completedAt: null };
    const stored = await this.store.createProvenancedResource({ resource, plan, idempotencyKey, normalizedPayload: normalized, operation, event: operationEvent(resource, "resource.create.intent", { action: "create", planDigest: plan.canonicalDigest }, this.clock) });
    if (stored.replayed) return { resource: stored.resource, replayed: true };
    try { await this.provider.prepareProvisioning?.(structuredClone(resource), structuredClone(plan)); }
    catch (error) { await this.store.markOperationUnknown(operation.id, "DISPATCH_UNKNOWN", operationEvent(resource, "resource.create.unknown", { reason: "DISPATCH_UNKNOWN" }, this.clock)); throw error; }
    const executor = new ProviderOperationExecutor(this.store, this.provider, this.clock);
    let createdObservation: OwnershipObservation | null = null;
    await executor.dispatch(resource, "create", "resource.create", async () => {
      if (!this.provider.provision) throw new KilnError("UNSUPPORTED", 501, "Provider does not support provenance provisioning");
      createdObservation = await this.provider.provision(structuredClone(resource), structuredClone(plan));
    }, async (current) => {
      const observed = createdObservation ?? await this.provider.inspect(resource.providerResourceId);
      if (!observed || !await provenanceGraphMatches(resource, this.store, this.provider) || !await templateSourceMatchesPlan(plan, this.store, this.provider) || !await operationBindingMatches(current, resource, this.store, this.provider)) throw new KilnError("SAFETY_DENIED", 403, "Provisioned resource does not match its plan");
      validateOwnership(resource, installationId, observed);
      resource.state = "READY";
      await this.completeTransition(current.id, resource, "resource.created", { operationId: current.id, planDigest: plan.canonicalDigest });
    }, stored.operation);
    return { resource, replayed: false };
  }
  async mutate(
    id: string,
    operation: "start" | "stop" | "destroy",
    projectId: string,
    requireExpired = false,
  ): Promise<Resource> {
    if (this.provider.mode !== "fake")
      throw new KilnError(
        "UNSUPPORTED",
        501,
        "Live provider mutations are disabled in Phase 1",
      );
    return this.store.withResourceLock(id, async () => {
      const resource = await this.requireResource(id, projectId);
      this.rejectGatewayMutation(resource);
      await this.rejectUnresolved(resource);
      await this.guardProvenance(resource);
      if (
        requireExpired &&
        (resource.expiresAt === null ||
          resource.expiresAt > this.clock().toISOString())
      )
        return resource;
      const target: ResourceState =
        operation === "start"
          ? "READY"
          : operation === "stop"
            ? "STOPPED"
            : "DESTROYED";
      if (resource.state === "DESTROYED" && operation === "destroy") {
        if (await this.store.completedOperation(resource.id, "destroy"))
          return resource;
        throw new KilnError(
          "SAFETY_DENIED",
          403,
          "Destroyed resource has no verified terminal operation",
        );
      }
      if (resource.state === target && operation !== "start") return resource;
      if (
        !canTransition(
          resource.state,
          operation === "start"
            ? "READY"
            : operation === "stop"
              ? "STOPPING"
              : "DESTROYING",
        )
      )
        throw new KilnError(
          "CONFLICT",
          409,
          "Resource state does not allow this operation",
        );
      const observation = await this.provider.inspect(
        resource.providerResourceId,
      );
      if (!observation) {
        resource.state = "LOST";
        await this.transition(resource, "resource.lost", {});
        throw new KilnError(
          "SAFETY_DENIED",
          403,
          "Provider resource is missing",
        );
      }
      try {
        validateOwnership(
          resource,
          await this.store.installationId(),
          observation,
        );
      } catch (error) {
        resource.state = "QUARANTINED";
        await this.transition(resource, "resource.safety_denied", {
          operation,
        });
        throw error;
      }
      const interim: ResourceState =
        operation === "stop"
          ? "STOPPING"
          : operation === "destroy"
            ? "DESTROYING"
            : "READY";
      if (interim !== "READY") {
        resource.state = interim;
      }
      const executor = new ProviderOperationExecutor(this.store, this.provider, this.clock);
      await executor.dispatch(
        resource,
        operation,
        `resource.${operation}`,
        async () => { await this.provider[operation](structuredClone(resource)); },
        async (operationRecord) => {
          const observed = await this.provider.inspect(resource.providerResourceId);
          if (operation === "destroy") {
            if (observed) throw new KilnError("SAFETY_DENIED", 403, "Destroyed provider resource still exists");
          } else {
            if (!observed) throw new KilnError("SAFETY_DENIED", 403, "Provider resource is missing after mutation");
            validateOwnership(resource, await this.store.installationId(), observed);
            const expectedPower = operation === "stop" ? "STOPPED" : "RUNNING";
            if (!this.provider.inspectPower || await this.provider.inspectPower(structuredClone(resource)) !== expectedPower)
              throw new KilnError("SAFETY_DENIED", 403, "Provider power state does not satisfy the operation");
          }
          if (!await operationBindingMatches(operationRecord, resource, this.store, this.provider))
            throw new KilnError("SAFETY_DENIED", 403, "Provider operation binding changed before completion");
          resource.state = target;
          const completedEvent = {
            installationId: resource.installationId,
            projectId: resource.projectId,
            resourceId: resource.id,
            type: `resource.${operation}ped`.replace("startped", "started").replace("destroyped", "destroyed"),
            timestamp: this.clock().toISOString(),
            payload: { operationId: operationRecord.id },
          };
          if (resource.type === "network_probe" && (operation === "stop" || operation === "destroy"))
            await this.store.completeNetworkProbeOperationTransition(operationRecord.id, resource, completedEvent);
          else await this.store.completeOperationTransition(operationRecord.id, resource, completedEvent);
        },
      );
      return resource;
    });
  }
  async extend(
    id: string,
    projectId: string,
    ttlSeconds: number,
  ): Promise<Resource> {
    if (this.provider.mode !== "fake")
      throw new KilnError(
        "UNSUPPORTED",
        501,
        "Live provider mutations are disabled in Phase 1",
      );
    return this.store.withResourceLock(id, async () => {
      const resource = await this.requireResource(id, projectId);
      this.rejectGatewayMutation(resource);
      await this.rejectUnresolved(resource);
      await this.guardProvenance(resource);
      if (resource.type === "network_probe")
        throw new KilnError("SAFETY_DENIED", 403, "Network probe leases are fixed by their configured profile");
      if (resource.state !== "READY" && resource.state !== "STOPPED")
        throw new KilnError("CONFLICT", 409, "Resource cannot be extended");
      const now = this.clock().getTime();
      const base = Math.max(
        now,
        resource.expiresAt ? Date.parse(resource.expiresAt) : now,
      );
      const bounded = new Date(now + 86400 * 1000).getTime();
      if (base + ttlSeconds * 1000 > bounded)
        throw new KilnError(
          "CONFLICT",
          409,
          "Lease exceeds the maximum expiry window",
        );
      resource.expiresAt = new Date(base + ttlSeconds * 1000).toISOString();
      await this.transition(resource, "lease.extended", { ttlSeconds });
      return resource;
    });
  }
  async operationHistory(id: string, projectId: string): Promise<PublicOperation[]> {
    const resource = await this.requireResource(id, projectId);
    return (await this.store.listOperations(resource.id, 100)).map((operation) => ({
      id: operation.id,
      kind: operation.kind,
      status: operation.status,
      createdAt: operation.createdAt,
      submittedAt: operation.submittedAt,
      completedAt: operation.completedAt,
      safeReason: operation.safeReason,
    }));
  }
  async expire(): Promise<void> {
    for (const resource of await this.store.expired(
      this.clock().toISOString(),
    )) {
      if (resource.type === "network_probe") continue;
      try {
        await this.mutate(resource.id, "destroy", resource.projectId, true);
      } catch (error) {
        if (error instanceof KilnError && error.code === "OPERATION_UNRESOLVED") continue;
        try {
          await this.store.appendEvent({
            installationId: resource.installationId,
            projectId: resource.projectId,
            resourceId: resource.id,
            type: "lease.cleanup_failed",
            timestamp: this.clock().toISOString(),
            payload: {
              code: error instanceof KilnError ? error.code : "PROVIDER_FAILURE",
            },
          });
        } catch {
          console.error("kiln lease cleanup audit persistence failed");
          /* persistence failure must not stop other lease checks */
        }
      }
    }
  }
  async reconcileOperations(): Promise<void> {
    const executor = new ProviderOperationExecutor(this.store, this.provider, this.clock);
    for (const operation of await this.store.submittedOperations()) {
      const resource = await this.store.getResource(operation.resourceId);
      if (resource?.type === "gateway") continue;
      await this.store.withResourceLock(operation.resourceId, async () => {
        if (resource && operation.kind !== "create" && operation.kind !== "destroy" && !await this.provenanceValid(resource)) {
          await this.store.markOperationUnknown(operation.id, "POSTCONDITION_FAILED", operationEvent(resource, "resource.operation_unknown", { operationId: operation.id, reason: "POSTCONDITION_FAILED" }, this.clock));
          return;
        }
        await executor.reconcile(operation.resourceId, async (current, resource, event) => {
          if (resource.type === "image_template") {
            await this.store.completeTemplateImport({ ...resource, state: "READY" }, resource.id, current.id, event);
            return;
          }
          if (resource.type === "network_probe" && (current.kind === "stop" || current.kind === "destroy"))
            await this.store.completeNetworkProbeOperationTransition(current.id, resource, event);
          else await this.store.completeOperationTransition(current.id, resource, event);
        });
      });
    }
  }
  private rejectGatewayMutation(resource: Resource): void {
    if (resource.type === "gateway" || resource.type === "image_template")
      throw new KilnError(
        "SAFETY_DENIED",
        403,
        "Gateway lifecycle is protected and cannot be changed through workload operations",
      );
  }
  private async rejectUnresolved(resource: Resource): Promise<void> {
    if (await this.store.unresolvedOperation(resource.id))
      throw new KilnError("OPERATION_UNRESOLVED", 409, "Resource has an unresolved provider operation");
  }
  private async provenanceValid(resource: Resource): Promise<boolean> {
    return provenanceGraphMatches(resource, this.store, this.provider);
  }
  private async guardProvenance(resource: Resource): Promise<void> {
    if (await this.provenanceValid(resource)) return;
    await this.store.appendEvent(operationEvent(resource, "resource.provenance_denied", { reason: "ATTACHMENT_GRAPH_MISMATCH" }, this.clock));
    throw new KilnError("SAFETY_DENIED", 403, "Resource provenance is missing or changed");
  }
  async requireResource(id: string, projectId: string): Promise<Resource> {
    const resource = await this.store.getResource(id);
    if (!resource) throw new KilnError("NOT_FOUND", 404, "Resource not found");
    if (resource.projectId !== projectId)
      throw new KilnError(
        "UNAUTHORIZED",
        403,
        "Resource is outside this project",
      );
    return resource;
  }
  private async transition(
    resource: Resource,
    type: string,
    payload: Record<string, unknown>,
  ): Promise<void> {
    await this.store.commitTransition(resource, {
      installationId: resource.installationId,
      projectId: resource.projectId,
      resourceId: resource.id,
      type,
      timestamp: this.clock().toISOString(),
      payload,
    });
  }
  private async completeTransition(
    operationId: string,
    resource: Resource,
    type: string,
    payload: Record<string, unknown>,
  ): Promise<void> {
    await this.store.completeOperationTransition(operationId, resource, {
      installationId: resource.installationId,
      projectId: resource.projectId,
      resourceId: resource.id,
      type,
      timestamp: this.clock().toISOString(),
      payload,
    });
  }
}

const gatewayFaults: Record<string, { code: string; severity: "warning" | "critical"; message: string; guidance: string[] }> = {
  PROVIDER_UNKNOWN: {
    code: "PROVIDER_UNKNOWN", severity: "warning", message: "Gateway provider evidence is unavailable", guidance: ["Check provider connectivity and read-only credentials."],
  },
  OWNERSHIP_QUARANTINE: {
    code: "OWNERSHIP_QUARANTINE", severity: "critical", message: "Gateway ownership or expected configuration cannot be verified", guidance: ["Do not alter the gateway.", "Inspect ownership metadata with kiln doctor."],
  },
  GATEWAY_POWER: {
    code: "GATEWAY_POWER", severity: "critical", message: "Gateway is not running", guidance: ["Inspect the protected gateway in Kiln.", "A future repair command may restart a verified gateway."],
  },
  GATEWAY_SERVICE: {
    code: "GATEWAY_SERVICE", severity: "critical", message: "Gateway policy, reservation, or service check failed", guidance: ["Run kiln doctor for the affected node.", "Do not replace the gateway while its ownership is uncertain."],
  },
  GATEWAY_NOT_READY: {
    code: "GATEWAY_NOT_READY", severity: "critical", message: "Gateway lifecycle has not reached READY", guidance: ["Inspect the gateway resource and its operation history.", "Do not retry creation while the previous operation is unresolved."],
  },
  UPSTREAM_CONNECTIVITY: {
    code: "UPSTREAM_CONNECTIVITY", severity: "warning", message: "Gateway cannot confirm DNS or internet reachability", guidance: ["Check upstream DNS and the selected network profile."],
  },
  NODE_OFFLINE: {
    code: "NODE_OFFLINE", severity: "critical", message: "The gateway node is offline", guidance: ["Restore the Proxmox node before attempting gateway recovery."],
  },
};

export class GatewayService {
  constructor(
    private readonly store: Store,
    private readonly provider: ComputeProvider,
    private readonly clock = () => new Date(),
  ) {}
  async createFakeGateway(node: string, key: string, createdBy: string): Promise<{ resource: Resource; replayed: boolean }> {
    if (this.provider.mode !== "fake")
      throw new KilnError("UNSUPPORTED", 501, "Live gateway creation is disabled in Phase 1");
    if (!node) throw new KilnError("INVALID_INPUT", 400, "A gateway node is required");
    const inventory = await this.provider.discover();
    if (!inventory.nodes.some((candidate) => candidate.id === node))
      throw new KilnError("INVALID_INPUT", 400, "Gateway node is not available from the fake provider");
    return this.store.withResourceLock(`gateway-node:${node}`, async () => {
      const installationId = await this.store.installationId();
      const now = this.clock().toISOString();
      const id = `gw_${crypto.randomUUID().replaceAll("-", "")}`;
      const generation = crypto.randomUUID();
      const resource: Resource = {
        id, installationId, projectId: "infrastructure", type: "gateway", ownership: "KILN_MANAGED", state: "PROVISIONING",
        providerId: this.provider.id, providerResourceId: id, providerKind: "fake", node, pool: "kiln", createdBy, createdAt: now, expiresAt: null, profile: null,
      };
      const metadata: GatewayMetadata = { resourceId: id, node, generation, expectedFingerprint: `fake:${installationId}:${node}:${generation}`, createdAt: now };
      const normalized = JSON.stringify({ installationId, node, type: "gateway" });
      const result = await this.store.createGateway(resource, metadata, `${installationId}:gateway:${key}`, normalized);
      if (result.replayed) return result;
      const executor = new ProviderOperationExecutor(this.store, this.provider, this.clock);
      let createdObservation: OwnershipObservation | null = null;
      const dispatched = await executor.dispatch(
        result.resource,
        "create",
        "gateway.create",
        async () => { createdObservation = await this.provider.create(structuredClone(result.resource)); },
        async (operation) => {
          const observed = createdObservation ?? await this.provider.inspect(result.resource.providerResourceId);
          if (!observed) throw new KilnError("SAFETY_DENIED", 403, "Provider gateway is missing after create");
          validateOwnership(result.resource, installationId, observed);
          if (!await operationBindingMatches(operation, result.resource, this.store, this.provider))
            throw new KilnError("SAFETY_DENIED", 403, "Provider operation binding changed before completion");
          result.resource.state = "READY";
          await this.store.completeOperationTransition(operation.id, result.resource, {
            installationId, projectId: "infrastructure", resourceId: id, type: "gateway.created", timestamp: this.clock().toISOString(), payload: { node, generation, providerMode: "fake", operationId: operation.id },
          });
        },
      );
      if (dispatched.status === "COMPLETED") await this.provider.registerGatewayAttestation?.(structuredClone(result.resource), structuredClone(metadata));
      return result;
    });
  }
  async reconcileOperations(): Promise<void> {
    const executor = new ProviderOperationExecutor(this.store, this.provider, this.clock);
    for (const operation of await this.store.submittedOperations()) {
      const resource = await this.store.getResource(operation.resourceId);
      if (!resource || resource.type !== "gateway") continue;
      await this.store.withResourceLock(resource.id, async () => {
        await executor.reconcile(resource.id);
        if ((await this.store.unresolvedOperation(resource.id)) !== null) return;
        if (operation.kind !== "create") return;
        const completed = await this.store.completedOperation(resource.id, "create");
        const metadata = await this.store.getGateway(resource.id);
        const current = await this.store.getResource(resource.id);
        if (completed && metadata && current?.state === "READY") {
          try { await this.provider.registerGatewayAttestation?.(structuredClone(current), structuredClone(metadata)); } catch { /* monitoring holds admission until attestation exists */ }
        }
      });
    }
  }
}

export class GatewayMonitor {
  constructor(private readonly store: Store, private readonly provider: ComputeProvider, private readonly clock = () => new Date()) {}
  async scan(): Promise<void> {
    return this.store.withResourceLock("gateway-monitor-scan", async () => this.scanLocked());
  }
  private async scanLocked(): Promise<void> {
    const gateways = await this.store.listGateways();
    if (gateways.length === 0) return;
    let inventory: ProviderInventory | null = null;
    try { inventory = await this.provider.discover(); } catch { /* represented as unknown evidence below */ }
    for (const gateway of gateways) {
      await this.store.withResourceLock(`gateway-admission:${gateway.resource.id}`, async () => {
        const currentGateway = (await this.store.listGateways()).find((candidate) => candidate.resource.id === gateway.resource.id);
        if (!currentGateway) return;
        const node = inventory?.nodes.find((candidate) => candidate.id === currentGateway.metadata.node);
        const evidence = !inventory || !node ? unknownEvidence(this.clock) : !node.online ? unknownEvidence(this.clock) : await this.evidence(currentGateway.resource, currentGateway.metadata);
        const unresolved = await this.store.unresolvedOperation(currentGateway.resource.id);
        const result = assessGateway(unresolved ? { ...currentGateway.resource, state: "PROVISIONING" } : currentGateway.resource, currentGateway.metadata, evidence, this.clock(), currentGateway.health, Boolean(node && !node.online));
        const prior = await this.store.listGatewayIncidents(currentGateway.metadata.node);
        const events: Array<Omit<Event, "id">> = [];
        const current = result.fault ? gatewayIncident(currentGateway, result.fault, this.clock) : null;
        const incidents = prior.filter((incident) => incident.gatewayId === currentGateway.resource.id).map((incident) => {
          if (current && incident.code === current.code && incident.status === "OPEN") return { ...incident, lastSeenAt: this.clock().toISOString() };
          if (incident.status === "OPEN" && result.health.status === "READY") {
            events.push(eventFor(currentGateway.resource, "gateway.incident_resolved", { incidentId: incident.id, code: incident.code }, this.clock));
            return { ...incident, status: "RESOLVED" as const, resolvedAt: this.clock().toISOString() };
          }
          return incident;
        });
        if (current && !incidents.some((incident) => incident.code === current.code && incident.status === "OPEN")) {
          incidents.push(current);
          events.push(eventFor(currentGateway.resource, "gateway.incident_opened", { incidentId: current.id, code: current.code }, this.clock));
        }
        events.push(eventFor(currentGateway.resource, "gateway.observed", { status: result.health.status }, this.clock));
        await this.store.saveGatewayScan(result.health, incidents, events);
      });
    }
  }
  private async evidence(resource: Resource, metadata: GatewayMetadata): Promise<GatewayEvidence> {
    try {
      if (!this.provider.observeGateway) return unknownEvidence(this.clock);
      const providerEvidence = await this.provider.observeGateway(structuredClone(resource), structuredClone(metadata));
      const identity = await this.store.getGatewayIdentity(resource.id);
      const identityRequired = await this.store.gatewayIdentityRequired(resource.id);
      if (!identity && !identityRequired) return providerEvidence;
      if (!identity) return { ...providerEvidence, heartbeat: "UNKNOWN", services: "UNKNOWN", policy: "UNKNOWN", reservation: "UNKNOWN", canary: "UNKNOWN" };
      const now = this.clock();
      const freshIdentity = identity.lastSeenAt && fresh(identity.lastSeenAt, now);
      return {
        ...providerEvidence,
        heartbeat: identity.revokedAt ? "FAIL" : freshIdentity ? "PASS" : "UNKNOWN",
        services: identity.lastServices ?? "UNKNOWN",
        policy: identity.lastPolicy ?? "UNKNOWN",
        reservation: identity.lastReservation ?? "UNKNOWN",
        // A gateway cannot attest its own routing policy or guest-path probes.
        canary: "UNKNOWN",
      };
    } catch {
      return unknownEvidence(this.clock);
    }
  }
}

function unknownEvidence(clock: () => Date): GatewayEvidence {
  return { power: "UNKNOWN", ownership: "UNKNOWN", config: "UNKNOWN", heartbeat: "UNKNOWN", policy: "UNKNOWN", reservation: "UNKNOWN", services: "UNKNOWN", canary: "UNKNOWN", generation: null, configFingerprint: null, observedAt: clock().toISOString() };
}
function assessGateway(resource: Resource, metadata: GatewayMetadata, evidence: GatewayEvidence, now: Date, previous: GatewayHealth | null, nodeOffline = false): { health: GatewayHealth; fault: keyof typeof gatewayFaults | null } {
  let fault: keyof typeof gatewayFaults | null = null;
  let status: GatewayNodeStatus = "READY";
  const observedAt = Date.parse(evidence.observedAt);
  const attestationMatches = evidence.generation === metadata.generation && evidence.configFingerprint === metadata.expectedFingerprint;
  const attestationComplete = evidence.generation !== null && evidence.configFingerprint !== null;
  if (evidence.ownership === "INVALID" || evidence.config === "INVALID" || (attestationComplete && !attestationMatches)) { status = "QUARANTINED"; fault = "OWNERSHIP_QUARANTINE"; }
  else if (resource.state !== "READY") { status = "NOT_READY"; fault = "GATEWAY_NOT_READY"; }
  else if (nodeOffline) { status = "NOT_READY"; fault = "NODE_OFFLINE"; }
  else if (!Number.isFinite(observedAt) || observedAt > now.getTime() + 5_000 || observedAt < now.getTime() - 30_000 || !attestationComplete || evidence.ownership === "UNKNOWN" || evidence.config === "UNKNOWN" || evidence.power === "UNKNOWN") { status = "NOT_READY"; fault = "PROVIDER_UNKNOWN"; }
  else if (evidence.power === "STOPPED") { status = "NOT_READY"; fault = "GATEWAY_POWER"; }
  else if ([evidence.heartbeat, evidence.policy, evidence.reservation, evidence.services].includes("FAIL") || [evidence.heartbeat, evidence.policy, evidence.reservation, evidence.services].includes("UNKNOWN")) { status = "NOT_READY"; fault = "GATEWAY_SERVICE"; }
  else if (evidence.canary !== "PASS") { status = "NOT_READY"; fault = "UPSTREAM_CONNECTIVITY"; }
  if (previous?.status === "QUARANTINED" && fault !== "OWNERSHIP_QUARANTINE") { status = "QUARANTINED"; fault = "OWNERSHIP_QUARANTINE"; }
  return { health: { resourceId: resource.id, node: metadata.node, status, observedAt: evidence.observedAt, generation: evidence.generation, expectedFingerprint: evidence.configFingerprint, evidence }, fault };
}
function gatewayIncident(gateway: { resource: Resource; metadata: GatewayMetadata }, code: keyof typeof gatewayFaults, clock: () => Date): GatewayIncident {
  const fault = gatewayFaults[code]!; const now = clock().toISOString();
  return { id: `inc_${crypto.randomUUID().replaceAll("-", "")}`, node: gateway.metadata.node, gatewayId: gateway.resource.id, code: fault.code, severity: fault.severity, status: "OPEN", firstSeenAt: now, lastSeenAt: now, resolvedAt: null, message: fault.message, guidance: fault.guidance };
}
function eventFor(resource: Resource, type: string, payload: Record<string, unknown>, clock: () => Date): Omit<Event, "id"> {
  return { installationId: resource.installationId, projectId: "infrastructure", resourceId: resource.id, type, timestamp: clock().toISOString(), payload };
}

export class DoctorService {
  constructor(private readonly store: Store, private readonly provider: ComputeProvider, private readonly clock = () => new Date(), private readonly networkProbeProfiles: NetworkProbeProfile[] = []) {}
  async inspect(node?: string): Promise<Record<string, unknown>> {
    return this.store.withResourceLock("gateway-monitor-scan", async () => this.inspectLocked(node));
  }
  private async inspectLocked(node?: string): Promise<Record<string, unknown>> {
    const installationId = await this.store.installationId();
    let inventory: ProviderInventory | null = null;
    try { inventory = await this.provider.discover(); } catch { /* reported below */ }
    const gateways = (await this.store.listGateways()).filter((gateway) => !node || gateway.metadata.node === node);
    const incidents = (await this.store.listGatewayIncidents(node)).filter((incident) => incident.status === "OPEN");
    const now = this.clock();
    const nodes: Array<{ node: string; gatewayId: string | null; status: GatewayNodeStatus; checks: Array<{ id: string; status: GatewayCheckStatus; code: string; message: string }>; identity?: { deviceId: string; revokedAt: string | null; lastSeenAt: string | null }; diagnostics?: Array<{ probeId: string; state: NetworkProbeJobState; placement: "UNVERIFIED"; receivedAt: string | null; resultSummary: { pass: number; fail: number; unknown: number } | null }> }> = await Promise.all(gateways.map(async ({ resource, metadata, health }) => {
      const providerNode = inventory?.nodes.find((candidate) => candidate.id === metadata.node);
      const available = Boolean(providerNode?.online);
      const attested = health?.generation === metadata.generation && health?.expectedFingerprint === metadata.expectedFingerprint;
      const identity = await this.store.getGatewayIdentity(resource.id);
      const checks = doctorChecks(health, now, available, attested, resource.state);
      const unresolved = await this.store.unresolvedOperation(resource.id);
      if (unresolved) checks.push({ id: "operation", status: "WARN", code: "OPERATION_UNRESOLVED", message: "Gateway has an unresolved provider operation" });
      if (identity) checks.push({ id: "identity", status: identity.revokedAt ? "FAIL" : identity.lastSeenAt && fresh(identity.lastSeenAt, now) ? "PASS" : "WARN", code: identity.revokedAt ? "IDENTITY_REVOKED" : identity.lastSeenAt && fresh(identity.lastSeenAt, now) ? "IDENTITY_FRESH" : "IDENTITY_STALE", message: identity.revokedAt ? "Gateway device identity is revoked" : identity.lastSeenAt && fresh(identity.lastSeenAt, now) ? "Gateway device identity has a fresh heartbeat" : "Gateway device identity has no fresh heartbeat" });
      const probes = await this.store.listNetworkProbes(resource.id);
      const latest = probes.sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0];
      if (latest) {
        if (latest.state === "PENDING") checks.push({ id: "network_probe", status: "WARN", code: "PROBE_PENDING", message: "A diagnostic network probe is pending" });
        else if (latest.state === "COMPLETED" && probeFresh(latest, metadata, this.networkProbeProfiles, now)) checks.push({ id: "network_probe", status: "UNKNOWN", code: "PROBE_DIAGNOSTIC_UNVERIFIED", message: "Diagnostic probe results are unverified and do not qualify workload network access" });
        else checks.push({ id: "network_probe", status: "WARN", code: latest.state === "TIMED_OUT" ? "PROBE_TIMED_OUT" : "PROBE_STALE", message: "Network probe evidence is stale or timed out" });
      }
      const diagnostics = probes.map((probe) => ({ probeId: probe.resourceId, state: probe.state, placement: "UNVERIFIED" as const, receivedAt: probe.receivedAt, resultSummary: probe.results ? summarizeProbe(probe) : null }));
      return { node: metadata.node, gatewayId: resource.id, status: health?.status === "QUARANTINED" ? "QUARANTINED" : !unresolved && gatewayReady({ resource, metadata, health }, inventory?.nodes ?? [], now) ? "READY" : "NOT_READY", checks, identity: identity ? { deviceId: identity.deviceId, revokedAt: identity.revokedAt, lastSeenAt: identity.lastSeenAt } : undefined, diagnostics };
    }));
    const known = new Set(nodes.map((entry) => entry.node));
    for (const providerNode of inventory?.nodes ?? []) if (!known.has(providerNode.id) && (!node || node === providerNode.id)) nodes.push({ node: providerNode.id, gatewayId: null, status: "UNCONFIGURED", checks: [{ id: "gateway", status: "WARN", code: "GATEWAY_UNCONFIGURED", message: "No Kiln gateway is configured for this node" }] });
    const checks = inventory ? [{ id: "provider", status: "PASS", code: "PROVIDER_READ_ONLY", message: "Provider discovery completed without mutation" }] : [{ id: "provider", status: "UNKNOWN", code: "PROVIDER_UNKNOWN", message: "Provider discovery is unavailable" }];
    const overall = !inventory ? "UNKNOWN" : nodes.some((entry) => entry.status !== "READY") ? "DEGRADED" : nodes.length === 0 ? "UNKNOWN" : "HEALTHY";
    return { schemaVersion: 1, checkedAt: now.toISOString(), installationId, providerMode: this.provider.mode, persistence: this.store.persistenceKind(), overall, checks, nodes, incidents, repairEnabled: false, limitations: ["Gateway repair is disabled in this release.", "Gateway identity telemetry does not prove provider ownership, VM configuration or guest-path connectivity.", "Network probes are diagnostic only and have unverified placement in this release.", "Fake-provider evidence is simulation only."] };
  }
}
function fresh(value: string, now: Date): boolean { const timestamp = Date.parse(value); return Number.isFinite(timestamp) && timestamp <= now.getTime() + 5_000 && timestamp >= now.getTime() - 30_000; }
function probeFresh(probe: NetworkProbeRecord, gateway: GatewayMetadata, profiles: NetworkProbeProfile[], now: Date): boolean { if (!probe.receivedAt || probe.gatewayGeneration !== gateway.generation || probe.gatewayConfigFingerprint !== gateway.expectedFingerprint || probe.node !== gateway.node) return false; const profile = profiles.find((candidate) => candidate.id === probe.profileId); if (!profile || probe.profileDigest !== createHash("sha256").update(JSON.stringify(profile)).digest("hex")) return false; const until = Math.min(Date.parse(probe.plan.expiresAt), Date.parse(probe.receivedAt) + 30_000); return Number.isFinite(until) && now.getTime() <= until; }
function summarizeProbe(probe: NetworkProbeRecord): { pass: number; fail: number; unknown: number } {
  let pass = 0; let fail = 0; let unknown = 0;
  for (const result of probe.results ?? []) {
    const check = probe.plan.checks.find((candidate) => candidate.id === result.id);
    if (!check || result.code === "TIMEOUT" || (check.kind === "tcp" && check.expect === "blocked" && result.code === "TCP_FAILED")) unknown += 1;
    else if (result.code === "DNS_ANSWER" || result.code === "HTTPS_EXPECTED" || (check.kind === "tcp" && check.expect === "reachable" && result.code === "TCP_CONNECTED")) pass += 1;
    else fail += 1;
  }
  return { pass, fail, unknown };
}
function gatewayReady(
  gateway: { resource: Resource; metadata: GatewayMetadata; health: GatewayHealth | null },
  nodes: ComputeNode[],
  now: Date,
): boolean {
  return gateway.resource.state === "READY" && gateway.health?.status === "READY" && gateway.health.generation === gateway.metadata.generation && gateway.health.expectedFingerprint === gateway.metadata.expectedFingerprint && fresh(gateway.health.observedAt, now) && Boolean(nodes.find((node) => node.id === gateway.metadata.node)?.online);
}
function doctorChecks(health: GatewayHealth | null, now: Date, providerAvailable = true, attested = false, resourceState: ResourceState = "ERROR"): Array<{ id: string; status: GatewayCheckStatus; code: string; message: string }> {
  if (!providerAvailable) return [{ id: "provider", status: "UNKNOWN", code: "PROVIDER_UNKNOWN", message: "Provider cannot confirm that this node is online" }];
  if (resourceState !== "READY") return [{ id: "gateway", status: "WARN", code: "GATEWAY_NOT_READY", message: "Gateway resource is not ready" }];
  if (!health) return [{ id: "monitor", status: "UNKNOWN", code: "NO_OBSERVATION", message: "No persisted gateway observation exists" }];
  if (!attested) return [{ id: "gateway", status: "FAIL", code: "ATTESTATION_MISMATCH", message: "Gateway health does not match the current generation and fingerprint" }];
  if (!fresh(health.observedAt, now)) return [{ id: "monitor", status: "WARN", code: "STALE_OBSERVATION", message: "Gateway evidence is stale or has an invalid timestamp" }];
  return [{ id: "gateway", status: health.status === "READY" ? "PASS" : health.status === "QUARANTINED" ? "FAIL" : "WARN", code: health.status, message: health.status === "READY" ? "Gateway evidence is fresh and ready" : "Gateway is not eligible for new workloads" }];
}

export function chooseNode(
  nodes: ComputeNode[],
  requirements: {
    storage: string;
    network: string;
    image: string;
    cpu: number;
    memory: number;
  },
): ComputeNode | null {
  return (
    nodes
      .filter(
        (node) =>
          node.online &&
          node.storage.includes(requirements.storage) &&
          node.networks.includes(requirements.network) &&
          node.images.includes(requirements.image) &&
          node.cpuFree >= requirements.cpu &&
          node.memoryFree >= requirements.memory,
      )
      .sort(
        (a, b) => b.cpuFree + b.memoryFree - (a.cpuFree + a.memoryFree),
      )[0] ?? null
  );
}

export * from "./gateway-identity.js";
export * from "./network-probes.js";
