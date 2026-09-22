import { createHash, randomUUID } from "node:crypto";
import { KilnError, type Event, type Resource, type Store } from "./index.js";
import { verifyImageImport, type ImageImportRequest, type TrustedImageKeys, type VerifiedImage } from "./provenance.js";

export const qualificationPhases = [
  "POOL_CREATE",
  "UPLOAD",
  "IMPORT",
  "TEMPLATE",
  "CLONE",
  "STAMP",
  "START",
  "STOP",
  "DESTROY_PROBE",
  "DESTROY_TEMPLATE",
] as const;
export type QualificationPhaseName = (typeof qualificationPhases)[number];
export type QualificationPhaseStatus = "INTENT" | "SUBMITTED" | "COMPLETED" | "UNKNOWN";
export type QualificationRunStatus = "ACTIVE" | "COMPLETED" | "UNKNOWN";

export interface QualificationPlan {
  schemaVersion: 1;
  installationId: string;
  node: string;
  pool: string;
  poolNonce: string;
  poolComment: string;
  stageStorage: string;
  targetStorage: string;
  pveVersion: "9.2.2";
  storageConfigDigest: string;
  tokenIdentity: string;
  stageVolumeId: string;
  templateVmid: string;
  probeVmid: string;
  templateResourceId: string;
  probeResourceId: string;
  templateBootVolume: string;
  probeBootVolume: string;
  templateNonce: string;
  probeNonce: string;
  image: Pick<VerifiedImage, "id" | "manifest" | "manifestDigest" | "signerFingerprint" | "policyDigest">;
  artifactBase64: string;
  artifactDisposition: "MANAGED_RETAINED_IMAGE_CACHE";
  poolDisposition: "MANAGED_RETAINED_POOL";
  canonicalDigest: string;
}

export interface QualificationRun {
  id: string;
  installationId: string;
  idempotencyKey: string;
  normalizedPayload: string;
  status: QualificationRunStatus;
  plan: QualificationPlan;
  createdAt: string;
  completedAt: string | null;
}
export interface QualificationAllocation {
  id: string;
  runId: string;
  kind: "POOL" | "STAGING";
  identity: string;
  intentDigest: string;
  state: "INTENT" | "RETAINED" | "UNKNOWN";
  receipt: QualificationReceipt | null;
  createdAt: string;
}

export interface QualificationPhase {
  runId: string;
  name: QualificationPhaseName;
  status: QualificationPhaseStatus;
  intentDigest: string;
  receipt: QualificationReceipt | null;
  safeReason: string | null;
  createdAt: string;
  reconciliationDeadline: string;
  submittedAt: string | null;
  completedAt: string | null;
}

export interface QualificationReceipt {
  taskId: string | null;
  workerType: string | null;
  sourceVmid: string | null;
  destinationVmid: string | null;
  tokenIdentity: string;
  responseDigest: string;
  requestDigest: string;
  dispatchDigest: string;
  dispatch: { method: string; path: string; body: Record<string, string | number> | null };
  generatedUuid: string | null;
  generatedCtime: string | null;
}

export interface QualificationProof { resources: Resource[]; allocations: QualificationAllocation[]; children: Array<{ nativeId: string; resourceId: string }>; phases: QualificationPhase[]; }

export interface QualificationStore {
  getQualificationProof(runId: string): Promise<QualificationProof>;
  createQualificationRun(input: { run: QualificationRun; resources: Resource[]; allocations: QualificationAllocation[]; event: Omit<Event, "id"> }): Promise<{ run: QualificationRun; replayed: boolean }>;
  getQualificationRun(runId: string): Promise<QualificationRun | null>;
  getQualificationRunByInstallation(installationId: string): Promise<QualificationRun | null>;
  getQualificationPhase(runId: string, name: QualificationPhaseName): Promise<QualificationPhase | null>;
  listQualificationAllocations(runId: string): Promise<QualificationAllocation[]>;
  completeQualificationAllocation(runId: string, kind: QualificationAllocation["kind"], receipt: QualificationReceipt | null): Promise<void>;
  completeQualificationPhaseAndAllocation(runId: string, name: QualificationPhaseName, kind: QualificationAllocation["kind"], event: Omit<Event, "id">, receiptPatch?: QualificationInspection["receiptPatch"]): Promise<void>;
  beginQualificationPhase(input: { runId: string; name: QualificationPhaseName; intentDigest: string; event: Omit<Event, "id"> }): Promise<{ phase: QualificationPhase; dispatch: boolean }>;
  submitQualificationPhase(runId: string, name: QualificationPhaseName, receipt: QualificationReceipt, event: Omit<Event, "id">): Promise<void>;
  completeQualificationPhase(runId: string, name: QualificationPhaseName, event: Omit<Event, "id">, receiptPatch?: QualificationInspection["receiptPatch"]): Promise<void>;
  markQualificationPhaseUnknown(runId: string, name: QualificationPhaseName, reason: string, event: Omit<Event, "id">): Promise<void>;
}

export interface LifecycleQualificationProvider {
  readonly mode: "proxmox-qualification";
  executeQualificationPhase(context: QualificationExecutionContext): Promise<QualificationReceipt>;
  inspectQualificationPhase(context: QualificationExecutionContext, receipt: QualificationReceipt): Promise<QualificationInspection>;
}
export interface QualificationInspection { status: "RUNNING" | "COMPLETED" | "FAILED" | "MISMATCH" | "UNKNOWN"; receiptPatch?: Pick<QualificationReceipt, "generatedUuid" | "generatedCtime" | "responseDigest">; }
export interface QualificationExecutionContext { plan: QualificationPlan; phase: QualificationPhaseName; priorReceipts: Partial<Record<QualificationPhaseName, QualificationReceipt>>; requestDigest: string; }

export interface QualificationProfile {
  node: string;
  pool: string;
  stageStorage: string;
  targetStorage: string;
  pveVersion: "9.2.2";
  storageConfigDigest: string;
  templateVmid: string;
  probeVmid: string;
  tokenIdentity: string;
}

export function canonicalQualificationDispatch(value: unknown): string {
  function canonical(input: unknown): unknown {
    if (Array.isArray(input)) return input.map(canonical);
    if (input !== null && typeof input === "object") return Object.fromEntries(Object.entries(input).sort(([a], [b]) => a.localeCompare(b)).map(([key, entry]) => [key, canonical(entry)]));
    return input;
  }
  return createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex");
}

export function canonicalQualificationPlan(plan: Omit<QualificationPlan, "canonicalDigest">): string {
  return createHash("sha256").update(JSON.stringify({
    schemaVersion: plan.schemaVersion,
    installationId: plan.installationId,
    node: plan.node,
    pool: plan.pool,
    poolNonce: plan.poolNonce,
    poolComment: plan.poolComment,
    stageStorage: plan.stageStorage,
    targetStorage: plan.targetStorage,
    pveVersion: plan.pveVersion,
    storageConfigDigest: plan.storageConfigDigest,
    tokenIdentity: plan.tokenIdentity,
    stageVolumeId: plan.stageVolumeId,
    templateVmid: plan.templateVmid,
    probeVmid: plan.probeVmid,
    templateResourceId: plan.templateResourceId,
    probeResourceId: plan.probeResourceId,
    templateBootVolume: plan.templateBootVolume,
    probeBootVolume: plan.probeBootVolume,
    templateNonce: plan.templateNonce,
    probeNonce: plan.probeNonce,
    image: {
      id: plan.image.id,
      manifest: {
        schemaVersion: plan.image.manifest.schemaVersion,
        name: plan.image.manifest.name,
        version: plan.image.manifest.version,
        arch: plan.image.manifest.arch,
        artifactSha256: plan.image.manifest.artifactSha256,
        artifactSize: plan.image.manifest.artifactSize,
        sourceBuild: plan.image.manifest.sourceBuild,
        capabilities: plan.image.manifest.capabilities,
        keyId: plan.image.manifest.keyId,
      },
      manifestDigest: plan.image.manifestDigest,
      signerFingerprint: plan.image.signerFingerprint,
      policyDigest: plan.image.policyDigest,
    },
    artifactBase64: plan.artifactBase64,
    artifactDisposition: plan.artifactDisposition,
    poolDisposition: plan.poolDisposition,
  })).digest("hex");
}

function phaseIntent(plan: QualificationPlan, name: QualificationPhaseName): string {
  return createHash("sha256").update(`${plan.canonicalDigest}:${name}`).digest("hex");
}

function assertPlan(plan: QualificationPlan): void {
  const ids = [plan.node, plan.pool, plan.stageStorage, plan.targetStorage, plan.templateVmid, plan.probeVmid, plan.templateResourceId, plan.probeResourceId, plan.templateBootVolume, plan.probeBootVolume, plan.poolNonce, plan.templateNonce, plan.probeNonce, plan.tokenIdentity];
  if (ids.some((id) => !/^[A-Za-z0-9._:@!-]{1,128}$/.test(id)) || plan.pveVersion !== "9.2.2" || !/^[a-f0-9]{40}$/.test(plan.storageConfigDigest) || !/^import\/[A-Za-z0-9._-]{1,128}\.qcow2$/.test(plan.stageVolumeId) || plan.templateVmid === plan.probeVmid || canonicalQualificationPlan({ ...plan, canonicalDigest: undefined } as Omit<QualificationPlan, "canonicalDigest">) !== plan.canonicalDigest) throw new KilnError("SAFETY_DENIED", 403, "Qualification plan is invalid");
}

function assertQualificationQcow2(artifactBase64: string): void {
  let artifact: Buffer;
  try { artifact = Buffer.from(artifactBase64, "base64"); } catch { throw new KilnError("INVALID_INPUT", 400, "Qualification artifact encoding is invalid"); }
  const headerLength = artifact.length >= 104 ? artifact.readUInt32BE(100) : 0;
  if (artifact.length < headerLength || ![104, 112].includes(headerLength) || (headerLength === 112 && artifact.subarray(104, 112).some((byte) => byte !== 0)) || artifact.length < 104 || artifact.subarray(0, 4).toString("binary") !== "QFI\u00fb" || artifact.readUInt32BE(4) !== 3 || artifact.readBigUInt64BE(8) !== 0n || artifact.readUInt32BE(16) !== 0 || artifact.readUInt32BE(20) !== 9 || artifact.readBigUInt64BE(24) !== 4n * 1024n * 1024n || artifact.readUInt32BE(32) !== 0 || artifact.readBigUInt64BE(72) !== 0n || artifact.readBigUInt64BE(80) !== 0n || artifact.readBigUInt64BE(88) !== 0n || artifact.readUInt32BE(96) !== 4) throw new KilnError("INVALID_INPUT", 400, "Qualification artifact is not the qualified standalone qcow2 profile");
}

export class LifecycleQualificationService {
  constructor(
    private readonly store: Store & QualificationStore,
    private readonly provider: LifecycleQualificationProvider,
    private readonly trustedKeys: TrustedImageKeys,
    private readonly profile: QualificationProfile,
    private readonly clock = () => new Date(),
  ) {}

  async createRun(request: ImageImportRequest, idempotencyKey: string): Promise<{ run: QualificationRun; replayed: boolean }> {
    const now = this.clock().toISOString();
    let image: VerifiedImage;
    try { image = verifyImageImport(request, this.trustedKeys, now); } catch (error) { throw new KilnError("INVALID_INPUT", 400, error instanceof Error ? error.message : "Qualification image is invalid"); }
    if (image.manifest.arch !== "amd64" || !image.manifest.capabilities.includes("network_probe")) throw new KilnError("INVALID_INPUT", 400, "Qualification image does not support the required BIOS probe profile");
    assertQualificationQcow2(request.artifactBase64);
    const installationId = await this.store.installationId();
    const existing = await this.store.getQualificationRunByInstallation(installationId);
    const normalizedPayload = JSON.stringify({ manifest: image.manifest, signature: request.signature, artifactDigest: image.manifest.artifactSha256 });
    if (existing) {
      if (existing.idempotencyKey !== idempotencyKey || existing.normalizedPayload !== normalizedPayload) throw new KilnError("CONFLICT", 409, "An installation already has a qualification run");
      return { run: existing, replayed: true };
    }
    const runId = `qual_${randomUUID().replaceAll("-", "")}`;
    const poolNonce = randomUUID();
    const templateResourceId = `qual_template_${randomUUID().replaceAll("-", "")}`;
    const probeResourceId = `qual_probe_${randomUUID().replaceAll("-", "")}`;
    const withoutDigest: Omit<QualificationPlan, "canonicalDigest"> = {
      schemaVersion: 1, installationId, node: this.profile.node, pool: this.profile.pool, poolNonce, poolComment: `kiln-qualification-${runId};nonce=${poolNonce}`, stageStorage: this.profile.stageStorage, targetStorage: this.profile.targetStorage, pveVersion: this.profile.pveVersion, storageConfigDigest: this.profile.storageConfigDigest, tokenIdentity: this.profile.tokenIdentity, stageVolumeId: `import/${image.manifestDigest.slice(0, 20)}-${runId}.qcow2`, templateVmid: this.profile.templateVmid, probeVmid: this.profile.probeVmid, templateResourceId, probeResourceId, templateBootVolume: `base-${this.profile.templateVmid}-disk-0`, probeBootVolume: `vm-${this.profile.probeVmid}-disk-0`, templateNonce: randomUUID(), probeNonce: randomUUID(), image: { id: image.id, manifest: image.manifest, manifestDigest: image.manifestDigest, signerFingerprint: image.signerFingerprint, policyDigest: image.policyDigest }, artifactBase64: request.artifactBase64, artifactDisposition: "MANAGED_RETAINED_IMAGE_CACHE", poolDisposition: "MANAGED_RETAINED_POOL",
    };
    const plan: QualificationPlan = { ...withoutDigest, canonicalDigest: canonicalQualificationPlan(withoutDigest) };
    const run: QualificationRun = { id: runId, installationId, idempotencyKey, normalizedPayload, status: "ACTIVE", plan, createdAt: now, completedAt: null };
    const resources: Resource[] = [
      { id: templateResourceId, installationId, projectId: "infrastructure", type: "image_template", ownership: "KILN_MANAGED", state: "PROVISIONING", providerId: "proxmox", providerResourceId: plan.templateVmid, providerKind: "qemu", node: plan.node, pool: plan.pool, createdBy: "qualification", createdAt: now, expiresAt: null, profile: "proxmox-qualification", provenanceRequired: true },
      { id: probeResourceId, installationId, projectId: "infrastructure", type: "network_probe", ownership: "KILN_MANAGED", state: "PROVISIONING", providerId: "proxmox", providerResourceId: plan.probeVmid, providerKind: "qemu", node: plan.node, pool: plan.pool, createdBy: "qualification", createdAt: now, expiresAt: null, profile: "proxmox-lifecycle-qualification", provenanceRequired: true },
    ];
    const allocations: QualificationAllocation[] = [
      { id: `alloc_pool_${runId}`, runId, kind: "POOL", identity: plan.pool, intentDigest: createHash("sha256").update(`${plan.canonicalDigest}:pool`).digest("hex"), state: "INTENT", receipt: null, createdAt: now },
      { id: `alloc_stage_${runId}`, runId, kind: "STAGING", identity: `${plan.stageStorage}:${plan.stageVolumeId}`, intentDigest: createHash("sha256").update(`${plan.canonicalDigest}:staging`).digest("hex"), state: "INTENT", receipt: null, createdAt: now },
    ];
    return this.store.createQualificationRun({ run, resources, allocations, event: { installationId, projectId: "infrastructure", resourceId: null, type: "qualification.run_intent", timestamp: now, payload: { runId, planDigest: plan.canonicalDigest, imageManifestDigest: image.manifestDigest } } });
  }

  async advance(runId: string): Promise<QualificationRun> {
    const run = await this.store.getQualificationRun(runId);
    if (!run) throw new KilnError("NOT_FOUND", 404, "Qualification run was not found");
    if (run.status !== "ACTIVE") return run;
    assertPlan(run.plan);
    await this.assertProof(run);
    const next = await this.nextPhase(run);
    if (!next) return (await this.store.getQualificationRun(runId))!;
    const intentDigest = phaseIntent(run.plan, next);
    const begun = await this.store.beginQualificationPhase({ runId, name: next, intentDigest, event: this.event(run, "qualification.phase_intent", { phase: next, intentDigest }) });
    if (!begun.dispatch) return run;
    try {
      const receipt = await this.provider.executeQualificationPhase(await this.context(run, next));
      if (receipt.tokenIdentity !== this.profile.tokenIdentity || receipt.requestDigest !== intentDigest || !/^[a-f0-9]{64}$/.test(receipt.dispatchDigest)) throw new KilnError("SAFETY_DENIED", 403, "Qualification receipt does not match its immutable request");
      this.assertReceipt(receipt, run, next);
      await this.store.submitQualificationPhase(runId, next, structuredClone(receipt), this.event(run, "qualification.phase_submitted", { phase: next }));
    } catch (error) {
      await this.store.markQualificationPhaseUnknown(runId, next, "DISPATCH_UNKNOWN", this.event(run, "qualification.phase_unknown", { phase: next, reason: "DISPATCH_UNKNOWN" }));
      throw error;
    }
    return (await this.store.getQualificationRun(runId))!;
  }

  async getRun(runId: string): Promise<QualificationRun | null> { return this.store.getQualificationRun(runId); }
  async status(runId: string): Promise<{ run: QualificationRun; phases: Array<Pick<QualificationPhase, "name" | "status" | "safeReason" | "createdAt" | "reconciliationDeadline" | "submittedAt" | "completedAt">>; allocations: Array<Pick<QualificationAllocation, "id" | "kind" | "state">> } | null> {
    const run = await this.store.getQualificationRun(runId);
    if (!run) return null;
    const phases = (await Promise.all(qualificationPhases.map((name) => this.store.getQualificationPhase(run.id, name)))).flatMap((phase) => phase ? [{ name: phase.name, status: phase.status, safeReason: phase.safeReason, createdAt: phase.createdAt, reconciliationDeadline: phase.reconciliationDeadline, submittedAt: phase.submittedAt, completedAt: phase.completedAt }] : []);
    const allocations = (await this.store.listQualificationAllocations(run.id)).map((allocation) => ({ id: allocation.id, kind: allocation.kind, state: allocation.state }));
    return { run, phases, allocations };
  }

  async recoverInstallation(): Promise<void> {
    const run = await this.store.getQualificationRunByInstallation(await this.store.installationId());
    if (!run || run.status !== "ACTIVE") return;
    for (const name of qualificationPhases) {
      const phase = await this.store.getQualificationPhase(run.id, name);
      if (!phase) return;
      if (phase.status === "INTENT") {
        await this.store.markQualificationPhaseUnknown(run.id, name, "RECOVERED_INTENT", this.event(run, "qualification.phase_unknown", { phase: name, reason: "RECOVERED_INTENT" }));
        return;
      }
      if (phase.status !== "COMPLETED") return;
    }
  }

  private async nextPhase(run: QualificationRun): Promise<QualificationPhaseName | null> {
    for (const name of qualificationPhases) {
      const phase = await this.store.getQualificationPhase(run.id, name);
      if (!phase) return name;
      if (phase.intentDigest !== phaseIntent(run.plan, name)) throw new KilnError("SAFETY_DENIED", 403, "Qualification phase intent changed");
      if (phase.status === "UNKNOWN") throw new KilnError("OPERATION_UNRESOLVED", 409, "Qualification run has an unknown phase");
      if (phase.status === "INTENT") return null;
      if (phase.status === "SUBMITTED") {
        if (!phase.receipt) throw new KilnError("OPERATION_UNRESOLVED", 409, "Qualification phase has no receipt");
        this.assertReceipt(phase.receipt, run, name);
        if (Number.isNaN(Date.parse(phase.reconciliationDeadline)) || phase.reconciliationDeadline <= this.clock().toISOString()) {
          await this.store.markQualificationPhaseUnknown(run.id, name, "DEADLINE_EXCEEDED", this.event(run, "qualification.phase_unknown", { phase: name, reason: "DEADLINE_EXCEEDED" }));
          return null;
        }
        const observation = await this.provider.inspectQualificationPhase(await this.context(run, name), structuredClone(phase.receipt));
        if (observation.status === "COMPLETED") {
          if (observation.receiptPatch) {
            const patch = observation.receiptPatch;
            if (name !== "CLONE" || Object.keys(patch).sort().join(",") !== "generatedCtime,generatedUuid,responseDigest" || typeof patch.generatedUuid !== "string" || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(patch.generatedUuid) || typeof patch.generatedCtime !== "string" || !/^[1-9][0-9]*$/.test(patch.generatedCtime)) throw new KilnError("SAFETY_DENIED", 403, "Qualification generated evidence is invalid");
            this.assertReceipt({ ...phase.receipt, ...patch }, run, name);
          }
          await this.assertProof(run);
          const allocationKind = name === "POOL_CREATE" ? "POOL" : name === "UPLOAD" ? "STAGING" : null;
          if (allocationKind) await this.store.completeQualificationPhaseAndAllocation(run.id, name, allocationKind, this.event(run, "qualification.phase_completed", { phase: name }), observation.receiptPatch);
          else await this.store.completeQualificationPhase(run.id, name, this.event(run, "qualification.phase_completed", { phase: name }), observation.receiptPatch);
        }
        else if (observation.status !== "RUNNING") await this.store.markQualificationPhaseUnknown(run.id, name, observation.status, this.event(run, "qualification.phase_unknown", { phase: name, reason: observation.status }));
        return null;
      }
    }
    return null;
  }

  private event(run: QualificationRun, type: string, payload: Record<string, unknown>): Omit<Event, "id"> {
    return { installationId: run.installationId, projectId: "infrastructure", resourceId: null, type, timestamp: this.clock().toISOString(), payload };
  }
  private async context(run: QualificationRun, phase: QualificationPhaseName): Promise<QualificationExecutionContext> {
    await this.assertProof(run);
    const priorReceipts: Partial<Record<QualificationPhaseName, QualificationReceipt>> = {};
    for (const name of qualificationPhases) {
      if (name === phase) break;
      const previous = await this.store.getQualificationPhase(run.id, name);
      if (!previous || previous.status !== "COMPLETED" || (previous.receipt && previous.receipt.requestDigest !== phaseIntent(run.plan, name))) throw new KilnError("SAFETY_DENIED", 403, "Qualification phase history is incomplete");
      if (!previous.receipt) throw new KilnError("SAFETY_DENIED", 403, "Qualification phase receipt is missing");
      this.assertReceipt(previous.receipt, run, name);
      priorReceipts[name] = structuredClone(previous.receipt);
    }
    return { plan: structuredClone(run.plan), phase, priorReceipts, requestDigest: phaseIntent(run.plan, phase) };
  }

  private assertReceipt(receipt: QualificationReceipt, run: QualificationRun, name: QualificationPhaseName): void {
    if (receipt.requestDigest !== phaseIntent(run.plan, name) || receipt.tokenIdentity !== run.plan.tokenIdentity || receipt.tokenIdentity !== this.profile.tokenIdentity || !/^[a-f0-9]{64}$/.test(receipt.responseDigest)) throw new KilnError("SAFETY_DENIED", 403, "Qualification receipt identity changed");
    if (!receipt.dispatch || canonicalQualificationDispatch(receipt.dispatch) !== receipt.dispatchDigest) throw new KilnError("SAFETY_DENIED", 403, "Qualification dispatch evidence changed");
  }

  private async assertProof(run: QualificationRun): Promise<void> {
    const deny = () => { throw new KilnError("SAFETY_DENIED", 403, "Qualification ownership proof is incomplete or changed"); };
    const plan = run.plan;
    if (run.installationId !== await this.store.installationId() || plan.installationId !== run.installationId) deny();
    for (const key of Object.keys(this.profile) as Array<keyof QualificationProfile>) if (plan[key] !== this.profile[key]) deny();
    const proof = await this.store.getQualificationProof(run.id);
    assertQualificationOwnership(run, proof);
  }
}

export function assertQualificationOwnership(run: QualificationRun, proof: QualificationProof): void {
  const plan = run.plan;
  const deny = () => { throw new KilnError("SAFETY_DENIED", 403, "Qualification ownership proof is incomplete or changed"); };
    const complete = (name: QualificationPhaseName) => proof.phases.some((phase) => phase.name === name && phase.status === "COMPLETED");
    if (proof.resources.length !== 2 || proof.allocations.length !== 2 || proof.children.length !== 3) deny();
    for (const [id, vmid, type, destroyed] of [
      [plan.templateResourceId, plan.templateVmid, "image_template", complete("DESTROY_TEMPLATE")],
      [plan.probeResourceId, plan.probeVmid, "network_probe", complete("DESTROY_PROBE")],
    ] as const) {
      const resource = proof.resources.find((item) => item.id === id);
      if (!resource || resource.installationId !== plan.installationId || resource.ownership !== "KILN_MANAGED" || resource.projectId !== "infrastructure" || resource.type !== type || resource.providerId !== "proxmox" || resource.providerKind !== "qemu" || resource.providerResourceId !== vmid || resource.node !== plan.node || resource.pool !== plan.pool || resource.provenanceRequired !== true || resource.createdBy !== "qualification" || resource.expiresAt !== null || resource.state !== (destroyed ? "DESTROYED" : "PROVISIONING")) deny();
    }
    for (const [kind, identity, suffix, phaseName] of [
      ["POOL", plan.pool, "pool", "POOL_CREATE"],
      ["STAGING", `${plan.stageStorage}:${plan.stageVolumeId}`, "staging", "UPLOAD"],
    ] as const) {
      const allocation = proof.allocations.find((item) => item.kind === kind);
      const phase = proof.phases.find((item) => item.name === phaseName);
      if (!allocation || allocation.runId !== run.id || allocation.identity !== identity || allocation.intentDigest !== createHash("sha256").update(`${plan.canonicalDigest}:${suffix}`).digest("hex") || allocation.state !== (complete(phaseName) ? "RETAINED" : "INTENT")) deny();
      if (complete(phaseName) && (!phase?.receipt || canonicalQualificationDispatch(allocation!.receipt) !== canonicalQualificationDispatch(phase.receipt))) deny();
    }
    for (const [volume, owner] of [
      [`vm-${plan.templateVmid}-disk-0`, plan.templateResourceId],
      [plan.templateBootVolume, plan.templateResourceId],
      [plan.probeBootVolume, plan.probeResourceId],
    ]) if (!proof.children.some((child) => child.nativeId === `${plan.targetStorage}:${volume}` && child.resourceId === owner)) deny();
}
