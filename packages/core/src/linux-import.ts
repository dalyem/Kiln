import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { KilnError, type Event, type Resource, type Store } from "./index.js";
import {
  assertQualificationOwnership,
  type QualificationStore,
} from "./qualification.js";
import { verifyImageFile, maxImageFileArtifactBytes } from "./image-file.js";
import {
  type ImageManifest,
  type TrustedImageKeys,
  type VerifiedImage,
} from "./provenance.js";
import { parseLinuxBuildMetadata } from "./linux-build-metadata.js";

// PVE staging deletion is deliberately absent. It needs its own qualified receipt and absence proof.
export const linuxImportPhases = [
  "UPLOAD",
  "IMPORT",
  "TEMPLATE",
  "CLONE",
  "STAMP",
  "START",
  "STOP",
  "DESTROY_CLONE",
  "DESTROY_TEMPLATE",
] as const;
export type LinuxImportPhaseName = (typeof linuxImportPhases)[number];
export type LinuxImportPhaseStatus =
  | "INTENT"
  | "SUBMITTED"
  | "COMPLETED"
  | "UNKNOWN";
export interface LinuxImportReceipt {
  taskId: string | null;
  tokenIdentity: string;
  workerType: string | null;
  sourceVmid: string | null;
  destinationVmid: string | null;
  requestDigest: string;
  dispatch: {
    method: string;
    path: string;
    body: Record<string, string | number> | null;
  };
  dispatchDigest: string;
  responseDigest: string;
  generatedUuid: string | null;
  generatedCtime: string | null;
  configDigest: string | null;
}
export interface LinuxImportPhase {
  runId: string;
  name: LinuxImportPhaseName;
  status: LinuxImportPhaseStatus;
  intentDigest: string;
  receipt: LinuxImportReceipt | null;
  safeReason: string | null;
  createdAt: string;
  reconciliationDeadline: string;
  submittedAt: string | null;
  completedAt: string | null;
}
export interface LinuxImportPlan {
  schemaVersion: 1;
  installationId: string;
  node: string;
  pool: string;
  stageStorage: string;
  targetStorage: string;
  pveVersion: "9.2.2";
  tokenIdentity: string;
  storageConfigDigest: string;
  stageId: string;
  stagePath: string;
  stageSha256: string;
  templateVmid: string;
  cloneVmid: string;
  templateName: string;
  cloneName: string;
  sourcePoolRunId: string;
  sourcePoolAllocationId: string;
  sourcePoolNonce: string;
  sourcePoolComment: string;
  templateResourceId: string;
  cloneResourceId: string;
  templateNonce: string;
  cloneNonce: string;
  image: Pick<
    VerifiedImage,
    "id" | "manifest" | "manifestDigest" | "signerFingerprint" | "policyDigest"
  >;
  buildMetadataSha256: string;
  canonicalDigest: string;
}
export interface LinuxImportRun {
  id: string;
  installationId: string;
  idempotencyKey: string;
  normalizedPayload: string;
  status: "ACTIVE" | "COMPLETED" | "UNKNOWN";
  plan: LinuxImportPlan;
  createdAt: string;
  completedAt: string | null;
}
export interface LinuxImportAllocation {
  id: string;
  runId: string;
  kind: "STAGING" | "TEMPLATE_DISK" | "CLONE_DISK";
  identity: string;
  intentDigest: string;
  state: "RESERVED" | "RETAINED" | "DESTROYED" | "UNKNOWN";
  createdAt: string;
}
export interface LinuxImportProof {
  resources: Resource[];
  allocations: LinuxImportAllocation[];
  children: Array<{ nativeId: string; resourceId: string }>;
  phases: LinuxImportPhase[];
}
export interface LinuxImportStore {
  createLinuxImportRun(input: {
    run: LinuxImportRun;
    resources: Resource[];
    allocations: LinuxImportAllocation[];
    event: Omit<Event, "id">;
  }): Promise<{ run: LinuxImportRun; replayed: boolean }>;
  getLinuxImportRun(id: string): Promise<LinuxImportRun | null>;
  listActiveLinuxImportRuns(): Promise<LinuxImportRun[]>;
  listLinuxImportPhases(runId: string): Promise<LinuxImportPhase[]>;
  getLinuxImportProof(id: string): Promise<LinuxImportProof>;
  getLinuxImportPhase(
    runId: string,
    name: LinuxImportPhaseName,
  ): Promise<LinuxImportPhase | null>;
  beginLinuxImportPhase(input: {
    runId: string;
    name: LinuxImportPhaseName;
    intentDigest: string;
    event: Omit<Event, "id">;
  }): Promise<{ phase: LinuxImportPhase; dispatch: boolean }>;
  submitLinuxImportPhase(
    runId: string,
    name: LinuxImportPhaseName,
    receipt: LinuxImportReceipt,
    event: Omit<Event, "id">,
  ): Promise<void>;
  completeLinuxImportPhase(
    runId: string,
    name: LinuxImportPhaseName,
    event: Omit<Event, "id">,
    receiptPatch?: Pick<
      LinuxImportReceipt,
      "generatedUuid" | "generatedCtime" | "responseDigest" | "configDigest"
    >,
  ): Promise<void>;
  markLinuxImportPhaseUnknown(
    runId: string,
    name: LinuxImportPhaseName,
    reason: string,
    event: Omit<Event, "id">,
  ): Promise<void>;
}
export interface LinuxImportInspection {
  status: "RUNNING" | "COMPLETED" | "FAILED" | "MISMATCH" | "UNKNOWN";
  receiptPatch?: Pick<
    LinuxImportReceipt,
    "generatedUuid" | "generatedCtime" | "responseDigest" | "configDigest"
  >;
}
export interface LinuxImportProvider {
  executeLinuxImportPhase(context: {
    plan: LinuxImportPlan;
    phase: LinuxImportPhaseName;
    priorReceipts: Partial<Record<LinuxImportPhaseName, LinuxImportReceipt>>;
    requestDigest: string;
  }): Promise<LinuxImportReceipt>;
  inspectLinuxImportPhase(context: {
    plan: LinuxImportPlan;
    phase: LinuxImportPhaseName;
    receipt: LinuxImportReceipt;
    priorReceipts: Partial<Record<LinuxImportPhaseName, LinuxImportReceipt>>;
  }): Promise<LinuxImportInspection>;
}
export interface LinuxImportProfile {
  node: string;
  pool: string;
  stageStorage: string;
  targetStorage: string;
  pveVersion: "9.2.2";
  tokenIdentity: string;
  storageConfigDigest: string;
  templateVmid: string;
  cloneVmid: string;
  templateName: string;
  cloneName: string;
  sourcePoolRunId: string;
  sourcePoolAllocationId: string;
  sourcePoolNonce: string;
  sourcePoolComment: string;
}
export interface LinuxImportRequest {
  stagingId: string;
  manifest: ImageManifest;
  signature: string;
  buildMetadataBase64: string;
}

export function canonicalLinuxImportPlan(
  plan: Omit<LinuxImportPlan, "canonicalDigest">,
): string {
  const image = plan.image;
  const manifest = image.manifest;
  return createHash("sha256")
    .update(
      JSON.stringify({
        schemaVersion: plan.schemaVersion,
        installationId: plan.installationId,
        node: plan.node,
        pool: plan.pool,
        stageStorage: plan.stageStorage,
        targetStorage: plan.targetStorage,
        pveVersion: plan.pveVersion,
        tokenIdentity: plan.tokenIdentity,
        storageConfigDigest: plan.storageConfigDigest,
        stageId: plan.stageId,
        stagePath: plan.stagePath,
        stageSha256: plan.stageSha256,
        templateVmid: plan.templateVmid,
        cloneVmid: plan.cloneVmid,
        templateName: plan.templateName,
        cloneName: plan.cloneName,
        sourcePoolRunId: plan.sourcePoolRunId,
        sourcePoolAllocationId: plan.sourcePoolAllocationId,
        sourcePoolNonce: plan.sourcePoolNonce,
        sourcePoolComment: plan.sourcePoolComment,
        templateResourceId: plan.templateResourceId,
        cloneResourceId: plan.cloneResourceId,
        templateNonce: plan.templateNonce,
        cloneNonce: plan.cloneNonce,
        image: {
          id: image.id,
          manifest: {
            schemaVersion: manifest.schemaVersion,
            name: manifest.name,
            version: manifest.version,
            arch: manifest.arch,
            artifactSha256: manifest.artifactSha256,
            artifactSize: manifest.artifactSize,
            sourceBuild: manifest.sourceBuild,
            capabilities: manifest.capabilities,
            keyId: manifest.keyId,
          },
          manifestDigest: image.manifestDigest,
          signerFingerprint: image.signerFingerprint,
          policyDigest: image.policyDigest,
        },
        buildMetadataSha256: plan.buildMetadataSha256,
      }),
    )
    .digest("hex");
}

export class LinuxImageImportService {
  constructor(
    private readonly store: Store & LinuxImportStore & QualificationStore,
    private readonly provider: LinuxImportProvider,
    private readonly keys: TrustedImageKeys,
    private readonly profile: LinuxImportProfile,
    private readonly staging: {
      pathFor(id: string): string;
      describe(
        id: string,
      ): Promise<{ id: string; path: string; size: number; sha256: string }>;
    },
    private readonly clock = () => new Date(),
  ) {}

  async createRun(
    input: LinuxImportRequest,
    idempotencyKey: string,
  ): Promise<{ run: LinuxImportRun; replayed: boolean }> {
    if (!/^lstg_[a-f0-9]{32}$/.test(input.stagingId))
      throw new KilnError(
        "INVALID_INPUT",
        400,
        "Linux image staging ID is invalid",
      );
    const metadata = await decodeBuildMetadata(input.buildMetadataBase64);
    const staged = await this.staging.describe(input.stagingId);
    const artifactPath = staged.path;
    if (
      staged.size !== input.manifest.artifactSize ||
      staged.sha256 !== input.manifest.artifactSha256
    )
      throw new KilnError(
        "INVALID_INPUT",
        400,
        "Linux image staging descriptor does not match its manifest",
      );
    const image = await verifyImageFile(
      { manifest: input.manifest, signature: input.signature, artifactPath },
      this.keys,
      this.clock().toISOString(),
    ).catch((error) => {
      throw new KilnError(
        "INVALID_INPUT",
        400,
        error instanceof Error ? error.message : "Linux image is invalid",
      );
    });
    if (
      input.manifest.sourceBuild !== `sha256:${metadata.digest}` ||
      metadata.artifactSha256 !== input.manifest.artifactSha256
    )
      throw new KilnError(
        "INVALID_INPUT",
        400,
        "Signed build metadata does not bind the staged Linux image",
      );
    const installationId = await this.store.installationId();
    const sourceRun = await this.store.getQualificationRun(
      this.profile.sourcePoolRunId,
    );
    const sourceProof = await this.store.getQualificationProof(
      this.profile.sourcePoolRunId,
    );
    if (
      !sourceRun ||
      sourceRun.status !== "COMPLETED" ||
      sourceRun.installationId !== installationId ||
      sourceRun.plan.pool !== this.profile.pool ||
      sourceRun.plan.poolNonce !== this.profile.sourcePoolNonce ||
      sourceRun.plan.poolComment !== this.profile.sourcePoolComment
    )
      throw new KilnError(
        "SAFETY_DENIED",
        403,
        "Linux image import does not have a completed owned pool proof",
      );
    assertQualificationOwnership(sourceRun, sourceProof);
    const allocation = sourceProof.allocations.find(
      (entry) =>
        entry.id === this.profile.sourcePoolAllocationId &&
        entry.kind === "POOL",
    );
    if (
      !allocation ||
      allocation.state !== "RETAINED" ||
      allocation.identity !== this.profile.pool ||
      !allocation.receipt
    )
      throw new KilnError(
        "SAFETY_DENIED",
        403,
        "Linux image import pool allocation proof is incomplete",
      );
    const now = this.clock().toISOString();
    const runId = `limp_${randomUUID().replaceAll("-", "")}`;
    const templateResourceId = `img_template_${randomUUID().replaceAll("-", "")}`;
    const cloneResourceId = `img_clone_${randomUUID().replaceAll("-", "")}`;
    const stage = await stableFile(
      artifactPath,
      input.manifest.artifactSize,
      input.manifest.artifactSha256,
    );
    const bare: Omit<LinuxImportPlan, "canonicalDigest"> = {
      schemaVersion: 1,
      installationId,
      node: this.profile.node,
      pool: this.profile.pool,
      stageStorage: this.profile.stageStorage,
      targetStorage: this.profile.targetStorage,
      pveVersion: this.profile.pveVersion,
      tokenIdentity: this.profile.tokenIdentity,
      storageConfigDigest: this.profile.storageConfigDigest,
      stageId: input.stagingId,
      stagePath: artifactPath,
      stageSha256: stage.sha256,
      templateVmid: this.profile.templateVmid,
      cloneVmid: this.profile.cloneVmid,
      templateName: this.profile.templateName,
      cloneName: this.profile.cloneName,
      sourcePoolRunId: this.profile.sourcePoolRunId,
      sourcePoolAllocationId: this.profile.sourcePoolAllocationId,
      sourcePoolNonce: this.profile.sourcePoolNonce,
      sourcePoolComment: this.profile.sourcePoolComment,
      templateResourceId,
      cloneResourceId,
      templateNonce: randomUUID(),
      cloneNonce: randomUUID(),
      image: {
        id: image.id,
        manifest: image.manifest,
        manifestDigest: image.manifestDigest,
        signerFingerprint: image.signerFingerprint,
        policyDigest: image.policyDigest,
      },
      buildMetadataSha256: metadata.digest,
    };
    const plan = { ...bare, canonicalDigest: canonicalLinuxImportPlan(bare) };
    const normalizedPayload = JSON.stringify({
      stagingId: input.stagingId,
      manifest: input.manifest,
      signature: input.signature,
      metadata: metadata.digest,
    });
    const run: LinuxImportRun = {
      id: runId,
      installationId,
      idempotencyKey,
      normalizedPayload,
      status: "ACTIVE",
      plan,
      createdAt: now,
      completedAt: null,
    };
    const resource = (
      id: string,
      vmid: string,
      type: Resource["type"],
    ): Resource => ({
      id,
      installationId,
      projectId: "infrastructure",
      type,
      ownership: "KILN_MANAGED",
      state: "PROVISIONING",
      providerId: "proxmox",
      providerResourceId: vmid,
      providerKind: "qemu",
      node: plan.node,
      pool: plan.pool,
      createdBy: "linux-image-import",
      createdAt: now,
      expiresAt: null,
      profile: "proxmox-linux-image-import",
      provenanceRequired: true,
    });
    const allocations: LinuxImportAllocation[] = [
      {
        id: `alloc_stage_${runId}`,
        runId,
        kind: "STAGING",
        identity: plan.stageId,
        intentDigest: digestIntent(plan, "STAGING"),
        state: "RESERVED",
        createdAt: now,
      },
      {
        id: `alloc_template_${runId}`,
        runId,
        kind: "TEMPLATE_DISK",
        identity: `${plan.targetStorage}:vm-${plan.templateVmid}-disk-0`,
        intentDigest: digestIntent(plan, "TEMPLATE_DISK"),
        state: "RESERVED",
        createdAt: now,
      },
      {
        id: `alloc_clone_${runId}`,
        runId,
        kind: "CLONE_DISK",
        identity: `${plan.targetStorage}:vm-${plan.cloneVmid}-disk-0`,
        intentDigest: digestIntent(plan, "CLONE_DISK"),
        state: "RESERVED",
        createdAt: now,
      },
    ];
    return this.store.createLinuxImportRun({
      run,
      resources: [
        resource(templateResourceId, plan.templateVmid, "image_template"),
        resource(cloneResourceId, plan.cloneVmid, "execution"),
      ],
      allocations,
      event: {
        installationId,
        projectId: "infrastructure",
        resourceId: null,
        type: "linux_import.run_intent",
        timestamp: now,
        payload: {
          runId,
          planDigest: plan.canonicalDigest,
          stagingId: input.stagingId,
        },
      },
    });
  }

  async advance(runId: string): Promise<LinuxImportRun> {
    const run = await this.store.getLinuxImportRun(runId);
    if (!run)
      throw new KilnError("NOT_FOUND", 404, "Linux image import was not found");
    if (run.status !== "ACTIVE") return run;
    if (
      canonicalLinuxImportPlan({
        ...run.plan,
        canonicalDigest: undefined,
      } as Omit<LinuxImportPlan, "canonicalDigest">) !==
      run.plan.canonicalDigest
    )
      throw new KilnError(
        "SAFETY_DENIED",
        403,
        "Linux image import plan changed",
      );
    const existing = await Promise.all(
      linuxImportPhases.map((name) =>
        this.store.getLinuxImportPhase(runId, name),
      ),
    );
    await this.assertProof(run);
    const current = existing.find((phase) => phase?.status === "SUBMITTED");
    if (current) return this.reconcile(run, current);
    if (existing.some((phase) => phase?.status === "UNKNOWN")) return run;
    const name = linuxImportPhases[existing.filter(Boolean).length];
    if (!name) return run;
    const intentDigest = createHash("sha256")
      .update(`${run.plan.canonicalDigest}:${name}`)
      .digest("hex");
    const begun = await this.store.beginLinuxImportPhase({
      runId,
      name,
      intentDigest,
      event: this.event(run, "linux_import.phase_intent", {
        phase: name,
        intentDigest,
      }),
    });
    if (!begun.dispatch) return run;
    let receipt: LinuxImportReceipt;
    try {
      receipt = await this.provider.executeLinuxImportPhase({
        plan: run.plan,
        phase: name,
        priorReceipts: receiptMap(existing),
        requestDigest: intentDigest,
      });
      if (
        receipt.requestDigest !== intentDigest ||
        !/^[a-f0-9]{64}$/.test(receipt.dispatchDigest) ||
        !/^[a-f0-9]{64}$/.test(receipt.responseDigest) ||
        !receipt.tokenIdentity ||
        !receipt.dispatch ||
        !["POST", "PUT", "DELETE"].includes(receipt.dispatch.method)
      )
        throw new KilnError(
          "SAFETY_DENIED",
          403,
          "Linux image import receipt is invalid",
        );
      await this.store.submitLinuxImportPhase(
        runId,
        name,
        receipt,
        this.event(run, "linux_import.phase_submitted", { phase: name }),
      );
    } catch (error) {
      await this.store.markLinuxImportPhaseUnknown(
        runId,
        name,
        "DISPATCH_UNKNOWN",
        this.event(run, "linux_import.phase_unknown", { phase: name }),
      );
      throw error;
    }
    return this.reconcile(run, {
      ...begun.phase,
      status: "SUBMITTED",
      receipt,
    });
  }
  async status(runId: string): Promise<LinuxImportRun | null> {
    return this.store.getLinuxImportRun(runId);
  }
  async statusDetail(
    runId: string,
  ): Promise<{
    run: LinuxImportRun;
    phases: Array<
      Pick<
        LinuxImportPhase,
        | "name"
        | "status"
        | "safeReason"
        | "createdAt"
        | "reconciliationDeadline"
        | "submittedAt"
        | "completedAt"
      >
    >;
  } | null> {
    const run = await this.store.getLinuxImportRun(runId);
    if (!run) return null;
    const phases = (await this.store.listLinuxImportPhases(runId))
      .sort(
        (left, right) =>
          linuxImportPhases.indexOf(left.name) -
          linuxImportPhases.indexOf(right.name),
      )
      .map((phase) => ({
        name: phase.name,
        status: phase.status,
        safeReason: phase.safeReason,
        createdAt: phase.createdAt,
        reconciliationDeadline: phase.reconciliationDeadline,
        submittedAt: phase.submittedAt,
        completedAt: phase.completedAt,
      }));
    return { run, phases };
  }
  async recoverInstallation(): Promise<void> {
    for (const run of await this.store.listActiveLinuxImportRuns()) {
      try {
        const phases = await this.store.listLinuxImportPhases(run.id);
        const receiptless = phases.find((phase) => phase.status === "INTENT");
        if (receiptless) {
          await this.store.markLinuxImportPhaseUnknown(
            run.id,
            receiptless.name,
            "RECOVERED_INTENT",
            this.event(run, "linux_import.phase_unknown", {
              phase: receiptless.name,
            }),
          );
          continue;
        }
        const submitted = phases.find((phase) => phase.status === "SUBMITTED");
        if (submitted) await this.reconcile(run, submitted);
      } catch {
        const phase = await this.store
          .listLinuxImportPhases(run.id)
          .then((phases) =>
            phases.find(
              (item) => item.status === "INTENT" || item.status === "SUBMITTED",
            ),
          )
          .catch(() => undefined);
        if (phase)
          await this.store
            .markLinuxImportPhaseUnknown(
              run.id,
              phase.name,
              "RECOVERY_SAFETY_PROOF_FAILED",
              this.event(run, "linux_import.phase_unknown", {
                phase: phase.name,
              }),
            )
            .catch(() => undefined);
        await this.store
          .appendEvent(
            this.event(run, "linux_import.recovery_safety_failed", {
              runId: run.id,
            }),
          )
          .catch(() => undefined);
      }
    }
  }
  private async reconcile(
    run: LinuxImportRun,
    phase: LinuxImportPhase,
  ): Promise<LinuxImportRun> {
    if (!phase.receipt)
      throw new KilnError(
        "SAFETY_DENIED",
        403,
        "Linux image import receipt is missing",
      );
    await this.assertProof(run);
    const prior = await Promise.all(
      linuxImportPhases.map((name) =>
        this.store.getLinuxImportPhase(run.id, name),
      ),
    );
    let result: LinuxImportInspection;
    try {
      result = await this.provider.inspectLinuxImportPhase({
        plan: run.plan,
        phase: phase.name,
        receipt: phase.receipt,
        priorReceipts: receiptMap(prior),
      });
    } catch {
      if (Date.parse(phase.reconciliationDeadline) <= this.clock().getTime())
        await this.store.markLinuxImportPhaseUnknown(
          run.id,
          phase.name,
          "RECONCILIATION_OBSERVATION_FAILED_DEADLINE",
          this.event(run, "linux_import.phase_unknown", {
            phase: phase.name,
            result: "OBSERVATION_FAILED",
          }),
        );
      else
        await this.store
          .appendEvent(
            this.event(run, "linux_import.phase_observation_failed", {
              phase: phase.name,
            }),
          )
          .catch(() => undefined);
      return (await this.store.getLinuxImportRun(run.id))!;
    }
    if (result.status === "COMPLETED")
      await this.store.completeLinuxImportPhase(
        run.id,
        phase.name,
        this.event(run, "linux_import.phase_completed", { phase: phase.name }),
        result.receiptPatch,
      );
    else if (
      ["FAILED", "MISMATCH"].includes(result.status) ||
      (result.status === "UNKNOWN" &&
        Date.parse(phase.reconciliationDeadline) <= this.clock().getTime())
    )
      await this.store.markLinuxImportPhaseUnknown(
        run.id,
        phase.name,
        result.status === "UNKNOWN"
          ? "RECONCILIATION_DEADLINE_EXCEEDED"
          : result.status,
        this.event(run, "linux_import.phase_unknown", {
          phase: phase.name,
          result: result.status,
        }),
      );
    return (await this.store.getLinuxImportRun(run.id))!;
  }
  private event(
    run: LinuxImportRun,
    type: string,
    payload: Record<string, unknown>,
  ): Omit<Event, "id"> {
    return {
      installationId: run.installationId,
      projectId: "infrastructure",
      resourceId: null,
      type,
      timestamp: this.clock().toISOString(),
      payload,
    };
  }
  private async assertProof(run: LinuxImportRun): Promise<void> {
    if (
      canonicalLinuxImportPlan({
        ...run.plan,
        canonicalDigest: undefined,
      } as Omit<LinuxImportPlan, "canonicalDigest">) !==
      run.plan.canonicalDigest
    )
      throw new KilnError(
        "SAFETY_DENIED",
        403,
        "Linux image import plan changed",
      );
    assertLinuxImportOwnership(
      run,
      await this.store.getLinuxImportProof(run.id),
    );
    const source = await this.store.getQualificationRun(
      run.plan.sourcePoolRunId,
    );
    const sourceProof = await this.store.getQualificationProof(
      run.plan.sourcePoolRunId,
    );
    if (
      !source ||
      source.status !== "COMPLETED" ||
      source.installationId !== run.installationId ||
      source.plan.pool !== run.plan.pool ||
      source.plan.poolNonce !== run.plan.sourcePoolNonce ||
      source.plan.poolComment !== run.plan.sourcePoolComment
    )
      throw new KilnError(
        "SAFETY_DENIED",
        403,
        "Linux image import source pool proof changed",
      );
    assertQualificationOwnership(source, sourceProof);
    const allocation = sourceProof.allocations.find(
      (entry) =>
        entry.id === run.plan.sourcePoolAllocationId && entry.kind === "POOL",
    );
    if (
      !allocation ||
      allocation.state !== "RETAINED" ||
      allocation.identity !== run.plan.pool ||
      !allocation.receipt
    )
      throw new KilnError(
        "SAFETY_DENIED",
        403,
        "Linux image import source pool allocation changed",
      );
  }
}
function receiptMap(
  phases: Array<LinuxImportPhase | null>,
): Partial<Record<LinuxImportPhaseName, LinuxImportReceipt>> {
  return Object.fromEntries(
    phases.flatMap((phase) =>
      phase?.receipt ? [[phase.name, phase.receipt]] : [],
    ),
  ) as Partial<Record<LinuxImportPhaseName, LinuxImportReceipt>>;
}
export function assertLinuxImportOwnership(
  run: LinuxImportRun,
  proof: LinuxImportProof,
): void {
  const p = run.plan;
  if (p.installationId !== run.installationId)
    throw new KilnError(
      "SAFETY_DENIED",
      403,
      "Linux image import installation changed",
    );
  const byPhase = new Map<LinuxImportPhaseName, LinuxImportPhase>();
  for (const phase of proof.phases) {
    if (
      !linuxImportPhases.includes(phase.name) ||
      byPhase.has(phase.name) ||
      phase.runId !== run.id ||
      phase.intentDigest !== digestIntent(p, phase.name) ||
      !phase.reconciliationDeadline ||
      Number.isNaN(Date.parse(phase.reconciliationDeadline))
    )
      throw new KilnError(
        "SAFETY_DENIED",
        403,
        "Linux image import phases changed",
      );
    if (
      (phase.status === "INTENT" &&
        (phase.receipt || phase.submittedAt || phase.completedAt)) ||
      (phase.status === "SUBMITTED" &&
        (!phase.receipt || !phase.submittedAt || phase.completedAt)) ||
      (phase.status === "COMPLETED" &&
        (!phase.receipt || !phase.submittedAt || !phase.completedAt)) ||
      (phase.status === "UNKNOWN" && !phase.safeReason)
    )
      throw new KilnError(
        "SAFETY_DENIED",
        403,
        "Linux image import phase state changed",
      );
    byPhase.set(phase.name, phase);
  }
  for (const [index, name] of linuxImportPhases.entries()) {
    const phase = byPhase.get(name);
    if (!phase) continue;
    if (
      linuxImportPhases
        .slice(0, index)
        .some((prior) => byPhase.get(prior)?.status !== "COMPLETED") ||
      (phase.status !== "COMPLETED" &&
        linuxImportPhases.slice(index + 1).some((later) => byPhase.has(later)))
    )
      throw new KilnError(
        "SAFETY_DENIED",
        403,
        "Linux image import phase order changed",
      );
  }
  const done = new Set(
    proof.phases
      .filter((phase) => phase.status === "COMPLETED")
      .map((phase) => phase.name),
  );
  const unknown = proof.phases.find(
    (phase) => phase.status === "UNKNOWN",
  )?.name;
  const expectedResources = new Map<
    string,
    { type: Resource["type"]; vmid: string; state: Resource["state"] }
  >([
    [
      p.templateResourceId,
      {
        type: "image_template",
        vmid: p.templateVmid,
        state: done.has("DESTROY_TEMPLATE")
          ? "DESTROYED"
          : unknown &&
              ["IMPORT", "TEMPLATE", "DESTROY_TEMPLATE"].includes(unknown)
            ? "QUARANTINED"
            : "PROVISIONING",
      },
    ],
    [
      p.cloneResourceId,
      {
        type: "execution",
        vmid: p.cloneVmid,
        state: done.has("DESTROY_CLONE")
          ? "DESTROYED"
          : unknown &&
              ["CLONE", "STAMP", "START", "STOP", "DESTROY_CLONE"].includes(
                unknown,
              )
            ? "QUARANTINED"
            : "PROVISIONING",
      },
    ],
  ]);
  if (
    proof.resources.length !== 2 ||
    proof.resources.some((resource) => {
      const expected = expectedResources.get(resource.id);
      return (
        !expected ||
        resource.type !== expected.type ||
        resource.providerResourceId !== expected.vmid ||
        resource.installationId !== p.installationId ||
        resource.projectId !== "infrastructure" ||
        resource.expiresAt !== null ||
        resource.ownership !== "KILN_MANAGED" ||
        resource.state !== expected.state ||
        resource.providerId !== "proxmox" ||
        resource.providerKind !== "qemu" ||
        resource.node !== p.node ||
        resource.pool !== p.pool ||
        resource.profile !== "proxmox-linux-image-import" ||
        !resource.provenanceRequired ||
        resource.createdBy !== "linux-image-import"
      );
    })
  )
    throw new KilnError(
      "SAFETY_DENIED",
      403,
      "Linux image import resources changed",
    );
  const expectedChildren = new Map<string, string>([
    [`${p.targetStorage}:vm-${p.templateVmid}-disk-0`, p.templateResourceId],
    [`${p.targetStorage}:base-${p.templateVmid}-disk-0`, p.templateResourceId],
    [`${p.targetStorage}:vm-${p.cloneVmid}-disk-0`, p.cloneResourceId],
  ]);
  if (
    proof.children.length !== expectedChildren.size ||
    proof.children.some(
      (child) => expectedChildren.get(child.nativeId) !== child.resourceId,
    )
  )
    throw new KilnError(
      "SAFETY_DENIED",
      403,
      "Linux image import child reservations changed",
    );
  const templateBase = `${p.targetStorage}:base-${p.templateVmid}-disk-0`;
  const templateVm = `${p.targetStorage}:vm-${p.templateVmid}-disk-0`;
  const cloneVm = `${p.targetStorage}:vm-${p.cloneVmid}-disk-0`;
  const expectedAllocations = new Map<
    string,
    {
      kind: LinuxImportAllocation["kind"];
      identity: string;
      state: LinuxImportAllocation["state"];
    }
  >([
    [
      `alloc_stage_${run.id}`,
      {
        kind: "STAGING",
        identity: p.stageId,
        state:
          unknown === "UPLOAD"
            ? "UNKNOWN"
            : done.has("UPLOAD")
              ? "RETAINED"
              : "RESERVED",
      },
    ],
    [
      `alloc_template_${run.id}`,
      {
        kind: "TEMPLATE_DISK",
        identity:
          done.has("TEMPLATE") || done.has("DESTROY_TEMPLATE")
            ? templateBase
            : templateVm,
        state: ["IMPORT", "TEMPLATE", "DESTROY_TEMPLATE"].includes(
          unknown ?? "",
        )
          ? "UNKNOWN"
          : done.has("DESTROY_TEMPLATE")
            ? "DESTROYED"
            : done.has("IMPORT")
              ? "RETAINED"
              : "RESERVED",
      },
    ],
    [
      `alloc_clone_${run.id}`,
      {
        kind: "CLONE_DISK",
        identity: cloneVm,
        state: ["CLONE", "DESTROY_CLONE"].includes(unknown ?? "")
          ? "UNKNOWN"
          : done.has("DESTROY_CLONE")
            ? "DESTROYED"
            : done.has("CLONE")
              ? "RETAINED"
              : "RESERVED",
      },
    ],
  ]);
  if (
    proof.allocations.length !== expectedAllocations.size ||
    proof.allocations.some((allocation) => {
      const expected = expectedAllocations.get(allocation.id);
      return (
        !expected ||
        allocation.runId !== run.id ||
        allocation.kind !== expected.kind ||
        allocation.identity !== expected.identity ||
        allocation.state !== expected.state ||
        allocation.intentDigest !== digestIntent(p, allocation.kind)
      );
    })
  )
    throw new KilnError(
      "SAFETY_DENIED",
      403,
      "Linux image import allocations changed",
    );
}
function digestIntent(plan: LinuxImportPlan, name: string): string {
  return createHash("sha256")
    .update(`${plan.canonicalDigest}:${name}`)
    .digest("hex");
}

async function decodeBuildMetadata(
  value: string,
): Promise<{ digest: string; artifactSha256: string }> {
  let raw: Buffer;
  try {
    raw = Buffer.from(value, "base64");
  } catch {
    throw new KilnError(
      "INVALID_INPUT",
      400,
      "Linux build metadata is invalid",
    );
  }
  if (!raw.length || raw.length > 1024 * 1024)
    throw new KilnError(
      "INVALID_INPUT",
      400,
      "Linux build metadata is invalid",
    );
  let metadata;
  try {
    metadata = parseLinuxBuildMetadata(raw);
  } catch {
    throw new KilnError(
      "INVALID_INPUT",
      400,
      "Linux build metadata is invalid",
    );
  }
  return {
    digest: createHash("sha256").update(raw).digest("hex"),
    artifactSha256: metadata.artifactSha256,
  };
}
async function stableFile(
  path: string,
  size: number,
  expectedDigest: string,
): Promise<{ sha256: string }> {
  const first = await lstat(path, { bigint: true }).catch(() => {
    throw new KilnError(
      "SAFETY_DENIED",
      403,
      "Linux image staging file is missing",
    );
  });
  if (
    !first.isFile() ||
    first.isSymbolicLink() ||
    first.size !== BigInt(size) ||
    first.size > BigInt(maxImageFileArtifactBytes)
  )
    throw new KilnError(
      "SAFETY_DENIED",
      403,
      "Linux image staging file changed",
    );
  const file = await open(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  const hash = createHash("sha256");
  const chunk = Buffer.allocUnsafe(64 * 1024);
  let offset = 0;
  try {
    while (offset < size) {
      const { bytesRead } = await file.read(
        chunk,
        0,
        Math.min(chunk.length, size - offset),
        offset,
      );
      if (!bytesRead)
        throw new KilnError(
          "SAFETY_DENIED",
          403,
          "Linux image staging file changed",
        );
      hash.update(chunk.subarray(0, bytesRead));
      offset += bytesRead;
    }
  } finally {
    await file.close();
  }
  const after = await lstat(path, { bigint: true });
  if (
    first.dev !== after.dev ||
    first.ino !== after.ino ||
    first.mtimeNs !== after.mtimeNs ||
    first.ctimeNs !== after.ctimeNs ||
    hash.digest("hex") !== expectedDigest
  )
    throw new KilnError(
      "SAFETY_DENIED",
      403,
      "Linux image staging file changed",
    );
  return { sha256: expectedDigest };
}
