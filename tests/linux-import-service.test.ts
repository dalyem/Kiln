import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  canonicalImageManifest,
  canonicalLinuxImportPlan,
  canonicalQualificationDispatch,
  LifecycleQualificationService,
  LinuxImageImportService,
  linuxImportPhases,
  type LifecycleQualificationProvider,
  type LinuxImportPhaseName,
  type LinuxImportProvider,
  type LinuxImportReceipt,
  type TrustedImageKeys,
} from "@kiln/core";
import { MemoryStore } from "@kiln/database";

const sourceToken = "qual@pam!run";
const linuxToken = "qual@pam!linux";
const stagingId = "lstg_0123456789abcdef0123456789abcdef";

function qcow(): Buffer {
  const value = Buffer.alloc(112);
  value.write("QFI\u00fb", 0, "binary");
  value.writeUInt32BE(3, 4);
  value.writeBigUInt64BE(0n, 8);
  value.writeUInt32BE(0, 16);
  value.writeUInt32BE(16, 20);
  value.writeBigUInt64BE(8n * 1024n * 1024n * 1024n, 24);
  value.writeUInt32BE(0, 32);
  value.writeUInt32BE(0, 60);
  value.writeBigUInt64BE(0n, 64);
  value.writeBigUInt64BE(0n, 72);
  value.writeBigUInt64BE(0n, 80);
  value.writeBigUInt64BE(0n, 88);
  value.writeUInt32BE(4, 96);
  value.writeUInt32BE(112, 100);
  return value;
}

function qualificationArtifact(): Buffer {
  const value = Buffer.alloc(112);
  value.write("QFI\u00fb", 0, "binary");
  value.writeUInt32BE(3, 4);
  value.writeBigUInt64BE(0n, 8);
  value.writeUInt32BE(0, 16);
  value.writeUInt32BE(9, 20);
  value.writeBigUInt64BE(4n * 1024n * 1024n, 24);
  value.writeUInt32BE(0, 32);
  value.writeBigUInt64BE(0n, 72);
  value.writeUInt32BE(4, 96);
  value.writeUInt32BE(112, 100);
  return value;
}

function keys(name: string, capabilities: string[]) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const trusted: TrustedImageKeys = {
    operator: {
      publicKeyPem: publicKey
        .export({ type: "spki", format: "pem" })
        .toString(),
      allowedNames: [name],
      allowedCapabilities: capabilities,
      allowedArchitectures: ["amd64"],
    },
  };
  return {
    trusted,
    sign: (manifest: Parameters<typeof canonicalImageManifest>[0]) =>
      sign(
        null,
        Buffer.from(canonicalImageManifest(manifest)),
        privateKey,
      ).toString("base64"),
  };
}

class QualificationProvider implements LifecycleQualificationProvider {
  readonly mode = "proxmox-qualification" as const;
  async executeQualificationPhase(
    context: Parameters<
      LifecycleQualificationProvider["executeQualificationPhase"]
    >[0],
  ) {
    const dispatch = {
      method: "POST" as const,
      path: `/qualification/${context.phase}`,
      body: null,
    };
    return {
      taskId: null,
      workerType: null,
      sourceVmid: null,
      destinationVmid: null,
      tokenIdentity: sourceToken,
      requestDigest: context.requestDigest,
      dispatch,
      dispatchDigest: canonicalQualificationDispatch(dispatch),
      responseDigest: "a".repeat(64),
      generatedUuid: null,
      generatedCtime: null,
    };
  }
  async inspectQualificationPhase() {
    return { status: "COMPLETED" as const };
  }
}

class Provider implements LinuxImportProvider {
  calls: LinuxImportPhaseName[] = [];
  inspection = new Map<
    LinuxImportPhaseName,
    "RUNNING" | "COMPLETED" | "UNKNOWN"
  >();
  failInspection = false;
  async executeLinuxImportPhase(
    context: Parameters<LinuxImportProvider["executeLinuxImportPhase"]>[0],
  ): Promise<LinuxImportReceipt> {
    this.calls.push(context.phase);
    return {
      taskId: null,
      tokenIdentity: linuxToken,
      workerType: null,
      sourceVmid: context.phase === "CLONE" ? context.plan.templateVmid : null,
      destinationVmid: ["IMPORT", "TEMPLATE", "DESTROY_TEMPLATE"].includes(
        context.phase,
      )
        ? context.plan.templateVmid
        : ["CLONE", "STAMP", "START", "STOP", "DESTROY_CLONE"].includes(
              context.phase,
            )
          ? context.plan.cloneVmid
          : null,
      requestDigest: context.requestDigest,
      dispatch: { method: "POST", path: `/linux/${context.phase}`, body: null },
      dispatchDigest: "b".repeat(64),
      responseDigest: "c".repeat(64),
      generatedUuid: null,
      generatedCtime: null,
      configDigest: null,
    };
  }
  async inspectLinuxImportPhase(
    context: Parameters<LinuxImportProvider["inspectLinuxImportPhase"]>[0],
  ) {
    if (this.failInspection) throw new Error("temporary observation failure");
    const status = this.inspection.get(context.phase) ?? "COMPLETED";
    if (status !== "COMPLETED") return { status };
    return context.phase === "CLONE"
      ? {
          status,
          receiptPatch: {
            generatedUuid: "11111111-1111-1111-1111-111111111111",
            generatedCtime: "1700000000",
            responseDigest: "d".repeat(64),
            configDigest: "e".repeat(40),
          },
        }
      : { status };
  }
}

class FailingReceiptStore extends MemoryStore {
  fail = true;
  override async submitLinuxImportPhase(
    ...input: Parameters<MemoryStore["submitLinuxImportPhase"]>
  ): Promise<void> {
    if (this.fail) {
      this.fail = false;
      throw new Error("audit persistence failed");
    }
    return super.submitLinuxImportPhase(...input);
  }
}

class SwappedProofStore extends MemoryStore {
  swap = false;
  badRunId: string | null = null;
  proofMutation: "project" | "lease" | null = null;
  override async getLinuxImportProof(runId: string) {
    const proof = await super.getLinuxImportProof(runId);
    if (this.proofMutation === "project")
      return {
        ...proof,
        resources: proof.resources.map((resource, index) =>
          index === 0 ? { ...resource, projectId: "foreign" } : resource,
        ),
      };
    if (this.proofMutation === "lease")
      return {
        ...proof,
        resources: proof.resources.map((resource, index) =>
          index === 0
            ? { ...resource, expiresAt: "2026-09-22T00:00:00.000Z" }
            : resource,
        ),
      };
    return this.swap && (!this.badRunId || this.badRunId === runId)
      ? {
          ...proof,
          children: [
            ...proof.children.slice(0, 2),
            {
              nativeId: proof.children[2]!.nativeId,
              resourceId: proof.children[0]!.resourceId,
            },
          ],
        }
      : proof;
  }
}

class CorruptPlanStore extends MemoryStore {
  corrupt = false;
  override async listActiveLinuxImportRuns() {
    const runs = await super.listActiveLinuxImportRuns();
    return this.corrupt
      ? runs.map((run) => ({
          ...run,
          plan: { ...run.plan, canonicalDigest: "f".repeat(64) },
        }))
      : runs;
  }
}

async function setup(store: MemoryStore = new MemoryStore()) {
  const qualificationKeys = keys("qualification-image", ["network_probe"]);
  const qualificationBytes = qualificationArtifact();
  const qualificationManifest = {
    schemaVersion: 1 as const,
    name: "qualification-image",
    version: "1",
    arch: "amd64" as const,
    artifactSha256: createHash("sha256")
      .update(qualificationBytes)
      .digest("hex"),
    artifactSize: qualificationBytes.length,
    sourceBuild: "test",
    capabilities: ["network_probe"],
    keyId: "operator",
  };
  const qualification = new LifecycleQualificationService(
    store,
    new QualificationProvider(),
    qualificationKeys.trusted,
    {
      node: "pve1",
      pool: "kiln",
      stageStorage: "local",
      targetStorage: "local-lvm",
      pveVersion: "9.2.2",
      storageConfigDigest: "a".repeat(40),
      templateVmid: "9100",
      probeVmid: "9101",
      tokenIdentity: sourceToken,
    },
  );
  const source = await qualification.createRun(
    {
      manifest: qualificationManifest,
      signature: qualificationKeys.sign(qualificationManifest),
      artifactBase64: qualificationBytes.toString("base64"),
    },
    "source",
  );
  for (let index = 0; index < 20; index += 1)
    await qualification.advance(source.run.id);
  expect((await qualification.getRun(source.run.id))?.status).toBe("COMPLETED");

  const directory = await mkdtemp(join(tmpdir(), "kiln-linux-import-service-"));
  const path = join(directory, "image.qcow2");
  const bytes = qcow();
  await writeFile(path, bytes, { mode: 0o600 });
  const linuxKeys = keys("kiln-dev-base", ["development"]);
  const artifactSha256 = createHash("sha256").update(bytes).digest("hex");
  const metadata = Buffer.from(
    JSON.stringify({
      schemaVersion: 1,
      name: "kiln-dev-base",
      arch: "amd64",
      profile: "debian13-nic-free-development-v1",
      recipe: "images/dev/build.sh",
      recipeSha256: "1".repeat(64),
      baseSha512: "2".repeat(128),
      kilndSha256: "3".repeat(64),
      artifactSha256,
      packages: ["base-files\t13.0"],
      reproducible: false,
    }),
  );
  const manifest = {
    schemaVersion: 1 as const,
    name: "kiln-dev-base",
    version: "1",
    arch: "amd64" as const,
    artifactSha256,
    artifactSize: bytes.length,
    sourceBuild: `sha256:${createHash("sha256").update(metadata).digest("hex")}`,
    capabilities: ["development"],
    keyId: "operator",
  };
  const profile = {
    node: "pve1",
    pool: "kiln",
    stageStorage: "local",
    targetStorage: "local-lvm",
    pveVersion: "9.2.2" as const,
    tokenIdentity: linuxToken,
    storageConfigDigest: "a".repeat(40),
    templateVmid: "9200",
    cloneVmid: "9201",
    templateName: "kiln-image-9200",
    cloneName: "Copy-of-kiln-image-9200",
    sourcePoolRunId: source.run.id,
    sourcePoolAllocationId: `alloc_pool_${source.run.id}`,
    sourcePoolNonce: source.run.plan.poolNonce,
    sourcePoolComment: source.run.plan.poolComment,
  };
  const staging = {
    pathFor: () => path,
    describe: async () => ({
      id: stagingId,
      path,
      size: bytes.length,
      sha256: artifactSha256,
    }),
  };
  const provider = new Provider();
  let now = new Date();
  const serviceFor = (
    templateVmid = profile.templateVmid,
    cloneVmid = profile.cloneVmid,
  ) =>
    new LinuxImageImportService(
      store,
      provider,
      linuxKeys.trusted,
      {
        ...profile,
        templateVmid,
        cloneVmid,
        templateName: `kiln-image-${templateVmid}`,
        cloneName: `Copy-of-kiln-image-${templateVmid}`,
      },
      staging,
      () => now,
    );
  const createRun = (id: string, templateVmid: string, cloneVmid: string) =>
    serviceFor(templateVmid, cloneVmid).createRun(
      {
        stagingId: id,
        manifest,
        signature: linuxKeys.sign(manifest),
        buildMetadataBase64: metadata.toString("base64"),
      },
      `linux-${templateVmid}`,
    );
  const created = await createRun(
    stagingId,
    profile.templateVmid,
    profile.cloneVmid,
  );
  return {
    store,
    provider,
    service: () => serviceFor(),
    createRun,
    run: created.run,
    advanceClock: () => {
      now = new Date(Date.now() + 60 * 60_000);
    },
    cleanup: () => rm(directory, { recursive: true, force: true }),
  };
}

describe("Linux image import service", () => {
  it("completes all nine phases through the durable service journal", async () => {
    const value = await setup();
    try {
      for (const phase of linuxImportPhases)
        await value.service().advance(value.run.id);
      expect(value.provider.calls).toEqual(linuxImportPhases);
      expect(await value.service().status(value.run.id)).toMatchObject({
        status: "COMPLETED",
      });
      expect(await value.service().statusDetail(value.run.id)).toMatchObject({
        run: { status: "COMPLETED" },
        phases: linuxImportPhases.map((name) => ({
          name,
          status: "COMPLETED",
        })),
      });
    } finally {
      await value.cleanup();
    }
  });

  it("reconciles a submitted receipt after a service restart without another effect", async () => {
    const value = await setup();
    try {
      value.provider.inspection.set("UPLOAD", "RUNNING");
      await value.service().advance(value.run.id);
      expect(
        await value.store.getLinuxImportPhase(value.run.id, "UPLOAD"),
      ).toMatchObject({ status: "SUBMITTED" });
      value.provider.inspection.set("UPLOAD", "COMPLETED");
      await value.service().recoverInstallation();
      expect(value.provider.calls).toEqual(["UPLOAD"]);
      expect(
        await value.store.getLinuxImportPhase(value.run.id, "UPLOAD"),
      ).toMatchObject({ status: "COMPLETED" });
    } finally {
      await value.cleanup();
    }
  });

  it("holds a thrown recovery observation until its deadline then fences the receipt", async () => {
    const value = await setup();
    try {
      value.provider.inspection.set("UPLOAD", "RUNNING");
      await value.service().advance(value.run.id);
      value.provider.failInspection = true;
      await value.service().recoverInstallation();
      expect(value.provider.calls).toEqual(["UPLOAD"]);
      expect(
        await value.store.getLinuxImportPhase(value.run.id, "UPLOAD"),
      ).toMatchObject({ status: "SUBMITTED" });
      value.advanceClock();
      await value.service().recoverInstallation();
      expect(value.provider.calls).toEqual(["UPLOAD"]);
      expect(
        await value.store.getLinuxImportPhase(value.run.id, "UPLOAD"),
      ).toMatchObject({
        status: "UNKNOWN",
        safeReason: "RECONCILIATION_OBSERVATION_FAILED_DEADLINE",
      });
    } finally {
      await value.cleanup();
    }
  });

  it("fences a receiptless intent during recovery without dispatching", async () => {
    const value = await setup();
    try {
      const plan = value.run.plan;
      const { canonicalDigest: _canonicalDigest, ...bare } = plan;
      await value.store.beginLinuxImportPhase({
        runId: value.run.id,
        name: "UPLOAD",
        intentDigest: createHash("sha256")
          .update(`${canonicalLinuxImportPlan(bare)}:UPLOAD`)
          .digest("hex"),
        event: {
          installationId: value.run.installationId,
          projectId: "infrastructure",
          resourceId: null,
          type: "test.intent",
          timestamp: new Date().toISOString(),
          payload: {},
        },
      });
      await value.service().recoverInstallation();
      expect(value.provider.calls).toEqual([]);
      expect(
        await value.store.getLinuxImportPhase(value.run.id, "UPLOAD"),
      ).toMatchObject({ status: "UNKNOWN", safeReason: "RECOVERED_INTENT" });
    } finally {
      await value.cleanup();
    }
  });

  it("holds transient unknown reconciliation until its deadline then quarantines the run", async () => {
    const value = await setup();
    try {
      value.provider.inspection.set("UPLOAD", "UNKNOWN");
      await value.service().advance(value.run.id);
      expect(
        await value.store.getLinuxImportPhase(value.run.id, "UPLOAD"),
      ).toMatchObject({ status: "SUBMITTED" });
      value.advanceClock();
      await value.service().recoverInstallation();
      expect(value.provider.calls).toEqual(["UPLOAD"]);
      expect(
        await value.store.getLinuxImportPhase(value.run.id, "UPLOAD"),
      ).toMatchObject({
        status: "UNKNOWN",
        safeReason: "RECONCILIATION_DEADLINE_EXCEEDED",
      });
      expect(await value.service().status(value.run.id)).toMatchObject({
        status: "UNKNOWN",
      });
    } finally {
      await value.cleanup();
    }
  });

  it.each([
    ["IMPORT", "template"],
    ["TEMPLATE", "template"],
    ["CLONE", "clone"],
    ["DESTROY_CLONE", "clone"],
    ["DESTROY_TEMPLATE", "template"],
  ] as const)(
    "quarantines the affected resource when %s remains uncertain",
    async (phase, affectedResource) => {
      const value = await setup();
      try {
        for (const prior of linuxImportPhases.slice(
          0,
          linuxImportPhases.indexOf(phase),
        ))
          await value.service().advance(value.run.id);
        value.provider.inspection.set(phase, "UNKNOWN");
        await value.service().advance(value.run.id);
        value.advanceClock();
        await value.service().recoverInstallation();
        const resourceId =
          affectedResource === "template"
            ? value.run.plan.templateResourceId
            : value.run.plan.cloneResourceId;
        expect(await value.store.getResource(resourceId)).toMatchObject({
          state: "QUARANTINED",
        });
      } finally {
        await value.cleanup();
      }
    },
  );

  it("denies swapped child ownership before the provider can write", async () => {
    const store = new SwappedProofStore();
    const value = await setup(store);
    try {
      store.swap = true;
      await expect(value.service().advance(value.run.id)).rejects.toMatchObject(
        { code: "SAFETY_DENIED" },
      );
      expect(value.provider.calls).toEqual([]);
    } finally {
      await value.cleanup();
    }
  });

  it.each(["project", "lease"] as const)(
    "denies a changed infrastructure %s before the provider can write",
    async (proofMutation) => {
      const store = new SwappedProofStore();
      const value = await setup(store);
      try {
        store.proofMutation = proofMutation;
        await expect(
          value.service().advance(value.run.id),
        ).rejects.toMatchObject({ code: "SAFETY_DENIED" });
        expect(value.provider.calls).toEqual([]);
      } finally {
        await value.cleanup();
      }
    },
  );

  it("isolates a corrupt recovery proof while completing another submitted run", async () => {
    const store = new SwappedProofStore();
    const value = await setup(store);
    try {
      value.provider.inspection.set("UPLOAD", "RUNNING");
      await value.service().advance(value.run.id);
      const valid = await value.createRun(
        "lstg_ffffffffffffffffffffffffffffffff",
        "9300",
        "9301",
      );
      await value.service().advance(valid.run.id);
      store.swap = true;
      store.badRunId = value.run.id;
      value.provider.inspection.set("UPLOAD", "COMPLETED");
      const callsBeforeRecovery = value.provider.calls.length;
      await value.service().recoverInstallation();
      expect(value.provider.calls).toHaveLength(callsBeforeRecovery);
      expect(
        await value.store.getLinuxImportPhase(value.run.id, "UPLOAD"),
      ).toMatchObject({
        status: "UNKNOWN",
        safeReason: "RECOVERY_SAFETY_PROOF_FAILED",
      });
      expect(
        await value.store.getLinuxImportPhase(valid.run.id, "UPLOAD"),
      ).toMatchObject({ status: "COMPLETED" });
    } finally {
      await value.cleanup();
    }
  });

  it("fences a corrupt canonical plan during recovery without another provider write", async () => {
    const store = new CorruptPlanStore();
    const value = await setup(store);
    try {
      value.provider.inspection.set("UPLOAD", "RUNNING");
      await value.service().advance(value.run.id);
      store.corrupt = true;
      const callsBeforeRecovery = value.provider.calls.length;
      await expect(
        value.service().recoverInstallation(),
      ).resolves.toBeUndefined();
      expect(value.provider.calls).toHaveLength(callsBeforeRecovery);
      expect(
        await value.store.getLinuxImportPhase(value.run.id, "UPLOAD"),
      ).toMatchObject({
        status: "UNKNOWN",
        safeReason: "RECOVERY_SAFETY_PROOF_FAILED",
      });
    } finally {
      await value.cleanup();
    }
  });

  it("does not repeat an effect when receipt persistence fails", async () => {
    const store = new FailingReceiptStore();
    const value = await setup(store);
    try {
      await expect(value.service().advance(value.run.id)).rejects.toThrow(
        "audit persistence failed",
      );
      await value.service().advance(value.run.id);
      expect(value.provider.calls).toEqual(["UPLOAD"]);
      expect(
        await value.store.getLinuxImportPhase(value.run.id, "UPLOAD"),
      ).toMatchObject({ status: "UNKNOWN", safeReason: "DISPATCH_UNKNOWN" });
    } finally {
      await value.cleanup();
    }
  });
});
