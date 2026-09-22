import { createHash } from "node:crypto";
import {
  KilnError,
  canonicalQualificationDispatch,
  type LifecycleQualificationProvider,
  type QualificationExecutionContext,
  type QualificationInspection,
  type QualificationPhaseName,
  type QualificationReceipt,
} from "@kiln/core";
import {
  canonicalQualifiedQemuIdentity,
  qualifyQemuConfig,
  type QualifiedQemuGraph,
} from "./qualified-config.js";

const UPID =
  /^UPID:([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?):([0-9A-Fa-f]{8}):([0-9A-Fa-f]{8,9}):([0-9A-Fa-f]{8}):([^:\s/]+):([^:\s/]*):([^:\s/]+):$/;
const phases: QualificationPhaseName[] = [
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
];
const workers: Partial<Record<QualificationPhaseName, string>> = {
  UPLOAD: "imgcopy",
  IMPORT: "qmcreate",
  TEMPLATE: "qmtemplate",
  CLONE: "qmclone",
  START: "qmstart",
  STOP: "qmstop",
  DESTROY_PROBE: "qmdestroy",
  DESTROY_TEMPLATE: "qmdestroy",
};

export interface QualificationCredentials {
  url: URL;
  tokenId: string;
  tokenSecret: string;
}

interface Upid {
  node: string;
  pid: number;
  pstart: number;
  starttime: number;
  type: string;
  id: string;
  identity: string;
}

interface Mutation {
  method: "POST" | "PUT" | "DELETE";
  path: string;
  body?: BodyInit;
  descriptor: Record<string, unknown>;
  worker: string | null;
}

function hash(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function ownershipTags(
  plan: QualificationExecutionContext["plan"],
  resourceId: string,
  kind: "image_template" | "network_probe",
  nonce: string,
): string[] {
  return [
    "kiln",
    "kiln-managed",
    `kiln-installation-${plan.installationId}`,
    `kiln-resource-${kind}`,
    `kiln-resource-id-${resourceId}`,
    `kiln-qualification-nonce-${nonce}`,
  ];
}

export class ProxmoxQualificationProvider
  implements LifecycleQualificationProvider
{
  readonly mode = "proxmox-qualification" as const;

  constructor(
    private readonly credentials: QualificationCredentials,
    private readonly fetcher: typeof fetch = fetch,
  ) {
    if (credentials.url.protocol !== "https:")
      throw new KilnError(
        "INVALID_PROVIDER_CONFIG",
        400,
        "Proxmox API URL must use HTTPS",
      );
  }

  async executeQualificationPhase(
    context: QualificationExecutionContext,
  ): Promise<QualificationReceipt> {
    this.assertContext(context);
    const stampGraph = await this.assertPrecondition(context);
    const mutation = this.mutation(context, stampGraph);
    const response = await this.mutate(mutation);
    const sourceVmid =
      context.phase === "CLONE" ? context.plan.templateVmid : null;
    const destinationVmid = ["IMPORT", "TEMPLATE", "DESTROY_TEMPLATE"].includes(
      context.phase,
    )
      ? context.plan.templateVmid
      : ["CLONE", "STAMP", "START", "STOP", "DESTROY_PROBE"].includes(
            context.phase,
          )
        ? context.plan.probeVmid
        : null;
    const dispatch = this.dispatch(mutation);
    const dispatchDigest = canonicalQualificationDispatch(dispatch);
    if (mutation.worker === null)
      return this.receipt(
        context,
        null,
        null,
        sourceVmid,
        destinationVmid,
        dispatch,
        dispatchDigest,
        hash({ acknowledgement: response }),
      );
    if (typeof response !== "string")
      throw this.denied("Proxmox task receipt is missing");
    const upid = this.parseUpid(response);
    if (!upid || !this.matchesUpid(context, upid, mutation.worker))
      throw this.denied(
        "Proxmox task receipt does not match the qualified operation",
      );
    return this.receipt(
      context,
      response,
      mutation.worker,
      sourceVmid,
      destinationVmid,
      dispatch,
      dispatchDigest,
      hash({ upid: response }),
    );
  }

  async inspectQualificationPhase(
    context: QualificationExecutionContext,
    receipt: QualificationReceipt,
  ): Promise<QualificationInspection> {
    try {
      this.assertContext(context);
      if (!this.validReceipt(context, receipt)) return { status: "MISMATCH" };
      await this.assertEnvironment(context.plan);
      if (receipt.taskId === null)
        return this.inspectSynchronous(context, receipt);
      const worker = workers[context.phase];
      if (!worker || receipt.workerType !== worker)
        return { status: "MISMATCH" };
      const upid = this.parseUpid(receipt.taskId);
      if (!upid || !this.matchesUpid(context, upid, worker))
        return { status: "MISMATCH" };
      const task = await this.data(
        `/api2/json/nodes/${this.part(context.plan.node)}/tasks/${this.part(receipt.taskId)}/status`,
      );
      if (!this.matchesTaskStatus(task, receipt.taskId, upid))
        return { status: "MISMATCH" };
      const status = (task as Record<string, unknown>).status;
      if (status === "running") return { status: "RUNNING" };
      if (
        status !== "stopped" ||
        (task as Record<string, unknown>).exitstatus !== "OK"
      )
        return { status: "FAILED" };
      const graph = await this.assertAfter(context, context.phase);
      if (context.phase === "CLONE") {
        if (!graph || !graph.ctime || !graph.smbiosUuid || !graph.vmgenid)
          return { status: "MISMATCH" };
        return {
          status: "COMPLETED",
          receiptPatch: {
            generatedUuid: graph.smbiosUuid,
            generatedCtime: graph.ctime,
            responseDigest: canonicalQualifiedQemuIdentity(graph),
          },
        };
      }
      return { status: "COMPLETED" };
    } catch {
      return { status: "UNKNOWN" };
    }
  }

  private mutation(
    context: QualificationExecutionContext,
    stampGraph: QualifiedQemuGraph | null,
  ): Mutation {
    const { plan, phase } = context;
    const node = `/api2/json/nodes/${this.part(plan.node)}`;
    if (phase === "POOL_CREATE") {
      const fields = { poolid: plan.pool, comment: plan.poolComment };
      return {
        method: "POST",
        path: "/api2/json/pools",
        body: this.form(fields),
        descriptor: { method: "POST", path: "/api2/json/pools", body: fields },
        worker: null,
      };
    }
    if (phase === "UPLOAD") {
      const artifact = Buffer.from(plan.artifactBase64, "base64");
      const fields = {
        content: "import",
        "checksum-algorithm": "sha256",
        checksum: plan.image.manifest.artifactSha256,
        filename: plan.stageVolumeId.slice("import/".length),
        artifactSha256: plan.image.manifest.artifactSha256,
        artifactSize: plan.image.manifest.artifactSize,
      };
      const body = new FormData();
      body.append("content", "import");
      body.append("checksum-algorithm", fields["checksum-algorithm"]);
      body.append("checksum", fields.checksum);
      body.append("filename", new Blob([artifact]), fields.filename);
      return {
        method: "POST",
        path: `${node}/storage/${this.part(plan.stageStorage)}/upload`,
        body,
        descriptor: {
          method: "POST",
          path: `${node}/storage/${this.part(plan.stageStorage)}/upload`,
          body: fields,
        },
        worker: "imgcopy",
      };
    }
    if (phase === "IMPORT") {
      const fields = {
        vmid: plan.templateVmid,
        pool: plan.pool,
        bios: "seabios",
        scsihw: "virtio-scsi-single",
        boot: "order=scsi0",
        serial0: "socket",
        memory: "128",
        cores: "1",
        cpu: "kvm64",
        tags: ownershipTags(
          plan,
          plan.templateResourceId,
          "image_template",
          plan.templateNonce,
        ).join(";"),
        scsi0: `${plan.targetStorage}:0,import-from=${plan.stageStorage}:${plan.stageVolumeId}`,
      };
      return {
        method: "POST",
        path: `${node}/qemu`,
        body: this.form(fields),
        descriptor: { method: "POST", path: `${node}/qemu`, body: fields },
        worker: "qmcreate",
      };
    }
    if (phase === "TEMPLATE")
      return this.empty(
        "POST",
        `${node}/qemu/${this.part(plan.templateVmid)}/template`,
        "qmtemplate",
      );
    if (phase === "CLONE") {
      const fields = {
        newid: plan.probeVmid,
        pool: plan.pool,
        storage: plan.targetStorage,
        full: "1",
      };
      return {
        method: "POST",
        path: `${node}/qemu/${this.part(plan.templateVmid)}/clone`,
        body: this.form(fields),
        descriptor: {
          method: "POST",
          path: `${node}/qemu/${this.part(plan.templateVmid)}/clone`,
          body: fields,
        },
        worker: "qmclone",
      };
    }
    if (phase === "STAMP") {
      const clone = context.priorReceipts.CLONE;
      const fields = {
        digest: stampGraph?.configDigest ?? "",
        tags: ownershipTags(
          plan,
          plan.probeResourceId,
          "network_probe",
          plan.probeNonce,
        ).join(";"),
      };
      return {
        method: "PUT",
        path: `${node}/qemu/${this.part(plan.probeVmid)}/config`,
        body: this.form(fields),
        descriptor: {
          method: "PUT",
          path: `${node}/qemu/${this.part(plan.probeVmid)}/config`,
          body: fields,
        },
        worker: null,
      };
    }
    if (phase === "START")
      return this.empty(
        "POST",
        `${node}/qemu/${this.part(plan.probeVmid)}/status/start`,
        "qmstart",
      );
    if (phase === "STOP")
      return this.empty(
        "POST",
        `${node}/qemu/${this.part(plan.probeVmid)}/status/stop`,
        "qmstop",
      );
    if (phase === "DESTROY_PROBE" || phase === "DESTROY_TEMPLATE") {
      const vmid =
        phase === "DESTROY_PROBE" ? plan.probeVmid : plan.templateVmid;
      const path = `${node}/qemu/${this.part(vmid)}?purge=0&destroy-unreferenced-disks=0`;
      return {
        method: "DELETE",
        path,
        descriptor: { method: "DELETE", path, body: null },
        worker: "qmdestroy",
      };
    }
    throw this.denied("Qualification phase is unsupported");
  }

  private empty(method: "POST", path: string, worker: string): Mutation {
    return {
      method,
      path,
      body: this.form({}),
      descriptor: { method, path, body: {} },
      worker,
    };
  }

  private async assertPrecondition(
    context: QualificationExecutionContext,
  ): Promise<QualifiedQemuGraph | null> {
    await this.assertEnvironment(context.plan);
    if (context.phase === "POOL_CREATE") {
      await this.assertVmAbsent(context.plan, context.plan.templateVmid, [
        `vm-${context.plan.templateVmid}-disk-0`,
        context.plan.templateBootVolume,
      ]);
      await this.assertVmAbsent(context.plan, context.plan.probeVmid, [
        context.plan.probeBootVolume,
      ]);
      await this.assertPoolMissing(context.plan);
      return null;
    }
    await this.assertAfter(context, phases[phases.indexOf(context.phase) - 1]!);
    return context.phase === "STAMP" ? this.assertClonePinned(context) : null;
  }

  private async assertAfter(
    context: QualificationExecutionContext,
    phase: QualificationPhaseName,
  ): Promise<QualifiedQemuGraph | null> {
    const { plan } = context;
    if (phase === "POOL_CREATE") {
      await this.assertPool(plan, []);
      await this.assertStage(plan, false);
      await this.assertVmAbsent(plan, plan.templateVmid, [
        `vm-${plan.templateVmid}-disk-0`,
        plan.templateBootVolume,
      ]);
      await this.assertVmAbsent(plan, plan.probeVmid, [plan.probeBootVolume]);
      return null;
    }
    if (phase === "UPLOAD") {
      await this.assertPool(plan, []);
      await this.assertStage(plan, true);
      await this.assertVmAbsent(plan, plan.templateVmid, [
        `vm-${plan.templateVmid}-disk-0`,
        plan.templateBootVolume,
      ]);
      await this.assertVmAbsent(plan, plan.probeVmid, [plan.probeBootVolume]);
      return null;
    }
    if (phase === "IMPORT") {
      await this.assertPool(plan, [plan.templateVmid]);
      await this.assertStage(plan, true);
      const graph = await this.assertVm(
        plan,
        plan.templateVmid,
        false,
        ownershipTags(
          plan,
          plan.templateResourceId,
          "image_template",
          plan.templateNonce,
        ),
        "stopped",
      );
      await this.assertVmAbsent(plan, plan.probeVmid, [plan.probeBootVolume]);
      return graph;
    }
    if (phase === "TEMPLATE") {
      await this.assertPool(plan, [plan.templateVmid]);
      await this.assertStage(plan, true);
      const graph = await this.assertVm(
        plan,
        plan.templateVmid,
        true,
        ownershipTags(
          plan,
          plan.templateResourceId,
          "image_template",
          plan.templateNonce,
        ),
        "stopped",
      );
      await this.assertVmAbsent(plan, plan.probeVmid, [plan.probeBootVolume]);
      return graph;
    }
    if (phase === "CLONE") {
      await this.assertPool(plan, [plan.templateVmid, plan.probeVmid]);
      await this.assertStage(plan, true);
      await this.assertVm(
        plan,
        plan.templateVmid,
        true,
        ownershipTags(
          plan,
          plan.templateResourceId,
          "image_template",
          plan.templateNonce,
        ),
        "stopped",
      );
      const graph = await this.assertVm(
        plan,
        plan.probeVmid,
        false,
        ownershipTags(
          plan,
          plan.templateResourceId,
          "image_template",
          plan.templateNonce,
        ),
        "stopped",
      );
      return graph;
    }
    if (phase === "STAMP" || phase === "START" || phase === "STOP") {
      await this.assertPool(plan, [plan.templateVmid, plan.probeVmid]);
      await this.assertStage(plan, true);
      await this.assertVm(
        plan,
        plan.templateVmid,
        true,
        ownershipTags(
          plan,
          plan.templateResourceId,
          "image_template",
          plan.templateNonce,
        ),
        "stopped",
      );
      const desiredStatus = phase === "START" ? "running" : "stopped";
      const graph = await this.assertVm(
        plan,
        plan.probeVmid,
        false,
        ownershipTags(
          plan,
          plan.probeResourceId,
          "network_probe",
          plan.probeNonce,
        ),
        desiredStatus,
      );
      this.assertSavedCloneIdentity(context, graph);
      return graph;
    }
    if (phase === "DESTROY_PROBE") {
      await this.assertPool(plan, [plan.templateVmid]);
      await this.assertStage(plan, true);
      await this.assertVm(
        plan,
        plan.templateVmid,
        true,
        ownershipTags(
          plan,
          plan.templateResourceId,
          "image_template",
          plan.templateNonce,
        ),
        "stopped",
      );
      await this.assertVmAbsent(plan, plan.probeVmid, [plan.probeBootVolume]);
      return null;
    }
    if (phase === "DESTROY_TEMPLATE") {
      await this.assertPool(plan, []);
      await this.assertStage(plan, true);
      await this.assertVmAbsent(plan, plan.templateVmid, [
        `vm-${plan.templateVmid}-disk-0`,
        plan.templateBootVolume,
      ]);
      await this.assertVmAbsent(plan, plan.probeVmid, [plan.probeBootVolume]);
      return null;
    }
    throw this.denied("Qualification phase is unsupported");
  }

  private async assertClonePinned(
    context: QualificationExecutionContext,
  ): Promise<QualifiedQemuGraph> {
    const receipt = context.priorReceipts.CLONE;
    if (
      !receipt ||
      receipt.sourceVmid !== context.plan.templateVmid ||
      receipt.destinationVmid !== context.plan.probeVmid ||
      !receipt.generatedUuid ||
      !receipt.generatedCtime
    )
      throw this.denied("Clone receipt lacks generated identity evidence");
    const graph = await this.assertVm(
      context.plan,
      context.plan.probeVmid,
      false,
      ownershipTags(
        context.plan,
        context.plan.templateResourceId,
        "image_template",
        context.plan.templateNonce,
      ),
      "stopped",
    );
    if (
      graph.smbiosUuid !== receipt.generatedUuid ||
      graph.ctime !== receipt.generatedCtime ||
      canonicalQualifiedQemuIdentity(graph) !== receipt.responseDigest
    )
      throw this.denied("Clone identity changed before stamping");
    return graph;
  }

  private assertSavedCloneIdentity(
    context: QualificationExecutionContext,
    graph: QualifiedQemuGraph,
  ): void {
    const receipt = context.priorReceipts.CLONE;
    if (
      receipt &&
      canonicalQualifiedQemuIdentity(graph) !== receipt.responseDigest
    )
      throw this.denied("Clone identity changed after its recorded creation");
  }

  private async assertEnvironment(
    plan: QualificationExecutionContext["plan"],
  ): Promise<void> {
    if (
      plan.pveVersion !== "9.2.2" ||
      plan.stageStorage !== "local" ||
      plan.targetStorage !== "local-lvm" ||
      !/^[a-f0-9]{40}$/.test(plan.storageConfigDigest)
    )
      throw this.denied("Qualification plan is not the pinned PVE profile");
    const [version, permissions, storage, nodeStorage, cluster, local] =
      await Promise.all([
        this.data("/api2/json/version"),
        this.data("/api2/json/access/permissions"),
        this.data("/api2/json/storage"),
        this.data(`/api2/json/nodes/${this.part(plan.node)}/storage`),
        this.data("/api2/json/cluster/resources?type=vm"),
        this.data(`/api2/json/nodes/${this.part(plan.node)}/qemu`),
      ]);
    const rootPermissions = isRecord(permissions) ? permissions["/"] : null;
    if (
      !isRecord(version) ||
      version.version !== "9.2.2" ||
      !isRecord(rootPermissions) ||
      rootPermissions["Sys.Audit"] !== 1 ||
      rootPermissions["Pool.Audit"] !== 1 ||
      rootPermissions["Datastore.Audit"] !== 1 ||
      rootPermissions["VM.Audit"] !== 1 ||
      !Array.isArray(storage) ||
      !Array.isArray(nodeStorage) ||
      !Array.isArray(cluster) ||
      !Array.isArray(local)
    )
      throw this.denied("Proxmox qualification evidence is incomplete");
    const stage = storage.find(
      (item) => isRecord(item) && item.storage === plan.stageStorage,
    );
    const target = storage.find(
      (item) => isRecord(item) && item.storage === plan.targetStorage,
    );
    if (!isRecord(stage) || !isRecord(target))
      throw this.denied("Qualified storage is missing");
    const nodeStage = nodeStorage.find(
      (item) => isRecord(item) && item.storage === plan.stageStorage,
    );
    const nodeTarget = nodeStorage.find(
      (item) => isRecord(item) && item.storage === plan.targetStorage,
    );
    if (
      stage.type !== "dir" ||
      stage.path !== "/var/lib/vz" ||
      !this.contentSet(stage.content).has("import") ||
      target.type !== "lvmthin" ||
      target.vgname !== "pve" ||
      target.thinpool !== "data" ||
      !this.contentSet(target.content).has("images") ||
      stage.digest !== plan.storageConfigDigest ||
      target.digest !== plan.storageConfigDigest ||
      !isRecord(nodeStage) ||
      !isRecord(nodeTarget) ||
      nodeStage.type !== "dir" ||
      nodeTarget.type !== "lvmthin" ||
      nodeStage.active !== 1 ||
      nodeTarget.active !== 1 ||
      nodeStage.enabled !== 1 ||
      nodeTarget.enabled !== 1 ||
      nodeStage.shared !== 0 ||
      nodeTarget.shared !== 0
    )
      throw this.denied("Qualified storage changed");
  }

  private async assertVm(
    plan: QualificationExecutionContext["plan"],
    vmid: string,
    template: boolean,
    tags: string[],
    desiredStatus: "running" | "stopped",
  ): Promise<QualifiedQemuGraph> {
    const base = `/api2/json/nodes/${this.part(plan.node)}/qemu/${this.part(vmid)}`;
    const [
      config,
      pending,
      snapshots,
      firewallOptions,
      firewallRules,
      firewallAliases,
      firewallIpsets,
      haResources,
      status,
    ] = await Promise.all([
      this.data(`${base}/config?current=1`),
      this.data(`${base}/pending`),
      this.data(`${base}/snapshot`),
      this.data(`${base}/firewall/options`),
      this.data(`${base}/firewall/rules`),
      this.data(`${base}/firewall/aliases`),
      this.data(`${base}/firewall/ipset`),
      this.data("/api2/json/cluster/ha/resources"),
      this.data(`${base}/status/current`),
    ]);
    if (!isRecord(status) || status.status !== desiredStatus)
      throw this.denied("QEMU power state does not match the qualified phase");
    try {
      const volume =
        vmid === plan.templateVmid
          ? template
            ? plan.templateBootVolume
            : `vm-${plan.templateVmid}-disk-0`
          : plan.probeBootVolume;
      const templateResource =
        vmid === plan.templateVmid ||
        tags.join(";") ===
          ownershipTags(
            plan,
            plan.templateResourceId,
            "image_template",
            plan.templateNonce,
          ).join(";");
      return qualifyQemuConfig({
        config,
        evidence: {
          vmid,
          pending,
          snapshots,
          firewallOptions,
          firewallRules,
          firewallAliases,
          firewallIpsets,
          haResources,
        },
        expected: {
          vmid,
          storage: "local-lvm",
          volume,
          template,
          name:
            vmid === plan.probeVmid ? `Copy-of-VM-${plan.templateVmid}` : null,
          ownership: {
            installationId: plan.installationId,
            resourceId: templateResource
              ? plan.templateResourceId
              : plan.probeResourceId,
            nonce: templateResource ? plan.templateNonce : plan.probeNonce,
            tags,
          },
        },
      });
    } catch (error) {
      throw this.denied(
        error instanceof Error ? error.message : "QEMU config is not qualified",
      );
    }
  }

  private async assertVmAbsent(
    plan: QualificationExecutionContext["plan"],
    vmid: string,
    volumes: string[],
  ): Promise<void> {
    const base = `/api2/json/nodes/${this.part(plan.node)}/qemu/${this.part(vmid)}`;
    const [config, status, cluster, local, content] = await Promise.all([
      this.raw(`${base}/config?current=1`, "GET"),
      this.raw(`${base}/status/current`, "GET"),
      this.data("/api2/json/cluster/resources?type=vm"),
      this.data(`/api2/json/nodes/${this.part(plan.node)}/qemu`),
      this.data(
        `/api2/json/nodes/${this.part(plan.node)}/storage/${this.part(plan.targetStorage)}/content`,
      ),
    ]);
    if (
      !(await this.isExactVmMissing(config, plan.node, vmid)) ||
      !(await this.isExactVmMissing(status, plan.node, vmid)) ||
      !Array.isArray(cluster) ||
      !Array.isArray(local) ||
      !Array.isArray(content)
    )
      throw this.denied("QEMU absence evidence is incomplete");
    if (
      cluster.some((item) => isRecord(item) && String(item.vmid) === vmid) ||
      local.some((item) => isRecord(item) && String(item.vmid) === vmid) ||
      content.some(
        (item) =>
          isRecord(item) &&
          typeof item.volid === "string" &&
          volumes.some(
            (volume) => item.volid === `${plan.targetStorage}:${volume}`,
          ),
      )
    )
      throw this.denied("Qualified QEMU identity is already in use");
  }

  private async assertStage(
    plan: QualificationExecutionContext["plan"],
    present: boolean,
  ): Promise<void> {
    const content = await this.data(
      `/api2/json/nodes/${this.part(plan.node)}/storage/${this.part(plan.stageStorage)}/content`,
    );
    if (!Array.isArray(content))
      throw this.denied("Staging inventory is incomplete");
    const entry = content.find(
      (item) =>
        isRecord(item) &&
        item.volid === `${plan.stageStorage}:${plan.stageVolumeId}`,
    );
    if (!present && entry) throw this.denied("Staging artifact already exists");
    if (
      present &&
      (!isRecord(entry) || entry.size !== plan.image.manifest.artifactSize)
    )
      throw this.denied("Staging artifact does not match the saved image");
  }

  private async assertPoolMissing(
    plan: QualificationExecutionContext["plan"],
  ): Promise<void> {
    const response = await this.raw(
      `/api2/json/pools/${this.part(plan.pool)}`,
      "GET",
    );
    const body = await this.json(response);
    if (
      response.status !== 500 ||
      !isRecord(body) ||
      Object.keys(body).length !== 2 ||
      body.data !== null ||
      body.message !== `pool '${plan.pool}' does not exist\n`
    )
      throw this.denied(
        "Qualification pool already exists or cannot be verified absent",
      );
  }

  private async assertPool(
    plan: QualificationExecutionContext["plan"],
    vmids: string[],
  ): Promise<void> {
    const pool = await this.data(`/api2/json/pools/${this.part(plan.pool)}`);
    if (
      !isRecord(pool) ||
      pool.poolid !== plan.pool ||
      pool.comment !== plan.poolComment ||
      !Array.isArray(pool.members) ||
      pool.members.length !== vmids.length ||
      pool.members.some(
        (item) =>
          !isRecord(item) ||
          item.type !== "qemu" ||
          item.node !== plan.node ||
          !vmids.includes(String(item.vmid)),
      ) ||
      new Set(
        pool.members.map((item) =>
          String((item as Record<string, unknown>).vmid),
        ),
      ).size !== vmids.length
    )
      throw this.denied("Qualification pool membership changed");
  }

  private inspectSynchronous(
    context: QualificationExecutionContext,
    receipt: QualificationReceipt,
  ): QualificationInspection | Promise<QualificationInspection> {
    if (context.phase !== "POOL_CREATE" && context.phase !== "STAMP")
      return { status: "MISMATCH" };
    return this.assertAfter(context, context.phase)
      .then(() => ({ status: "COMPLETED" as const }))
      .catch(() => ({ status: "MISMATCH" as const }));
  }

  private receipt(
    context: QualificationExecutionContext,
    taskId: string | null,
    workerType: string | null,
    sourceVmid: string | null,
    destinationVmid: string | null,
    dispatch: NonNullable<QualificationReceipt["dispatch"]>,
    dispatchDigest: string,
    responseDigest: string,
  ): QualificationReceipt {
    return {
      taskId,
      workerType,
      sourceVmid,
      destinationVmid,
      tokenIdentity: context.plan.tokenIdentity,
      requestDigest: context.requestDigest,
      dispatch,
      dispatchDigest,
      responseDigest,
      generatedUuid: null,
      generatedCtime: null,
    };
  }

  private validReceipt(
    context: QualificationExecutionContext,
    receipt: QualificationReceipt,
  ): boolean {
    const expectedSource =
      context.phase === "CLONE" ? context.plan.templateVmid : null;
    const expectedDestination = [
      "IMPORT",
      "TEMPLATE",
      "DESTROY_TEMPLATE",
    ].includes(context.phase)
      ? context.plan.templateVmid
      : ["CLONE", "STAMP", "START", "STOP", "DESTROY_PROBE"].includes(
            context.phase,
          )
        ? context.plan.probeVmid
        : null;
    const expectedWorker = workers[context.phase] ?? null;
    if (
      receipt.tokenIdentity !== context.plan.tokenIdentity ||
      receipt.requestDigest !== context.requestDigest ||
      receipt.sourceVmid !== expectedSource ||
      receipt.destinationVmid !== expectedDestination ||
      !/^[a-f0-9]{64}$/.test(receipt.dispatchDigest) ||
      !/^[a-f0-9]{64}$/.test(receipt.responseDigest) ||
      (receipt.taskId === null) !== (receipt.workerType === null) ||
      receipt.workerType !== expectedWorker ||
      !this.validDispatch(context, receipt.dispatch)
    )
      return false;
    if (expectedWorker !== null) {
      const task =
        receipt.taskId === null ? null : this.parseUpid(receipt.taskId);
      if (!task || !this.matchesUpid(context, task, expectedWorker))
        return false;
    }
    return (
      receipt.dispatchDigest ===
      canonicalQualificationDispatch(receipt.dispatch)
    );
  }

  private assertContext(context: QualificationExecutionContext): void {
    const { plan, phase } = context;
    if (
      plan.pveVersion !== "9.2.2" ||
      plan.tokenIdentity !== this.credentials.tokenId ||
      !plan.poolComment.endsWith(`;nonce=${plan.poolNonce}`) ||
      plan.templateVmid === plan.probeVmid ||
      plan.templateBootVolume !== `base-${plan.templateVmid}-disk-0` ||
      plan.probeBootVolume !== `vm-${plan.probeVmid}-disk-0` ||
      !/^[1-9][0-9]{2,8}$/.test(plan.templateVmid) ||
      !/^[1-9][0-9]{2,8}$/.test(plan.probeVmid) ||
      context.requestDigest !==
        createHash("sha256")
          .update(`${plan.canonicalDigest}:${phase}`)
          .digest("hex")
    )
      throw this.denied("Qualification context is invalid");
    for (const previous of phases.slice(0, phases.indexOf(phase))) {
      const receipt = context.priorReceipts[previous];
      const requestDigest = createHash("sha256")
        .update(`${plan.canonicalDigest}:${previous}`)
        .digest("hex");
      if (
        !receipt ||
        !this.validReceipt(
          { ...context, phase: previous, requestDigest },
          receipt,
        )
      )
        throw this.denied("Qualification phase history is incomplete");
    }
  }

  private parseUpid(value: string): Upid | null {
    const match = UPID.exec(value);
    if (!match) return null;
    const [, node, pid, pstart, starttime, type, id, identity] = match;
    if (
      !node ||
      !pid ||
      !pstart ||
      !starttime ||
      !type ||
      id === undefined ||
      !identity
    )
      return null;
    return {
      node,
      pid: Number.parseInt(pid, 16),
      pstart: Number.parseInt(pstart, 16),
      starttime: Number.parseInt(starttime, 16),
      type,
      id,
      identity,
    };
  }

  private matchesUpid(
    context: QualificationExecutionContext,
    upid: Upid,
    worker: string,
  ): boolean {
    const object =
      worker === "imgcopy"
        ? ""
        : worker === "qmclone"
          ? context.plan.templateVmid
          : worker === "qmcreate" ||
              worker === "qmtemplate" ||
              (worker === "qmdestroy" && context.phase === "DESTROY_TEMPLATE")
            ? context.plan.templateVmid
            : context.plan.probeVmid;
    return (
      upid.node === context.plan.node &&
      upid.type === worker &&
      upid.id === object &&
      upid.identity === context.plan.tokenIdentity
    );
  }

  private matchesTaskStatus(
    value: unknown,
    taskId: string,
    upid: Upid,
  ): boolean {
    if (
      !isRecord(value) ||
      value.upid !== taskId ||
      value.node !== upid.node ||
      value.type !== upid.type ||
      value.id !== upid.id ||
      value.pid !== upid.pid ||
      value.pstart !== upid.pstart ||
      value.starttime !== upid.starttime ||
      typeof value.user !== "string" ||
      typeof value.tokenid !== "string"
    )
      return false;
    return `${value.user}!${value.tokenid}` === upid.identity;
  }

  private contentSet(value: unknown): Set<string> {
    if (typeof value !== "string" || value.length === 0) return new Set();
    return new Set(
      value
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean),
    );
  }

  private dispatch(
    mutation: Mutation,
  ): NonNullable<QualificationReceipt["dispatch"]> {
    const body = mutation.descriptor.body;
    if (body === null)
      return { method: mutation.method, path: mutation.path, body: null };
    if (
      !isRecord(body) ||
      Object.values(body).some(
        (value) => typeof value !== "string" && typeof value !== "number",
      )
    )
      throw this.denied("Qualification dispatch descriptor is invalid");
    return {
      method: mutation.method,
      path: mutation.path,
      body: body as Record<string, string | number>,
    };
  }

  private validDispatch(
    context: QualificationExecutionContext,
    dispatch: QualificationReceipt["dispatch"],
  ): dispatch is NonNullable<QualificationReceipt["dispatch"]> {
    if (
      !dispatch ||
      !isRecord(dispatch) ||
      Object.keys(dispatch).length !== 3 ||
      typeof dispatch.method !== "string" ||
      typeof dispatch.path !== "string" ||
      (dispatch.body !== null &&
        (!isRecord(dispatch.body) ||
          Object.values(dispatch.body).some(
            (value) => typeof value !== "string" && typeof value !== "number",
          )))
    )
      return false;
    if (context.phase === "STAMP") {
      const expectedPath = `/api2/json/nodes/${this.part(context.plan.node)}/qemu/${this.part(context.plan.probeVmid)}/config`;
      const body = dispatch.body;
      return (
        dispatch.method === "PUT" &&
        dispatch.path === expectedPath &&
        isRecord(body) &&
        Object.keys(body).length === 2 &&
        typeof body.digest === "string" &&
        /^[a-f0-9]{40}$/.test(body.digest) &&
        body.tags ===
          ownershipTags(
            context.plan,
            context.plan.probeResourceId,
            "network_probe",
            context.plan.probeNonce,
          ).join(";")
      );
    }
    try {
      const expected = this.dispatch(this.mutation(context, null));
      return (
        canonicalQualificationDispatch(dispatch) ===
        canonicalQualificationDispatch(expected)
      );
    } catch {
      return false;
    }
  }

  private form(values: Record<string, string>): URLSearchParams {
    return new URLSearchParams(values);
  }
  private part(value: string): string {
    return encodeURIComponent(value);
  }
  private denied(message: string): KilnError {
    return new KilnError("SAFETY_DENIED", 403, message);
  }

  private async mutate(mutation: Mutation): Promise<unknown> {
    const response = await this.raw(
      mutation.path,
      mutation.method,
      mutation.body,
    );
    if (!response.ok) throw this.denied("Proxmox mutation was rejected");
    const body = await this.json(response);
    if (!isRecord(body) || !Object.hasOwn(body, "data"))
      throw this.denied("Proxmox mutation returned an invalid response");
    return body.data;
  }

  private async data(path: string): Promise<unknown> {
    const response = await this.raw(path, "GET");
    if (!response.ok) throw this.denied("Proxmox observation failed");
    const body = await this.json(response);
    if (!isRecord(body) || !Object.hasOwn(body, "data"))
      throw this.denied("Proxmox observation returned an invalid response");
    return body.data;
  }

  private async isExactVmMissing(
    response: Response,
    node: string,
    vmid: string,
  ): Promise<boolean> {
    const body = await this.json(response);
    return (
      response.status === 500 &&
      isRecord(body) &&
      Object.keys(body).length === 2 &&
      body.data === null &&
      body.message ===
        `Configuration file 'nodes/${node}/qemu-server/${vmid}.conf' does not exist\n`
    );
  }

  private async json(response: Response): Promise<unknown> {
    try {
      return await response.json();
    } catch {
      throw this.denied("Proxmox response is not JSON");
    }
  }

  private async raw(
    path: string,
    method: string,
    body?: BodyInit,
  ): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5_000);
    try {
      return await this.fetcher(new URL(path, this.credentials.url), {
        method,
        headers: {
          Authorization: `PVEAPIToken=${this.credentials.tokenId}=${this.credentials.tokenSecret}`,
        },
        body,
        redirect: "error",
        signal: controller.signal,
      });
    } catch {
      throw this.denied("Proxmox request failed");
    } finally {
      clearTimeout(timer);
    }
  }
}
