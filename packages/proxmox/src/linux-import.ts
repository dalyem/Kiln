import { createHash } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import { open, type FileHandle } from "node:fs/promises";
import { Readable } from "node:stream";
import {
  KilnError,
  type LinuxImportPhaseName,
  type LinuxImportPlan,
  type LinuxImportProvider,
  type LinuxImportReceipt,
} from "@kiln/core";
import type { QualificationCredentials } from "./qualification.js";
import {
  canonicalLinuxQualifiedQemuIdentity,
  qualifyLinuxImportQemuGraph,
  type LinuxQualifiedQemuGraph,
} from "./linux-qualified-config.js";

const UPID =
  /^UPID:([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?):([0-9A-Fa-f]{8}):([0-9A-Fa-f]{8,9}):([0-9A-Fa-f]{8}):([^:\s/]+):([^:\s/]*):([^:\s/]+):$/;
const VMID = /^[1-9][0-9]{2,8}$/;
const NATIVE = /^[A-Za-z0-9._-]{1,64}$/;
const SHA1 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const STAGING = /^lstg_[a-f0-9]{32}$/;
const MAX_STAGE = 2 * 1024 * 1024 * 1024;
const phases: LinuxImportPhaseName[] = [
  "UPLOAD",
  "IMPORT",
  "TEMPLATE",
  "CLONE",
  "STAMP",
  "START",
  "STOP",
  "DESTROY_CLONE",
  "DESTROY_TEMPLATE",
];

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
  headers?: Record<string, string>;
  close?: () => Promise<void>;
  descriptor: LinuxImportReceipt["dispatch"];
  worker: string | null;
}
interface StagedFile {
  file: FileHandle;
  first: BigIntStats;
  size: number;
  sha256: string;
}
type Context = {
  plan: LinuxImportPlan;
  phase: LinuxImportPhaseName;
  requestDigest?: string;
  priorReceipts?: Partial<Record<LinuxImportPhaseName, LinuxImportReceipt>>;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function hash(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function intentDigest(
  plan: LinuxImportPlan,
  phase: LinuxImportPhaseName,
): string {
  return createHash("sha256")
    .update(`${plan.canonicalDigest}:${phase}`)
    .digest("hex");
}
function dispatchDigest(dispatch: LinuxImportReceipt["dispatch"]): string {
  return createHash("sha256")
    .update(
      JSON.stringify({
        method: dispatch.method,
        path: dispatch.path,
        body:
          dispatch.body === null
            ? null
            : Object.fromEntries(
                Object.entries(dispatch.body).sort(([a], [b]) =>
                  a.localeCompare(b),
                ),
              ),
      }),
    )
    .digest("hex");
}
function tags(
  plan: LinuxImportPlan,
  id: string,
  kind: "image_template" | "execution",
  nonce: string,
): string[] {
  return [
    "kiln",
    "kiln-managed",
    `kiln-installation-${plan.installationId}`,
    `kiln-resource-${kind}`,
    `kiln-resource-id-${id}`,
    `kiln-import-nonce-${nonce}`,
  ];
}
function previous(phase: LinuxImportPhaseName): LinuxImportPhaseName | null {
  const index = phases.indexOf(phase);
  return index > 0 ? phases[index - 1]! : null;
}

/** Separate, opt-in writer for the Linux-image qualification path. The normal provider stays read-only. */
export class ProxmoxLinuxImportProvider implements LinuxImportProvider {
  readonly mode = "proxmox-linux-image-import" as const;
  constructor(
    private readonly credentials: QualificationCredentials,
    private readonly fetcher: typeof fetch = fetch,
  ) {
    if (credentials.url.protocol !== "https:")
      throw this.denied("Proxmox API URL must use HTTPS");
  }

  async executeLinuxImportPhase(context: Context): Promise<LinuxImportReceipt> {
    this.assertContext(context as Context & { requestDigest: string });
    const graph = await this.assertPrecondition(context);
    const mutation = await this.mutation(context, graph);
    const response = await this.mutate(mutation, context.phase);
    const sourceVmid =
      context.phase === "CLONE" ? context.plan.templateVmid : null;
    const destinationVmid = ["IMPORT", "TEMPLATE", "DESTROY_TEMPLATE"].includes(
      context.phase,
    )
      ? context.plan.templateVmid
      : ["CLONE", "STAMP", "START", "STOP", "DESTROY_CLONE"].includes(
            context.phase,
          )
        ? context.plan.cloneVmid
        : null;
    const receiptDispatchDigest = dispatchDigest(mutation.descriptor);
    if (mutation.worker === null)
      return this.receipt(
        context,
        null,
        null,
        sourceVmid,
        destinationVmid,
        mutation.descriptor,
        receiptDispatchDigest,
        hash({ acknowledgement: response }),
      );
    if (typeof response !== "string")
      throw this.denied("Proxmox task receipt is missing");
    const upid = this.parseUpid(response);
    if (!upid || !this.matchesUpid(context, upid, mutation.worker))
      throw this.denied(
        "Proxmox task receipt does not match the planned operation",
      );
    return this.receipt(
      context,
      response,
      mutation.worker,
      sourceVmid,
      destinationVmid,
      mutation.descriptor,
      receiptDispatchDigest,
      hash({ upid: response }),
    );
  }

  async inspectLinuxImportPhase(
    context: Context & { receipt: LinuxImportReceipt },
  ): Promise<import("@kiln/core").LinuxImportInspection> {
    try {
      const execution = {
        ...context,
        requestDigest: intentDigest(context.plan, context.phase),
      };
      this.assertContext(execution);
      if (!this.validReceipt(execution, context.receipt))
        return { status: "MISMATCH" };
      await this.assertEnvironment(execution.plan, execution.phase);
      if (context.receipt.taskId === null) {
        await this.assertAfter(execution, execution.phase);
        return { status: "COMPLETED" };
      }
      const worker = this.worker(execution.phase);
      const upid = worker && this.parseUpid(context.receipt.taskId);
      if (!worker || !upid || !this.matchesUpid(execution, upid, worker))
        return { status: "MISMATCH" };
      const task = await this.data(
        `/api2/json/nodes/${this.part(execution.plan.node)}/tasks/${this.part(context.receipt.taskId)}/status`,
      );
      if (!this.matchesTask(task, context.receipt.taskId, upid))
        return { status: "MISMATCH" };
      if ((task as Record<string, unknown>).status === "running")
        return { status: "RUNNING" };
      if (
        (task as Record<string, unknown>).status !== "stopped" ||
        (task as Record<string, unknown>).exitstatus !== "OK"
      )
        return { status: "FAILED" };
      const graph = await this.assertAfter(execution, execution.phase);
      if (context.phase === "CLONE" && graph) {
        return {
          status: "COMPLETED",
          receiptPatch: {
            generatedUuid: graph.generatedUuid,
            generatedCtime: graph.generatedCtime,
            configDigest: graph.configDigest,
            responseDigest: canonicalLinuxQualifiedQemuIdentity(graph),
          },
        };
      }
      return { status: "COMPLETED" };
    } catch {
      return { status: "UNKNOWN" };
    }
  }

  private async mutation(
    context: Context,
    graph: LinuxQualifiedQemuGraph | null,
  ): Promise<Mutation> {
    const { plan, phase } = context;
    const node = `/api2/json/nodes/${this.part(plan.node)}`;
    if (phase === "UPLOAD") return this.upload(plan, node);
    if (phase === "IMPORT")
      return this.form(
        "POST",
        `${node}/qemu`,
        {
          vmid: plan.templateVmid,
          pool: plan.pool,
          name: plan.templateName,
          bios: "seabios",
          scsihw: "virtio-scsi-pci",
          boot: "order=scsi0",
          serial0: "socket",
          memory: "2048",
          cores: "2",
          cpu: "kvm64",
          tags: tags(
            plan,
            plan.templateResourceId,
            "image_template",
            plan.templateNonce,
          ).join(";"),
          scsi0: `${plan.targetStorage}:0,import-from=${plan.stageStorage}:import/${plan.stageId}.qcow2`,
        },
        "qmcreate",
      );
    if (phase === "TEMPLATE")
      return this.empty(
        `${node}/qemu/${this.part(plan.templateVmid)}/template`,
        "qmtemplate",
      );
    if (phase === "CLONE")
      return this.form(
        "POST",
        `${node}/qemu/${this.part(plan.templateVmid)}/clone`,
        {
          newid: plan.cloneVmid,
          name: plan.cloneName,
          pool: plan.pool,
          storage: plan.targetStorage,
          full: "1",
        },
        "qmclone",
      );
    if (phase === "STAMP") {
      if (!graph)
        throw this.denied(
          "Linux clone identity is missing before ownership stamping",
        );
      return this.form(
        "PUT",
        `${node}/qemu/${this.part(plan.cloneVmid)}/config`,
        {
          digest: graph.configDigest,
          tags: tags(
            plan,
            plan.cloneResourceId,
            "execution",
            plan.cloneNonce,
          ).join(";"),
        },
        null,
      );
    }
    if (phase === "START")
      return this.empty(
        `${node}/qemu/${this.part(plan.cloneVmid)}/status/start`,
        "qmstart",
      );
    if (phase === "STOP")
      return this.empty(
        `${node}/qemu/${this.part(plan.cloneVmid)}/status/stop`,
        "qmstop",
      );
    if (phase === "DESTROY_CLONE" || phase === "DESTROY_TEMPLATE") {
      const vmid =
        phase === "DESTROY_CLONE" ? plan.cloneVmid : plan.templateVmid;
      const path = `${node}/qemu/${this.part(vmid)}?purge=0&destroy-unreferenced-disks=0`;
      return {
        method: "DELETE",
        path,
        descriptor: { method: "DELETE", path, body: null },
        worker: "qmdestroy",
      };
    }
    throw this.denied("Linux image import phase is unsupported");
  }

  private async upload(plan: LinuxImportPlan, node: string): Promise<Mutation> {
    const fields = {
      content: "import",
      "checksum-algorithm": "sha256",
      checksum: plan.stageSha256,
      filename: `${plan.stageId}.qcow2`,
    };
    const boundary = `kiln-${hash({ plan: plan.canonicalDigest, phase: "upload" }).slice(0, 32)}`;
    const staged = await this.openStage(plan);
    let closed = false;
    const close = async () => {
      if (closed) return;
      closed = true;
      await staged.file.close();
    };
    return {
      method: "POST",
      path: `${node}/storage/${this.part(plan.stageStorage)}/upload`,
      body: Readable.toWeb(
        Readable.from(multipart(staged, boundary, fields)),
      ) as unknown as BodyInit,
      headers: {
        "content-type": `multipart/form-data; boundary=${boundary}`,
        "content-length": String(multipartSize(boundary, fields, staged.size)),
      },
      close,
      descriptor: {
        method: "POST",
        path: `${node}/storage/${this.part(plan.stageStorage)}/upload`,
        body: fields,
      },
      worker: "imgcopy",
    };
  }

  private form(
    method: "POST" | "PUT",
    path: string,
    fields: Record<string, string>,
    worker: string | null,
  ): Mutation {
    return {
      method,
      path,
      body: new URLSearchParams(fields),
      headers: { "content-type": "application/x-www-form-urlencoded" },
      descriptor: { method, path, body: fields },
      worker,
    };
  }
  private empty(path: string, worker: string): Mutation {
    return this.form("POST", path, {}, worker);
  }

  private async assertPrecondition(
    context: Context,
  ): Promise<LinuxQualifiedQemuGraph | null> {
    await this.assertEnvironment(context.plan, context.phase);
    const prior = previous(context.phase);
    if (!prior) {
      await this.assertPool(context.plan, []);
      await this.assertStage(context.plan, false);
      await this.assertAbsent(context.plan, context.plan.templateVmid, [
        `vm-${context.plan.templateVmid}-disk-0`,
        `base-${context.plan.templateVmid}-disk-0`,
      ]);
      await this.assertAbsent(context.plan, context.plan.cloneVmid, [
        `vm-${context.plan.cloneVmid}-disk-0`,
      ]);
      return null;
    }
    const graph = await this.assertAfter(context, prior);
    if (context.phase !== "STAMP") return graph;
    const receipt = context.priorReceipts?.CLONE as
      | (LinuxImportReceipt & {
          generatedUuid?: string;
          generatedCtime?: string;
        })
      | undefined;
    const clone = await this.vm(
      context.plan,
      context.plan.cloneVmid,
      false,
      tags(
        context.plan,
        context.plan.templateResourceId,
        "image_template",
        context.plan.templateNonce,
      ),
      "stopped",
      context.plan.cloneName,
    );
    if (
      !receipt ||
      receipt.sourceVmid !== context.plan.templateVmid ||
      receipt.destinationVmid !== context.plan.cloneVmid ||
      receipt.generatedUuid !== clone.generatedUuid ||
      receipt.generatedCtime !== clone.generatedCtime ||
      receipt.configDigest !== clone.configDigest ||
      receipt.responseDigest !== canonicalLinuxQualifiedQemuIdentity(clone)
    )
      throw this.denied(
        "Linux clone identity changed before ownership stamping",
      );
    return clone;
  }

  private async assertAfter(
    context: Context,
    phase: LinuxImportPhaseName,
  ): Promise<LinuxQualifiedQemuGraph | null> {
    const plan = context.plan;
    if (phase === "UPLOAD") {
      await this.assertPool(plan, []);
      await this.assertStage(plan, true);
      await this.assertAbsent(plan, plan.templateVmid, [
        `vm-${plan.templateVmid}-disk-0`,
        `base-${plan.templateVmid}-disk-0`,
      ]);
      await this.assertAbsent(plan, plan.cloneVmid, [
        `vm-${plan.cloneVmid}-disk-0`,
      ]);
      return null;
    }
    if (phase === "IMPORT") {
      await this.assertPool(plan, [plan.templateVmid]);
      await this.assertStage(plan, true);
      const graph = await this.vm(
        plan,
        plan.templateVmid,
        false,
        tags(
          plan,
          plan.templateResourceId,
          "image_template",
          plan.templateNonce,
        ),
        "stopped",
        plan.templateName,
      );
      await this.assertAbsent(plan, plan.cloneVmid, [
        `vm-${plan.cloneVmid}-disk-0`,
      ]);
      return graph;
    }
    if (phase === "TEMPLATE") {
      await this.assertPool(plan, [plan.templateVmid]);
      await this.assertStage(plan, true);
      const graph = await this.vm(
        plan,
        plan.templateVmid,
        true,
        tags(
          plan,
          plan.templateResourceId,
          "image_template",
          plan.templateNonce,
        ),
        "stopped",
        plan.templateName,
      );
      await this.assertAbsent(plan, plan.cloneVmid, [
        `vm-${plan.cloneVmid}-disk-0`,
      ]);
      return graph;
    }
    if (phase === "CLONE") {
      await this.assertPool(plan, [plan.templateVmid, plan.cloneVmid]);
      await this.assertStage(plan, true);
      await this.vm(
        plan,
        plan.templateVmid,
        true,
        tags(
          plan,
          plan.templateResourceId,
          "image_template",
          plan.templateNonce,
        ),
        "stopped",
        plan.templateName,
      );
      return this.vm(
        plan,
        plan.cloneVmid,
        false,
        tags(
          plan,
          plan.templateResourceId,
          "image_template",
          plan.templateNonce,
        ),
        "stopped",
        plan.cloneName,
      );
    }
    if (phase === "STAMP" || phase === "START" || phase === "STOP") {
      await this.assertPool(plan, [plan.templateVmid, plan.cloneVmid]);
      await this.assertStage(plan, true);
      await this.vm(
        plan,
        plan.templateVmid,
        true,
        tags(
          plan,
          plan.templateResourceId,
          "image_template",
          plan.templateNonce,
        ),
        "stopped",
        plan.templateName,
      );
      const graph = await this.vm(
        plan,
        plan.cloneVmid,
        false,
        tags(plan, plan.cloneResourceId, "execution", plan.cloneNonce),
        phase === "START" ? "running" : "stopped",
        plan.cloneName,
      );
      const receipt = context.priorReceipts?.CLONE;
      if (
        !receipt ||
        receipt.responseDigest !== canonicalLinuxQualifiedQemuIdentity(graph)
      )
        throw this.denied("Linux clone identity changed after creation");
      return graph;
    }
    if (phase === "DESTROY_CLONE") {
      await this.assertPool(plan, [plan.templateVmid]);
      await this.assertStage(plan, true);
      await this.vm(
        plan,
        plan.templateVmid,
        true,
        tags(
          plan,
          plan.templateResourceId,
          "image_template",
          plan.templateNonce,
        ),
        "stopped",
        plan.templateName,
      );
      await this.assertAbsent(plan, plan.cloneVmid, [
        `vm-${plan.cloneVmid}-disk-0`,
      ]);
      return null;
    }
    if (phase === "DESTROY_TEMPLATE") {
      await this.assertPool(plan, []);
      await this.assertStage(plan, true);
      await this.assertAbsent(plan, plan.templateVmid, [
        `vm-${plan.templateVmid}-disk-0`,
        `base-${plan.templateVmid}-disk-0`,
      ]);
      await this.assertAbsent(plan, plan.cloneVmid, [
        `vm-${plan.cloneVmid}-disk-0`,
      ]);
      return null;
    }
    throw this.denied("Linux image import phase is unsupported");
  }

  private async assertEnvironment(
    plan: LinuxImportPlan,
    phase: LinuxImportPhaseName,
  ): Promise<void> {
    if (
      plan.schemaVersion !== 1 ||
      plan.pveVersion !== "9.2.2" ||
      plan.stageStorage !== "local" ||
      plan.targetStorage !== "local-lvm" ||
      plan.tokenIdentity !== this.credentials.tokenId ||
      !NATIVE.test(plan.node) ||
      !NATIVE.test(plan.pool) ||
      !NATIVE.test(plan.stageStorage) ||
      !NATIVE.test(plan.targetStorage) ||
      !NATIVE.test(plan.templateName) ||
      !NATIVE.test(plan.cloneName) ||
      !SHA1.test(plan.storageConfigDigest)
    )
      throw this.denied("Linux image import plan is invalid");
    const [version, permissions, storage, nodeStorage, cluster, local] =
      await Promise.all([
        this.data("/api2/json/version"),
        this.data("/api2/json/access/permissions"),
        this.data("/api2/json/storage"),
        this.data(`/api2/json/nodes/${this.part(plan.node)}/storage`),
        this.data("/api2/json/cluster/resources?type=vm"),
        this.data(`/api2/json/nodes/${this.part(plan.node)}/qemu`),
      ]);
    const perms = isRecord(permissions) ? permissions["/"] : null;
    if (
      !isRecord(version) ||
      version.version !== "9.2.2" ||
      !isRecord(perms) ||
      perms["Sys.Audit"] !== 1 ||
      perms["VM.Audit"] !== 1 ||
      !isRecord(permissions) ||
      !Array.isArray(storage) ||
      !Array.isArray(nodeStorage) ||
      !Array.isArray(cluster) ||
      !Array.isArray(local) ||
      !this.vmInventory(cluster, ["qemu", "lxc"]) ||
      !this.nodeQemuInventory(local)
    )
      throw this.denied("Proxmox Linux import evidence is incomplete");
    const stage = storage.find(
        (x) => isRecord(x) && x.storage === plan.stageStorage,
      ),
      target = storage.find(
        (x) => isRecord(x) && x.storage === plan.targetStorage,
      ),
      nstage = nodeStorage.find(
        (x) => isRecord(x) && x.storage === plan.stageStorage,
      ),
      ntarget = nodeStorage.find(
        (x) => isRecord(x) && x.storage === plan.targetStorage,
      );
    if (
      !isRecord(stage) ||
      !isRecord(target) ||
      !isRecord(nstage) ||
      !isRecord(ntarget) ||
      stage.type !== "dir" ||
      stage.path !== "/var/lib/vz" ||
      !this.contents(stage.content).has("import") ||
      stage.digest !== plan.storageConfigDigest ||
      target.type !== "lvmthin" ||
      target.vgname !== "pve" ||
      target.thinpool !== "data" ||
      !this.contents(target.content).has("images") ||
      target.digest !== plan.storageConfigDigest ||
      nstage.type !== "dir" ||
      ntarget.type !== "lvmthin" ||
      nstage.active !== 1 ||
      nstage.enabled !== 1 ||
      nstage.shared !== 0 ||
      ntarget.active !== 1 ||
      ntarget.enabled !== 1 ||
      ntarget.shared !== 0
    )
      throw this.denied("Linux image import storage changed");
    this.assertAuditPermissions(permissions, plan);
    this.assertPermissions(permissions, plan, phase);
  }

  private async assertPool(
    plan: LinuxImportPlan,
    ids: string[],
  ): Promise<void> {
    const pool = await this.data(`/api2/json/pools/${this.part(plan.pool)}`);
    if (
      !isRecord(pool) ||
      pool.poolid !== plan.pool ||
      pool.comment !== plan.sourcePoolComment ||
      !plan.sourcePoolComment.endsWith(`;nonce=${plan.sourcePoolNonce}`) ||
      !Array.isArray(pool.members) ||
      pool.members.length !== ids.length ||
      pool.members.some(
        (x) =>
          !isRecord(x) ||
          x.type !== "qemu" ||
          x.node !== plan.node ||
          !ids.includes(String(x.vmid)),
      ) ||
      new Set(
        pool.members.map((x) => String((x as Record<string, unknown>).vmid)),
      ).size !== ids.length
    )
      throw this.denied("Retained Kiln pool membership changed");
  }

  private async assertStage(
    plan: LinuxImportPlan,
    present: boolean,
  ): Promise<void> {
    const content = await this.data(
      `/api2/json/nodes/${this.part(plan.node)}/storage/${this.part(plan.stageStorage)}/content`,
    );
    if (!Array.isArray(content) || !this.volumeInventory(content))
      throw this.denied("Linux staging inventory is incomplete");
    const entries = content.filter(
      (x) =>
        isRecord(x) &&
        x.volid === `${plan.stageStorage}:import/${plan.stageId}.qcow2`,
    );
    if (
      (!present && entries.length) ||
      (present &&
        (entries.length !== 1 ||
          entries[0]!.size !== plan.image.manifest.artifactSize))
    )
      throw this.denied(
        "Linux staging artifact does not match the saved image",
      );
  }

  private async vm(
    plan: LinuxImportPlan,
    vmid: string,
    template: boolean,
    expectedTags: string[],
    desiredStatus: "running" | "stopped",
    name: string,
  ): Promise<LinuxQualifiedQemuGraph> {
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
      content,
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
      this.data(
        `/api2/json/nodes/${this.part(plan.node)}/storage/${this.part(plan.targetStorage)}/content`,
      ),
    ]);
    const volume = `${template ? "base" : "vm"}-${vmid}-disk-0`;
    if (
      !Array.isArray(content) ||
      !this.volumeInventory(content) ||
      content.filter(
        (x) => isRecord(x) && x.volid === `${plan.targetStorage}:${volume}`,
      ).length !== 1 ||
      content.some(
        (x) =>
          isRecord(x) &&
          typeof x.volid === "string" &&
          (x.volid.startsWith(`${plan.targetStorage}:vm-${vmid}-`) ||
            x.volid.startsWith(`${plan.targetStorage}:base-${vmid}-`)) &&
          x.volid !== `${plan.targetStorage}:${volume}`,
      )
    )
      throw this.denied(
        "Linux QEMU boot volume does not match the planned attachment",
      );
    try {
      return qualifyLinuxImportQemuGraph(
        config,
        {
          vmid,
          pending,
          snapshots,
          firewallOptions,
          firewallRules,
          firewallAliases,
          firewallIpsets,
          haResources,
          status,
        },
        {
          vmid,
          storage: plan.targetStorage,
          volume,
          template,
          name,
          tags: expectedTags,
          status: desiredStatus,
        },
      );
    } catch (error) {
      throw this.denied(
        error instanceof Error
          ? error.message
          : "Linux QEMU config is not qualified",
      );
    }
  }

  private async assertAbsent(
    plan: LinuxImportPlan,
    vmid: string,
    volumes: string[],
  ): Promise<void> {
    const base = `/api2/json/nodes/${this.part(plan.node)}/qemu/${this.part(vmid)}`;
    const [config, status, cluster, local, content] = await Promise.all([
      this.raw(`${base}/config?current=1`, "GET", undefined, 5_000),
      this.raw(`${base}/status/current`, "GET", undefined, 5_000),
      this.data("/api2/json/cluster/resources?type=vm"),
      this.data(`/api2/json/nodes/${this.part(plan.node)}/qemu`),
      this.data(
        `/api2/json/nodes/${this.part(plan.node)}/storage/${this.part(plan.targetStorage)}/content`,
      ),
    ]);
    if (
      !(await this.missing(config, plan.node, vmid)) ||
      !(await this.missing(status, plan.node, vmid)) ||
      !Array.isArray(cluster) ||
      !Array.isArray(local) ||
      !Array.isArray(content) ||
      !this.vmInventory(cluster, ["qemu", "lxc"]) ||
      !this.nodeQemuInventory(local) ||
      !this.volumeInventory(content) ||
      cluster.some((x) => isRecord(x) && String(x.vmid) === vmid) ||
      local.some((x) => isRecord(x) && String(x.vmid) === vmid) ||
      content.some(
        (x) =>
          isRecord(x) &&
          typeof x.volid === "string" &&
          (x.volid.startsWith(`${plan.targetStorage}:vm-${vmid}-`) ||
            x.volid.startsWith(`${plan.targetStorage}:base-${vmid}-`)),
      )
    )
      throw this.denied("Linux QEMU identity is already in use");
  }

  private async openStage(plan: LinuxImportPlan): Promise<StagedFile> {
    if (
      !STAGING.test(plan.stageId) ||
      !SHA256.test(plan.stageSha256) ||
      !Number.isSafeInteger(plan.image.manifest.artifactSize) ||
      plan.image.manifest.artifactSize <= 0 ||
      plan.image.manifest.artifactSize > MAX_STAGE ||
      typeof plan.stagePath !== "string" ||
      !plan.stagePath.startsWith("/") ||
      plan.stagePath.includes("\0")
    )
      throw this.denied("Linux image staging descriptor is invalid");
    let file: FileHandle;
    try {
      file = await open(
        plan.stagePath,
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
      );
    } catch {
      throw this.denied("Linux image staging file cannot be opened");
    }
    try {
      const first = await file.stat({ bigint: true });
      if (
        !first.isFile() ||
        first.size !== BigInt(plan.image.manifest.artifactSize)
      )
        throw this.denied("Linux image staging file changed");
      const sum = await checksum(file, plan.image.manifest.artifactSize);
      const after = await file.stat({ bigint: true });
      if (
        sum !== plan.stageSha256 ||
        first.dev !== after.dev ||
        first.ino !== after.ino ||
        first.size !== after.size ||
        first.mtimeNs !== after.mtimeNs ||
        first.ctimeNs !== after.ctimeNs
      )
        throw this.denied("Linux image staging file changed");
      return {
        file,
        first,
        size: plan.image.manifest.artifactSize,
        sha256: sum,
      };
    } catch (error) {
      await file.close();
      throw error;
    }
  }

  private receipt(
    context: Context,
    taskId: string | null,
    workerType: string | null,
    sourceVmid: string | null,
    destinationVmid: string | null,
    dispatch: LinuxImportReceipt["dispatch"],
    dispatchDigest: string,
    responseDigest: string,
  ): LinuxImportReceipt {
    return {
      taskId,
      tokenIdentity: this.credentials.tokenId,
      workerType,
      sourceVmid,
      destinationVmid,
      requestDigest: context.requestDigest!,
      dispatch,
      dispatchDigest,
      responseDigest,
      generatedUuid: null,
      generatedCtime: null,
      configDigest: null,
    };
  }
  private worker(phase: LinuxImportPhaseName): string | null {
    return (
      {
        UPLOAD: "imgcopy",
        IMPORT: "qmcreate",
        TEMPLATE: "qmtemplate",
        CLONE: "qmclone",
        STAMP: null,
        START: "qmstart",
        STOP: "qmstop",
        DESTROY_CLONE: "qmdestroy",
        DESTROY_TEMPLATE: "qmdestroy",
      } as const
    )[phase];
  }
  private assertContext(context: Context & { requestDigest: string }): void {
    const plan = context.plan;
    if (
      !VMID.test(plan.templateVmid) ||
      !VMID.test(plan.cloneVmid) ||
      plan.templateVmid === plan.cloneVmid ||
      !plan.installationId ||
      !plan.sourcePoolRunId ||
      !plan.sourcePoolAllocationId ||
      !plan.sourcePoolNonce ||
      !plan.sourcePoolComment ||
      !plan.templateResourceId ||
      !plan.cloneResourceId ||
      !plan.templateNonce ||
      !plan.cloneNonce ||
      context.requestDigest !== intentDigest(plan, context.phase)
    )
      throw this.denied("Linux image import context is invalid");
    for (const phase of phases.slice(0, phases.indexOf(context.phase))) {
      const receipt = context.priorReceipts?.[phase];
      if (
        !receipt ||
        !this.validReceipt(
          { ...context, phase, requestDigest: intentDigest(plan, phase) },
          receipt,
        )
      )
        throw this.denied("Linux image import history is incomplete");
    }
  }
  private validReceipt(
    context: Context & { requestDigest: string },
    receipt: LinuxImportReceipt,
  ): boolean {
    const worker = this.worker(context.phase),
      source = context.phase === "CLONE" ? context.plan.templateVmid : null,
      destination = ["IMPORT", "TEMPLATE", "DESTROY_TEMPLATE"].includes(
        context.phase,
      )
        ? context.plan.templateVmid
        : ["CLONE", "STAMP", "START", "STOP", "DESTROY_CLONE"].includes(
              context.phase,
            )
          ? context.plan.cloneVmid
          : null;
    if (
      receipt.tokenIdentity !== context.plan.tokenIdentity ||
      receipt.tokenIdentity !== this.credentials.tokenId ||
      receipt.requestDigest !== context.requestDigest ||
      receipt.workerType !== worker ||
      receipt.sourceVmid !== source ||
      receipt.destinationVmid !== destination ||
      !SHA256.test(receipt.dispatchDigest) ||
      !SHA256.test(receipt.responseDigest) ||
      (receipt.taskId === null) !== (worker === null) ||
      !this.validDispatch(context, receipt.dispatch) ||
      receipt.dispatchDigest !== dispatchDigest(receipt.dispatch)
    )
      return false;
    if (!worker)
      return (
        receipt.generatedUuid === null &&
        receipt.generatedCtime === null &&
        receipt.responseDigest === hash({ acknowledgement: null })
      );
    const task = receipt.taskId ? this.parseUpid(receipt.taskId) : null;
    if (!task || !this.matchesUpid(context, task, worker)) return false;
    if (context.phase !== "CLONE")
      return (
        receipt.generatedUuid === null &&
        receipt.generatedCtime === null &&
        receipt.responseDigest === hash({ upid: receipt.taskId })
      );
    return (
      (receipt.generatedUuid === null &&
        receipt.generatedCtime === null &&
        receipt.responseDigest === hash({ upid: receipt.taskId })) ||
      (typeof receipt.generatedUuid === "string" &&
        typeof receipt.generatedCtime === "string")
    );
  }
  private validDispatch(
    context: Context,
    dispatch: LinuxImportReceipt["dispatch"],
  ): boolean {
    if (
      !dispatch ||
      !isRecord(dispatch) ||
      Object.keys(dispatch).length !== 3 ||
      typeof dispatch.method !== "string" ||
      typeof dispatch.path !== "string" ||
      (dispatch.body !== null &&
        (!isRecord(dispatch.body) ||
          Object.values(dispatch.body).some(
            (x) => typeof x !== "string" && typeof x !== "number",
          )))
    )
      return false;
    const plan = context.plan,
      node = `/api2/json/nodes/${this.part(plan.node)}`;
    const cloneDigest = context.priorReceipts?.CLONE?.configDigest;
    if (
      context.phase === "STAMP" &&
      (typeof cloneDigest !== "string" || !SHA1.test(cloneDigest))
    )
      return false;
    const expected: LinuxImportReceipt["dispatch"] =
      context.phase === "UPLOAD"
        ? {
            method: "POST",
            path: `${node}/storage/${this.part(plan.stageStorage)}/upload`,
            body: {
              content: "import",
              "checksum-algorithm": "sha256",
              checksum: plan.stageSha256,
              filename: `${plan.stageId}.qcow2`,
            },
          }
        : context.phase === "IMPORT"
          ? {
              method: "POST",
              path: `${node}/qemu`,
              body: {
                vmid: plan.templateVmid,
                pool: plan.pool,
                name: plan.templateName,
                bios: "seabios",
                scsihw: "virtio-scsi-pci",
                boot: "order=scsi0",
                serial0: "socket",
                memory: "2048",
                cores: "2",
                cpu: "kvm64",
                tags: tags(
                  plan,
                  plan.templateResourceId,
                  "image_template",
                  plan.templateNonce,
                ).join(";"),
                scsi0: `${plan.targetStorage}:0,import-from=${plan.stageStorage}:import/${plan.stageId}.qcow2`,
              },
            }
          : context.phase === "TEMPLATE"
            ? {
                method: "POST",
                path: `${node}/qemu/${this.part(plan.templateVmid)}/template`,
                body: {},
              }
            : context.phase === "CLONE"
              ? {
                  method: "POST",
                  path: `${node}/qemu/${this.part(plan.templateVmid)}/clone`,
                  body: {
                    newid: plan.cloneVmid,
                    name: plan.cloneName,
                    pool: plan.pool,
                    storage: plan.targetStorage,
                    full: "1",
                  },
                }
              : context.phase === "STAMP"
                ? {
                    method: "PUT",
                    path: `${node}/qemu/${this.part(plan.cloneVmid)}/config`,
                    body: {
                      digest: cloneDigest!,
                      tags: tags(
                        plan,
                        plan.cloneResourceId,
                        "execution",
                        plan.cloneNonce,
                      ).join(";"),
                    },
                  }
                : context.phase === "START"
                  ? {
                      method: "POST",
                      path: `${node}/qemu/${this.part(plan.cloneVmid)}/status/start`,
                      body: {},
                    }
                  : context.phase === "STOP"
                    ? {
                        method: "POST",
                        path: `${node}/qemu/${this.part(plan.cloneVmid)}/status/stop`,
                        body: {},
                      }
                    : {
                        method: "DELETE",
                        path: `${node}/qemu/${this.part(context.phase === "DESTROY_CLONE" ? plan.cloneVmid : plan.templateVmid)}?purge=0&destroy-unreferenced-disks=0`,
                        body: null,
                      };
    return (
      dispatch.method === expected.method &&
      dispatch.path === expected.path &&
      dispatchDigest(dispatch) === dispatchDigest(expected)
    );
  }
  private parseUpid(value: string): Upid | null {
    const m = UPID.exec(value);
    if (
      !m ||
      !m[1] ||
      !m[2] ||
      !m[3] ||
      !m[4] ||
      !m[5] ||
      m[6] === undefined ||
      !m[7]
    )
      return null;
    return {
      node: m[1],
      pid: Number.parseInt(m[2], 16),
      pstart: Number.parseInt(m[3], 16),
      starttime: Number.parseInt(m[4], 16),
      type: m[5],
      id: m[6],
      identity: m[7],
    };
  }
  private matchesUpid(context: Context, task: Upid, worker: string): boolean {
    const id =
      worker === "imgcopy"
        ? ""
        : worker === "qmclone"
          ? context.plan.templateVmid
          : worker === "qmcreate" ||
              worker === "qmtemplate" ||
              (worker === "qmdestroy" && context.phase === "DESTROY_TEMPLATE")
            ? context.plan.templateVmid
            : context.plan.cloneVmid;
    return (
      task.node === context.plan.node &&
      task.type === worker &&
      task.id === id &&
      task.identity === context.plan.tokenIdentity
    );
  }
  private matchesTask(value: unknown, taskId: string, task: Upid): boolean {
    return (
      isRecord(value) &&
      value.upid === taskId &&
      value.node === task.node &&
      value.type === task.type &&
      value.id === task.id &&
      value.pid === task.pid &&
      value.pstart === task.pstart &&
      value.starttime === task.starttime &&
      typeof value.user === "string" &&
      typeof value.tokenid === "string" &&
      `${value.user}!${value.tokenid}` === task.identity
    );
  }
  private contents(value: unknown): Set<string> {
    return typeof value === "string"
      ? new Set(
          value
            .split(",")
            .map((x) => x.trim())
            .filter(Boolean),
        )
      : new Set();
  }
  private vmInventory(value: unknown[], types: string[]): boolean {
    return value.every(
      (item) =>
        isRecord(item) &&
        typeof item.type === "string" &&
        types.includes(item.type) &&
        this.validVmid(item.vmid),
    );
  }
  private nodeQemuInventory(value: unknown[]): boolean {
    return value.every(
      (item) =>
        isRecord(item) &&
        this.validVmid(item.vmid) &&
        (item.type === undefined || item.type === "qemu"),
    );
  }
  private validVmid(value: unknown): boolean {
    return (
      (typeof value === "string" || typeof value === "number") &&
      VMID.test(String(value))
    );
  }
  private volumeInventory(value: unknown[]): boolean {
    return value.every(
      (item) => isRecord(item) && typeof item.volid === "string",
    );
  }
  private assertAuditPermissions(
    permissions: Record<string, unknown>,
    plan: LinuxImportPlan,
  ): void {
    const requirements: Array<[string, string[]]> = [
      [`/pool/${this.part(plan.pool)}`, ["Pool.Audit"]],
      [`/storage/${this.part(plan.stageStorage)}`, ["Datastore.Audit"]],
      [`/storage/${this.part(plan.targetStorage)}`, ["Datastore.Audit"]],
    ];
    for (const [path, grants] of requirements) {
      const granted = permissions[path];
      if (!isRecord(granted) || grants.some((grant) => granted[grant] !== 1))
        throw this.denied(
          "Proxmox Linux import audit permissions are incomplete",
        );
    }
  }
  private assertPermissions(
    permissions: Record<string, unknown>,
    plan: LinuxImportPlan,
    phase: LinuxImportPhaseName,
  ): void {
    const vm = (id: string) => `/vms/${this.part(id)}`;
    const pool = `/pool/${this.part(plan.pool)}`;
    const requirements: Array<[string[], string[]]> =
      phase === "UPLOAD"
        ? [
            [
              [`/storage/${this.part(plan.stageStorage)}`],
              ["Datastore.AllocateTemplate"],
            ],
          ]
        : phase === "IMPORT"
          ? [
              [
                [vm(plan.templateVmid), pool],
                [
                  "VM.Allocate",
                  "VM.Config.CPU",
                  "VM.Config.Memory",
                  "VM.Config.Disk",
                  "VM.Config.Options",
                  "VM.Config.HWType",
                ],
              ],
              [
                [`/storage/${this.part(plan.targetStorage)}`],
                ["Datastore.AllocateSpace"],
              ],
            ]
          : phase === "TEMPLATE"
            ? [[[vm(plan.templateVmid)], ["VM.Allocate"]]]
            : phase === "CLONE"
              ? [
                  [[vm(plan.templateVmid)], ["VM.Clone"]],
                  [[vm(plan.cloneVmid), pool], ["VM.Allocate"]],
                  [
                    [`/storage/${this.part(plan.targetStorage)}`],
                    ["Datastore.AllocateSpace"],
                  ],
                ]
              : phase === "STAMP"
                ? []
                : phase === "START" || phase === "STOP"
                  ? [[[vm(plan.cloneVmid), pool], ["VM.PowerMgmt"]]]
                  : [
                      [
                        [
                          vm(
                            phase === "DESTROY_CLONE"
                              ? plan.cloneVmid
                              : plan.templateVmid,
                          ),
                          pool,
                        ],
                        ["VM.Allocate"],
                      ],
                    ];
    for (const [paths, grants] of requirements) {
      if (
        !paths.some((path) => {
          const granted = permissions[path];
          return (
            isRecord(granted) && grants.every((grant) => granted[grant] === 1)
          );
        })
      )
        throw this.denied("Proxmox Linux import permissions are incomplete");
    }
  }
  private async mutate(
    mutation: Mutation,
    phase: LinuxImportPhaseName,
  ): Promise<unknown> {
    let response: Response;
    try {
      response = await this.raw(
        mutation.path,
        mutation.method,
        mutation.body,
        phase === "UPLOAD" ? 20 * 60_000 : 5 * 60_000,
        mutation.headers,
      );
    } catch (error) {
      await mutation.close?.().catch(() => undefined);
      throw error;
    }
    if (!response.ok) {
      await mutation.close?.().catch(() => undefined);
      throw this.denied("Proxmox mutation was rejected");
    }
    const json = await this.json(response);
    if (!isRecord(json) || !Object.hasOwn(json, "data"))
      throw this.denied("Proxmox mutation returned an invalid response");
    return json.data;
  }
  private async data(path: string): Promise<unknown> {
    const response = await this.raw(path, "GET", undefined, 5_000);
    if (!response.ok) throw this.denied("Proxmox observation failed");
    const json = await this.json(response);
    if (!isRecord(json) || !Object.hasOwn(json, "data"))
      throw this.denied("Proxmox observation returned an invalid response");
    return json.data;
  }
  private async missing(
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
    const length = Number(response.headers.get("content-length") ?? "0");
    if (!Number.isFinite(length) || length > 64 * 1024 || !response.body)
      throw this.denied("Proxmox response is too large");
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    const timer = setTimeout(() => void reader.cancel(), 5_000);
    try {
      for (;;) {
        const next = await reader.read();
        if (next.done) break;
        total += next.value.byteLength;
        if (total > 64 * 1024)
          throw this.denied("Proxmox response is too large");
        chunks.push(next.value);
      }
    } catch (error) {
      if (error instanceof KilnError) throw error;
      throw this.denied("Proxmox response cannot be read");
    } finally {
      clearTimeout(timer);
      reader.releaseLock();
    }
    const text = Buffer.concat(chunks).toString("utf8");
    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw this.denied("Proxmox response is not JSON");
    }
  }
  private async raw(
    path: string,
    method: string,
    body: BodyInit | undefined,
    timeoutMs: number,
    headers: Record<string, string> = {},
  ): Promise<Response> {
    const controller = new AbortController(),
      timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      return await this.fetcher(new URL(path, this.credentials.url), {
        method,
        headers: {
          Authorization: `PVEAPIToken=${this.credentials.tokenId}=${this.credentials.tokenSecret}`,
          ...headers,
        },
        body,
        redirect: "error",
        signal: controller.signal,
        duplex: "half",
      } as RequestInit);
    } catch {
      throw this.denied("Proxmox request failed");
    } finally {
      clearTimeout(timer);
    }
  }
  private part(value: string): string {
    return encodeURIComponent(value);
  }
  private denied(message: string): KilnError {
    return new KilnError("SAFETY_DENIED", 403, message);
  }
}

async function checksum(file: FileHandle, size: number): Promise<string> {
  const digest = createHash("sha256"),
    chunk = Buffer.allocUnsafe(64 * 1024);
  let offset = 0;
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
    digest.update(chunk.subarray(0, bytesRead));
    offset += bytesRead;
  }
  return digest.digest("hex");
}
function headers(
  boundary: string,
  fields: {
    content: string;
    "checksum-algorithm": string;
    checksum: string;
    filename: string;
  },
): Buffer[] {
  const field = (name: string, value: string) =>
    Buffer.from(
      `--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`,
    );
  return [
    field("content", fields.content),
    field("checksum-algorithm", fields["checksum-algorithm"]),
    field("checksum", fields.checksum),
    Buffer.from(
      `--${boundary}\r\nContent-Disposition: form-data; name="filename"; filename="${fields.filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`,
    ),
  ];
}
function multipartSize(
  boundary: string,
  fields: {
    content: string;
    "checksum-algorithm": string;
    checksum: string;
    filename: string;
  },
  artifactSize: number,
): number {
  const size =
    headers(boundary, fields).reduce((n, part) => n + part.length, 0) +
    artifactSize +
    Buffer.byteLength(`\r\n--${boundary}--\r\n`);
  if (!Number.isSafeInteger(size) || size > MAX_STAGE + 16 * 1024)
    throw new KilnError(
      "SAFETY_DENIED",
      403,
      "Linux image multipart request is invalid",
    );
  return size;
}
async function* multipart(
  staged: StagedFile,
  boundary: string,
  fields: {
    content: string;
    "checksum-algorithm": string;
    checksum: string;
    filename: string;
  },
): AsyncGenerator<Buffer> {
  try {
    for (const part of headers(boundary, fields)) yield part;
    const digest = createHash("sha256"),
      chunk = Buffer.allocUnsafe(64 * 1024);
    let offset = 0;
    while (offset < staged.size) {
      const { bytesRead } = await staged.file.read(
        chunk,
        0,
        Math.min(chunk.length, staged.size - offset),
        offset,
      );
      if (!bytesRead)
        throw new KilnError(
          "SAFETY_DENIED",
          403,
          "Linux image staging file changed during upload",
        );
      const copy = Buffer.from(chunk.subarray(0, bytesRead));
      digest.update(copy);
      yield copy;
      offset += bytesRead;
    }
    const after = await staged.file.stat({ bigint: true });
    if (
      after.dev !== staged.first.dev ||
      after.ino !== staged.first.ino ||
      after.size !== staged.first.size ||
      after.mtimeNs !== staged.first.mtimeNs ||
      after.ctimeNs !== staged.first.ctimeNs ||
      digest.digest("hex") !== staged.sha256
    )
      throw new KilnError(
        "SAFETY_DENIED",
        403,
        "Linux image staging file changed during upload",
      );
    yield Buffer.from(`\r\n--${boundary}--\r\n`);
  } finally {
    await staged.file.close();
  }
}

export { qualifyLinuxImportQemuGraph } from "./linux-qualified-config.js";
