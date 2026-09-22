import {
  KilnError,
  type ComputeProvider,
  type OwnershipObservation,
  type ProviderInventory,
  type ProviderMetrics,
  type Resource,
  type GatewayEvidence,
  type GatewayMetadata,
  type ProviderTaskHandle,
  type ProviderTaskObservation,
  validateOwnership,
} from "@kiln/core";
export { ProxmoxQualificationProvider } from "./qualification.js";
export { ProxmoxLinuxImportProvider, qualifyLinuxImportQemuGraph } from "./linux-import.js";

const MAX_TASK_RESPONSE_BYTES = 64 * 1024;
// Pinned direct QEMU API workers. Clone, restore, LXC and HA paths need separate provenance and qualification.
const DIRECT_QEMU_WORKERS = {
  create: "qmcreate",
  start: "qmstart",
  stop: "qmstop",
  destroy: "qmdestroy",
} as const;
const UPID_PATTERN =
  /^UPID:([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?):([0-9A-Fa-f]{8}):([0-9A-Fa-f]{8,9}):([0-9A-Fa-f]{8}):([^:\s/]+):([^:\s/]*):([^:\s/]+):$/;
const VMID_PATTERN = /^[1-9][0-9]{2,8}$/;

interface ProxmoxTask {
  node: string;
  pid: number;
  pstart: number;
  starttime: number;
  type: string;
  id: string;
  user: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export interface ProxmoxCredentials {
  url: URL;
  tokenId: string;
  tokenSecret: string;
}
export function parseProxmoxToken(
  url: string,
  token: string,
): ProxmoxCredentials {
  const match = /^PVEAPIToken=([^@!=\s]+@[^!\s]+![^=\s]+)=([^\s=]+)$/.exec(
    token,
  );
  if (!match || !match[1] || !match[2])
    throw new KilnError(
      "INVALID_PROVIDER_CONFIG",
      400,
      "Invalid Proxmox API token format",
    );
  const parsed = new URL(url);
  if (parsed.protocol !== "https:")
    throw new KilnError(
      "INVALID_PROVIDER_CONFIG",
      400,
      "Proxmox API URL must use HTTPS",
    );
  return { url: parsed, tokenId: match[1], tokenSecret: match[2] };
}
export class ProxmoxProvider implements ComputeProvider {
  readonly id = "proxmox";
  readonly mode = "proxmox-read-only" as const;
  constructor(
    private readonly credentials: ProxmoxCredentials,
    private readonly fetcher: typeof fetch = fetch,
  ) {
    if (credentials.url.protocol !== "https:")
      throw new KilnError(
        "INVALID_PROVIDER_CONFIG",
        400,
        "Proxmox API URL must use HTTPS",
      );
  }
  async discover(): Promise<ProviderInventory> {
    const data = await this.request("/api2/json/nodes");
    const source = Array.isArray(data)
      ? (data as Record<string, unknown>[])
      : [];
    const nodes = source.map((node) => ({
      id: String(node.node),
      online: node.status === "online",
      cpuFree: Math.max(
        0,
        Number(node.maxcpu ?? 0) * (1 - Number(node.cpu ?? 1)),
      ),
      memoryFree: Math.max(0, Number(node.maxmem ?? 0) - Number(node.mem ?? 0)),
      storage: [],
      networks: [],
      images: [],
    }));
    const storage = (
      await Promise.all(
        source.map(async (node) => {
          const nodeId = String(node.node);
          const entries = await this.request(
            `/api2/json/nodes/${encodeURIComponent(nodeId)}/storage`,
          );
          return Array.isArray(entries)
            ? entries.map((entry) => ({
                id: `${nodeId}/${String((entry as Record<string, unknown>).storage)}`,
                shared: Boolean((entry as Record<string, unknown>).shared),
                supportsSnapshots: false,
                supportsClones: false,
                nodes: [nodeId],
              }))
            : [];
        }),
      )
    ).flat();
    const cluster = await this.request("/api2/json/cluster/resources?type=vm");
    const records = Array.isArray(cluster)
      ? (cluster as Record<string, unknown>[])
      : [];
    const inspected = await Promise.all(
      records
        .filter((record) => record.type === "qemu" || record.type === "lxc")
        .map((record) => this.inspectRecord(record)),
    );
    return {
      nodes,
      storage,
      resources: inspected.flatMap((result) => (result ? [result] : [])),
    };
  }
  async inspect(
    providerResourceId: string,
  ): Promise<OwnershipObservation | null> {
    const data = await this.request(`/api2/json/cluster/resources?type=vm`);
    const resource = Array.isArray(data)
      ? data.find(
          (item: Record<string, unknown>) =>
            String(item.vmid) === providerResourceId &&
            (item.type === "qemu" || item.type === "lxc"),
        )
      : undefined;
    if (!resource)
      throw new KilnError(
        "PROVIDER_FAILURE",
        502,
        "Proxmox resource cannot be confirmed visible",
      );
    return this.inspectRecord(resource);
  }
  async metrics(): Promise<ProviderMetrics[]> {
    return (await this.discover()).nodes.map((node) => ({
      nodeId: node.id,
      cpuFree: node.cpuFree,
      memoryFree: node.memoryFree,
      observedAt: new Date().toISOString(),
    }));
  }
  async create(_resource: Resource): Promise<OwnershipObservation> {
    throw this.unsupported();
  }
  async start(_resource: Resource): Promise<void> {
    throw this.unsupported();
  }
  async stop(_resource: Resource): Promise<void> {
    throw this.unsupported();
  }
  async destroy(_resource: Resource): Promise<void> {
    throw this.unsupported();
  }
  async inspectOperation(
    handle: ProviderTaskHandle,
  ): Promise<ProviderTaskObservation> {
    const task = this.validateTaskHandle(handle);
    if (!task) return { status: "UNKNOWN" };
    const path = `/api2/json/nodes/${encodeURIComponent(task.node)}/tasks/${encodeURIComponent(handle.taskId)}/status`;
    const result = await this.readTaskStatus(path);
    if (result === "MISSING") return { status: "MISSING" };
    if (!result) return { status: "UNKNOWN" };
    if (
      ![
        "upid",
        "node",
        "type",
        "id",
        "pid",
        "pstart",
        "starttime",
        "user",
      ].every((field) => Object.hasOwn(result, field))
    )
      return { status: "UNKNOWN" };
    if (!this.matchesTaskResponse(result, handle.taskId, task))
      return { status: "MISMATCH" };
    if (result.status === "running") return { status: "RUNNING" };
    if (result.status !== "stopped") return { status: "UNKNOWN" };
    if (result.exitstatus === "OK") return { status: "SUCCEEDED" };
    if (
      typeof result.exitstatus !== "string" ||
      result.exitstatus.length === 0 ||
      result.exitstatus === "unexpected status"
    )
      return { status: "UNKNOWN" };
    return { status: "FAILED" };
  }
  async observeGateway(
    resource: Resource,
    _metadata: GatewayMetadata,
  ): Promise<GatewayEvidence> {
    let ownership: GatewayEvidence["ownership"] = "UNKNOWN";
    let config: GatewayEvidence["config"] = "UNKNOWN";
    try {
      const observed = await this.inspect(resource.providerResourceId);
      if (observed) {
        try {
          validateOwnership(resource, resource.installationId, observed);
          ownership = "VALID";
        } catch {
          ownership = "INVALID";
        }
        // The Phase 1 API observer has no authenticated gateway heartbeat or config fingerprint.
        config = "UNKNOWN";
      }
    } catch {
      // A visibility error is not proof that a gateway was deleted.
    }
    return {
      power: "UNKNOWN",
      ownership,
      config,
      heartbeat: "UNKNOWN",
      policy: "UNKNOWN",
      reservation: "UNKNOWN",
      services: "UNKNOWN",
      canary: "UNKNOWN",
      generation: null,
      configFingerprint: null,
      observedAt: new Date().toISOString(),
    };
  }
  private unsupported(): KilnError {
    return new KilnError(
      "UNSUPPORTED",
      501,
      "Live Proxmox mutations are disabled in Phase 1",
    );
  }
  private validateTaskHandle(handle: ProviderTaskHandle): ProxmoxTask | null {
    if (!isRecord(handle)) return null;
    if (
      handle.providerId !== this.id ||
      handle.providerKind !== "qemu" ||
      typeof handle.providerResourceId !== "string" ||
      !VMID_PATTERN.test(handle.providerResourceId) ||
      typeof handle.node !== "string" ||
      typeof handle.workerType !== "string" ||
      !["create", "start", "stop", "destroy"].includes(
        handle.action as string,
      ) ||
      typeof handle.snapshotDigest !== "string" ||
      !/^[a-f0-9]{64}$/.test(handle.snapshotDigest) ||
      typeof handle.taskId !== "string" ||
      handle.taskId.length > 512
    )
      return null;
    if (handle.workerType !== DIRECT_QEMU_WORKERS[handle.action]) return null;
    const match = UPID_PATTERN.exec(handle.taskId);
    if (!match || match[0] !== handle.taskId) return null;
    const [, node, pid, pstart, starttime, type, id, user] = match;
    if (
      !node ||
      !pid ||
      !pstart ||
      !starttime ||
      !type ||
      id === undefined ||
      !user
    )
      return null;
    const task = {
      node,
      pid: Number.parseInt(pid, 16),
      pstart: Number.parseInt(pstart, 16),
      starttime: Number.parseInt(starttime, 16),
      type,
      id,
      user,
    };
    if (
      handle.node !== task.node ||
      // qmclone UPIDs bind their source VM ID. A target resource needs a separately recorded source binding.
      handle.providerResourceId !== task.id ||
      handle.workerType !== task.type
    )
      return null;
    return task;
  }
  private matchesTaskResponse(
    response: Record<string, unknown>,
    upid: string,
    task: ProxmoxTask,
  ): boolean {
    if (
      response.upid !== upid ||
      response.node !== task.node ||
      response.type !== task.type ||
      response.id !== task.id ||
      response.pid !== task.pid ||
      response.pstart !== task.pstart ||
      response.starttime !== task.starttime ||
      typeof response.user !== "string"
    )
      return false;
    if (
      Object.prototype.hasOwnProperty.call(response, "tokenid") &&
      typeof response.tokenid !== "string"
    )
      return false;
    const tokenId = response.tokenid;
    const submittingIdentity =
      typeof tokenId === "string"
        ? `${response.user}!${tokenId}`
        : response.user;
    return submittingIdentity === task.user;
  }
  private async readTaskStatus(
    path: string,
  ): Promise<Record<string, unknown> | "MISSING" | null> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    try {
      const response = await this.fetcher(new URL(path, this.credentials.url), {
        method: "GET",
        headers: {
          Authorization: `PVEAPIToken=${this.credentials.tokenId}=${this.credentials.tokenSecret}`,
        },
        redirect: "error",
        signal: controller.signal,
      });
      const body = await this.readBoundedJson(response);
      if (!response.ok)
        return this.isExplicitMissingTask(response.status, body)
          ? "MISSING"
          : null;
      if (!isRecord(body) || !isRecord(body.data)) return null;
      return body.data;
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }
  private isExplicitMissingTask(status: number, body: unknown): boolean {
    return (
      status === 400 &&
      isRecord(body) &&
      isRecord(body.errors) &&
      body.errors.upid === "no such task"
    );
  }
  private async readBoundedJson(response: Response): Promise<unknown> {
    const contentLength = response.headers.get("content-length");
    if (
      contentLength !== null &&
      (!/^\d+$/.test(contentLength) ||
        Number(contentLength) > MAX_TASK_RESPONSE_BYTES)
    ) {
      await response.body?.cancel().catch(() => undefined);
      throw new Error("Proxmox task response exceeds the size limit");
    }
    const reader = response.body?.getReader();
    if (!reader) throw new Error("Proxmox task response has no body");
    const chunks: Uint8Array[] = [];
    let length = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        length += value.byteLength;
        if (length > MAX_TASK_RESPONSE_BYTES) {
          void reader.cancel().catch(() => undefined);
          throw new Error("Proxmox task response exceeds the size limit");
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    const body = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
      body.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return JSON.parse(new TextDecoder().decode(body)) as unknown;
  }
  private async inspectRecord(
    record: Record<string, unknown>,
  ): Promise<OwnershipObservation | null> {
    const node = typeof record.node === "string" ? record.node : null;
    const vmid =
      typeof record.vmid === "number" || typeof record.vmid === "string"
        ? String(record.vmid)
        : null;
    const type =
      record.type === "qemu" ? "qemu" : record.type === "lxc" ? "lxc" : null;
    if (!node || !vmid || !type) return null;
    const config = (await this.request(
      `/api2/json/nodes/${encodeURIComponent(node)}/${type}/${encodeURIComponent(vmid)}/config`,
    )) as Record<string, unknown>;
    const tags: string[] =
      typeof config.tags === "string" ? config.tags.split(";") : [];
    const taggedType = tags
      .find(
        (tag) =>
          tag.startsWith("kiln-resource-") &&
          !tag.startsWith("kiln-resource-id-"),
      )
      ?.slice("kiln-resource-".length);
    const kind =
      taggedType === "development" ||
      taggedType === "execution" ||
      taggedType === "browser" ||
      taggedType === "gateway"
        ? taggedType
        : null;
    return {
      providerId: this.id,
      providerResourceId: vmid,
      providerKind: type,
      kind,
      pool: typeof record.pool === "string" ? record.pool : null,
      node,
      tags,
    };
  }
  private async request(path: string): Promise<unknown> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    try {
      const response = await this.fetcher(new URL(path, this.credentials.url), {
        headers: {
          Authorization: `PVEAPIToken=${this.credentials.tokenId}=${this.credentials.tokenSecret}`,
        },
        redirect: "error",
        signal: controller.signal,
      });
      if (!response.ok)
        throw new KilnError(
          "PROVIDER_FAILURE",
          502,
          "Proxmox inspection failed",
        );
      const body = (await response.json()) as { data?: unknown };
      if (!body || typeof body !== "object" || !("data" in body))
        throw new KilnError(
          "PROVIDER_FAILURE",
          502,
          "Proxmox inspection returned an invalid response",
        );
      return body.data;
    } catch (error) {
      if (error instanceof KilnError) throw error;
      throw new KilnError("PROVIDER_FAILURE", 502, "Proxmox inspection failed");
    } finally {
      clearTimeout(timer);
    }
  }
}
