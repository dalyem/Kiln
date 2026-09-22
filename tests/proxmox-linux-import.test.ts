import { createHash } from "node:crypto";
import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type {
  LinuxImportPhaseName,
  LinuxImportPlan,
  LinuxImportReceipt,
} from "@kiln/core";
import { ProxmoxLinuxImportProvider } from "../packages/proxmox/src/linux-import.js";
import { qualifyLinuxImportQemuGraph } from "../packages/proxmox/src/linux-qualified-config.js";

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
const storageDigest = "a".repeat(40);
const token = "qual@pam!linux";
const stageId = "lstg_0123456789abcdef0123456789abcdef";

function envelope(data: unknown, status = 200, length?: number): Response {
  return new Response(JSON.stringify({ data }), {
    status,
    headers: {
      "content-type": "application/json",
      ...(length === undefined ? {} : { "content-length": String(length) }),
    },
  });
}
function missing(vmid: string): Response {
  return new Response(
    JSON.stringify({
      data: null,
      message: `Configuration file 'nodes/pve1/qemu-server/${vmid}.conf' does not exist\n`,
    }),
    { status: 500, headers: { "content-type": "application/json" } },
  );
}
function plan(path: string, bytes: Buffer): LinuxImportPlan {
  const bare = {
    schemaVersion: 1 as const,
    installationId: "inst1",
    node: "pve1",
    pool: "kiln",
    stageStorage: "local",
    targetStorage: "local-lvm",
    pveVersion: "9.2.2" as const,
    tokenIdentity: token,
    storageConfigDigest: storageDigest,
    stageId,
    stagePath: path,
    stageSha256: createHash("sha256").update(bytes).digest("hex"),
    templateVmid: "9200",
    cloneVmid: "9201",
    templateName: "kiln-image-9200",
    cloneName: "Copy-of-kiln-image-9200",
    sourcePoolRunId: "qualrun",
    sourcePoolAllocationId: "allocpool",
    sourcePoolNonce: "nonce",
    sourcePoolComment: "kiln-qualification-run1;nonce=nonce",
    templateResourceId: "template1",
    cloneResourceId: "clone1",
    templateNonce: "template-nonce",
    cloneNonce: "clone-nonce",
    image: {
      id: "image1",
      manifest: {
        schemaVersion: 1 as const,
        name: "kiln-dev",
        version: "1",
        arch: "amd64" as const,
        artifactSha256: createHash("sha256").update(bytes).digest("hex"),
        artifactSize: bytes.length,
        sourceBuild: `sha256:${"b".repeat(64)}`,
        capabilities: [],
        keyId: "operator",
      },
      manifestDigest: "c".repeat(64),
      signerFingerprint: "fingerprint",
      policyDigest: "d".repeat(64),
    },
    buildMetadataSha256: "e".repeat(64),
  };
  return {
    ...bare,
    canonicalDigest: createHash("sha256")
      .update(JSON.stringify(bare))
      .digest("hex"),
  };
}
function context(
  plan: LinuxImportPlan,
  phase: LinuxImportPhaseName,
  priorReceipts: Partial<Record<LinuxImportPhaseName, LinuxImportReceipt>>,
) {
  return {
    plan,
    phase,
    priorReceipts,
    requestDigest: createHash("sha256")
      .update(`${plan.canonicalDigest}:${phase}`)
      .digest("hex"),
  };
}
function reorder(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(reorder);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => right.localeCompare(left))
        .map(([key, entry]) => [key, reorder(entry)]),
    );
  return value;
}
function durable<T>(value: T): T {
  return reorder(JSON.parse(JSON.stringify(value))) as T;
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
                Object.entries(dispatch.body).sort(([left], [right]) =>
                  left.localeCompare(right),
                ),
              ),
      }),
    )
    .digest("hex");
}
function tags(
  plan: LinuxImportPlan,
  kind: "image_template" | "execution",
  id: string,
  nonce: string,
): string {
  return [
    "kiln",
    "kiln-managed",
    `kiln-installation-${plan.installationId}`,
    `kiln-resource-${kind}`,
    `kiln-resource-id-${id}`,
    `kiln-import-nonce-${nonce}`,
  ].join(";");
}

function fixture(
  plan: LinuxImportPlan,
  overrides: { existingTemplate?: boolean } = {},
) {
  const state = {
    stage: false,
    template: (overrides.existingTemplate ? "vm" : "absent") as
      | "absent"
      | "vm"
      | "template",
    clone: "absent" as "absent" | "vm",
    cloneTags: tags(
      plan,
      "image_template",
      plan.templateResourceId,
      plan.templateNonce,
    ),
    cloneDigest: "d".repeat(40),
    power: "stopped" as "stopped" | "running",
    overlay: "" as string,
    uploaded: "",
  };
  const calls: Array<{ method: string; path: string }> = [];
  const tasks = new Map<string, { worker: string; id: string; pid: number }>();
  let nextPid = 1;
  const member = (vmid: string) => ({
    type: "qemu",
    vmid: Number(vmid),
    node: plan.node,
  });
  const config = (vmid: string): Record<string, unknown> | null => {
    const template = vmid === plan.templateVmid,
      mode = template ? state.template : state.clone;
    if (mode === "absent") return null;
    const volume = template
      ? `${mode === "template" ? "base" : "vm"}-${vmid}-disk-0`
      : `vm-${vmid}-disk-0`;
    const value: Record<string, unknown> = {
      bios: "seabios",
      boot: "order=scsi0",
      cores: 2,
      cpu: "kvm64",
      memory: "2048",
      scsihw: "virtio-scsi-pci",
      serial0: "socket",
      scsi0: `${plan.targetStorage}:${volume},size=8G`,
      tags: template
        ? tags(
            plan,
            "image_template",
            plan.templateResourceId,
            plan.templateNonce,
          )
        : state.cloneTags,
      digest: template ? "c".repeat(40) : state.cloneDigest,
      meta: "creation-qemu=11.0.0,ctime=1700000000",
      smbios1: `uuid=${template ? "11111111-1111-1111-1111-111111111111" : "22222222-2222-2222-2222-222222222222"}`,
      vmgenid: template
        ? "33333333-3333-3333-3333-333333333333"
        : "44444444-4444-4444-4444-444444444444",
      name: template ? plan.templateName : plan.cloneName,
      ...(template && mode === "template" ? { template: 1 } : {}),
    };
    if (!template && state.overlay === "wrongtags") value.tags = "kiln;foreign";
    if (!template && state.overlay === "extra disk")
      value.scsi1 = `${plan.targetStorage}:vm-${vmid}-disk-1,size=8G`;
    if (!template && state.overlay === "seed")
      value.ide2 = `${plan.targetStorage}:cloudinit`;
    return value;
  };
  const fetcher: typeof fetch = async (input, init) => {
    const url = new URL(String(input)),
      method = init?.method ?? "GET",
      path = `${url.pathname}${url.search}`;
    calls.push({ method, path });
    const task = (worker: string, id: string) => {
      const pid = nextPid++;
      const upid = `UPID:pve1:${pid.toString(16).padStart(8, "0")}:00000002:00000003:${worker}:${id}:${token}:`;
      tasks.set(upid, { worker, id, pid });
      return envelope(upid);
    };
    if (method !== "GET") {
      if (method === "POST" && path.endsWith("/upload")) {
        state.uploaded = Buffer.from(
          await new Response(init?.body as BodyInit).arrayBuffer(),
        ).toString("utf8");
        state.stage = true;
        return task("imgcopy", "");
      }
      if (method === "POST" && path === "/api2/json/nodes/pve1/qemu") {
        state.template = "vm";
        return task("qmcreate", plan.templateVmid);
      }
      if (method === "POST" && path.endsWith("/template")) {
        state.template = "template";
        return task("qmtemplate", plan.templateVmid);
      }
      if (method === "POST" && path.endsWith("/clone")) {
        state.clone = "vm";
        state.cloneTags = tags(
          plan,
          "image_template",
          plan.templateResourceId,
          plan.templateNonce,
        );
        state.cloneDigest = "d".repeat(40);
        return task("qmclone", plan.templateVmid);
      }
      if (method === "PUT" && path.endsWith("/config")) {
        state.cloneTags = tags(
          plan,
          "execution",
          plan.cloneResourceId,
          plan.cloneNonce,
        );
        state.cloneDigest = "e".repeat(40);
        return envelope(null);
      }
      if (method === "POST" && path.endsWith("/status/start")) {
        state.power = "running";
        return task("qmstart", plan.cloneVmid);
      }
      if (method === "POST" && path.endsWith("/status/stop")) {
        state.power = "stopped";
        return task("qmstop", plan.cloneVmid);
      }
      if (
        method === "DELETE" &&
        path.startsWith(`/api2/json/nodes/pve1/qemu/${plan.cloneVmid}`)
      ) {
        state.clone = "absent";
        return task("qmdestroy", plan.cloneVmid);
      }
      if (
        method === "DELETE" &&
        path.startsWith(`/api2/json/nodes/pve1/qemu/${plan.templateVmid}`)
      ) {
        state.template = "absent";
        return task("qmdestroy", plan.templateVmid);
      }
      return envelope(null, 500);
    }
    if (path === "/api2/json/version")
      return envelope(
        { version: "9.2.2" },
        200,
        state.overlay === "oversized response" ? 65_537 : undefined,
      );
    if (path === "/api2/json/access/permissions")
      return envelope({
        "/": {
          "Sys.Audit": 1,
          "Pool.Audit": 1,
          "Datastore.Audit": 1,
          "VM.Audit": 1,
        },
        "/storage/local": {
          "Datastore.Audit": 1,
          "Datastore.AllocateTemplate":
            state.overlay === "missing permission" ? 0 : 1,
        },
        "/storage/local-lvm": {
          "Datastore.Audit": 1,
          "Datastore.AllocateSpace": 1,
        },
        "/pool/kiln": { "Pool.Audit": 1, "VM.Allocate": 1 },
        "/vms/9200": {
          "VM.Allocate": 1,
          "VM.Config.CPU": 1,
          "VM.Config.Memory": 1,
          "VM.Config.Disk": 1,
          "VM.Config.Options": 1,
          "VM.Config.HWType": 1,
          "VM.Clone": 1,
        },
        "/vms/9201": {
          "VM.Allocate": 1,
          "VM.Config.Options": 1,
          "VM.PowerMgmt": 1,
        },
      });
    if (path === "/api2/json/storage")
      return envelope([
        {
          storage: plan.stageStorage,
          type: "dir",
          path: "/var/lib/vz",
          content: "import",
          digest: storageDigest,
        },
        {
          storage: plan.targetStorage,
          type: "lvmthin",
          vgname: "pve",
          thinpool: "data",
          content: "images",
          digest: storageDigest,
        },
      ]);
    if (path === "/api2/json/nodes/pve1/storage")
      return envelope([
        {
          storage: plan.stageStorage,
          type: "dir",
          active: 1,
          enabled: 1,
          shared: 0,
        },
        {
          storage: plan.targetStorage,
          type: "lvmthin",
          active: 1,
          enabled: 1,
          shared: 0,
        },
      ]);
    const entries = [
      state.template !== "absent" ? member(plan.templateVmid) : null,
      state.clone !== "absent" ? member(plan.cloneVmid) : null,
    ].filter((entry) => entry !== null);
    const residents = [100, 101, 102].map((vmid) => member(String(vmid)));
    const clusterRows =
      state.overlay === "cluster inventory omits type"
        ? [...residents, ...entries].map(({ type: _type, ...rest }) => rest)
        : [...residents, ...entries];
    const nodeRows: Array<Record<string, unknown>> = [
      { vmid: 100, node: plan.node },
      { type: "qemu", vmid: 101, node: plan.node },
      { vmid: 102, node: plan.node },
      ...entries.map(({ vmid, node }) => ({ vmid, node })),
    ];
    if (path === "/api2/json/cluster/resources?type=vm")
      return envelope(
        state.overlay === "malformed cluster inventory"
          ? [...clusterRows, {}]
          : clusterRows,
      );
    if (path === "/api2/json/nodes/pve1/qemu") {
      const rows = [...nodeRows];
      if (state.overlay === "malformed node inventory") rows.push({});
      if (state.overlay === "node inventory non-qemu type")
        rows.push({ type: "lxc", vmid: 103, node: plan.node });
      if (state.overlay === "node inventory invalid vmid")
        rows.push({ vmid: "abc", node: plan.node });
      if (state.overlay === "node inventory null type")
        rows.push({ type: null, vmid: 103, node: plan.node });
      return envelope(rows);
    }
    if (path === "/api2/json/pools/kiln")
      return envelope({
        poolid: plan.pool,
        comment: plan.sourcePoolComment,
        members:
          state.overlay === "external pool member"
            ? [...entries, member("9999")]
            : entries,
      });
    if (path === "/api2/json/nodes/pve1/storage/local/content")
      return envelope([
        ...(state.stage
          ? [
              {
                volid: `local:import/${stageId}.qcow2`,
                size: plan.image.manifest.artifactSize,
              },
            ]
          : []),
        ...(state.overlay === "malformed stage inventory" ? [{}] : []),
      ]);
    if (path === "/api2/json/nodes/pve1/storage/local-lvm/content")
      return envelope(
        [
          state.template === "vm"
            ? { volid: `local-lvm:vm-${plan.templateVmid}-disk-0` }
            : null,
          state.template === "template"
            ? { volid: `local-lvm:base-${plan.templateVmid}-disk-0` }
            : null,
          state.clone === "vm"
            ? { volid: `local-lvm:vm-${plan.cloneVmid}-disk-0` }
            : null,
          state.clone === "vm" && state.overlay === "extra disk"
            ? { volid: `local-lvm:vm-${plan.cloneVmid}-disk-1` }
            : null,
          ...(state.overlay === "malformed target inventory" ? [{}] : []),
        ].filter(Boolean),
      );
    const taskMatch = /^\/api2\/json\/nodes\/pve1\/tasks\/(.+)\/status$/.exec(
      url.pathname,
    );
    if (taskMatch) {
      const upid = decodeURIComponent(taskMatch[1]!);
      const found = tasks.get(upid);
      return found
        ? envelope({
            upid:
              state.overlay === "wrong UPID"
                ? upid.replace("00000002", "00000004")
                : upid,
            node: "pve1",
            type: found.worker,
            id: found.id,
            pid: found.pid,
            pstart: 2,
            starttime: 3,
            user: "qual@pam",
            tokenid: "linux",
            status: "stopped",
            exitstatus: "OK",
          })
        : envelope(null, 500);
    }
    const vmMatch = /^\/api2\/json\/nodes\/pve1\/qemu\/(9200|9201)\/(.+)$/.exec(
      url.pathname,
    );
    if (vmMatch) {
      const vmid = vmMatch[1]!,
        endpoint = vmMatch[2]!,
        current = config(vmid);
      if (!current && (endpoint === "config" || endpoint === "status/current"))
        return state.overlay === "malformed absence"
          ? envelope(null, 500)
          : missing(vmid);
      if (endpoint === "config") return envelope(current);
      if (endpoint === "pending")
        return envelope(
          current
            ? Object.entries(current).map(([key, entry]) => ({
                key,
                value:
                  state.overlay === "pending" && key === "scsi0"
                    ? "foreign"
                    : entry,
              }))
            : [],
        );
      if (endpoint === "snapshot")
        return envelope([
          {
            name: "current",
            description: "You are here!",
            digest: "f".repeat(40),
            running: 0,
          },
        ]);
      if (endpoint === "firewall/options")
        return envelope({ digest: "f".repeat(40) });
      if (
        ["firewall/rules", "firewall/aliases", "firewall/ipset"].includes(
          endpoint,
        )
      )
        return envelope([]);
      if (endpoint === "status/current")
        return envelope({
          status: vmid === plan.cloneVmid ? state.power : "stopped",
        });
    }
    if (path === "/api2/json/cluster/ha/resources")
      return envelope(
        state.overlay === "HA" ? [{ sid: `vm:${plan.cloneVmid}` }] : [],
      );
    return envelope(null, 500);
  };
  return { calls, fetcher, state, uploaded: () => state.uploaded };
}
function provider(fetcher: typeof fetch) {
  return new ProxmoxLinuxImportProvider(
    {
      url: new URL("https://pve1.example:8006"),
      tokenId: token,
      tokenSecret: "secret",
    },
    fetcher,
  );
}
async function completeBefore(
  mock: ReturnType<typeof fixture>,
  plan: LinuxImportPlan,
  phase: LinuxImportPhaseName,
) {
  const prior: Partial<Record<LinuxImportPhaseName, LinuxImportReceipt>> = {};
  for (const name of phases.slice(0, phases.indexOf(phase))) {
    const current = context(plan, name, prior);
    const receipt = await provider(mock.fetcher).executeLinuxImportPhase(
      current,
    );
    const observation = await provider(mock.fetcher).inspectLinuxImportPhase({
      ...current,
      receipt,
    });
    if (observation.status !== "COMPLETED")
      throw new Error(`fixture ${name} did not complete`);
    prior[name] = durable({ ...receipt, ...observation.receiptPatch });
  }
  return prior;
}
async function withImage(
  test: (
    plan: LinuxImportPlan,
    mock: ReturnType<typeof fixture>,
  ) => Promise<void>,
  options: { existingTemplate?: boolean } = {},
) {
  const directory = await mkdtemp(join(tmpdir(), "kiln-linux-provider-"));
  const file = join(directory, "image.qcow2");
  const bytes = Buffer.from("qcow2!!");
  await writeFile(file, bytes, { mode: 0o600 });
  const value = plan(file, bytes),
    mock = fixture(value, options);
  try {
    await test(value, mock);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

describe("Proxmox Linux image import provider", () => {
  it("runs all nine phases through serialized durable receipts", async () => {
    await withImage(async (plan, mock) => {
      const prior: Partial<Record<LinuxImportPhaseName, LinuxImportReceipt>> =
        {};
      for (const phase of phases) {
        const current = context(plan, phase, prior);
        const receipt = await provider(mock.fetcher).executeLinuxImportPhase(
          current,
        );
        expect(receipt.requestDigest).toBe(current.requestDigest);
        expect(receipt.dispatchDigest).toHaveLength(64);
        const writes = mock.calls.filter(
          (call) => call.method !== "GET",
        ).length;
        const observation = await provider(
          mock.fetcher,
        ).inspectLinuxImportPhase({
          ...durable(current),
          receipt: durable(receipt),
        });
        expect(observation.status, phase).toBe("COMPLETED");
        expect(mock.calls.filter((call) => call.method !== "GET")).toHaveLength(
          writes,
        );
        prior[phase] = durable({ ...receipt, ...observation.receiptPatch });
      }
      expect(
        mock.calls
          .filter((call) => call.method !== "GET")
          .map((call) => call.path),
      ).toEqual([
        "/api2/json/nodes/pve1/storage/local/upload",
        "/api2/json/nodes/pve1/qemu",
        "/api2/json/nodes/pve1/qemu/9200/template",
        "/api2/json/nodes/pve1/qemu/9200/clone",
        "/api2/json/nodes/pve1/qemu/9201/config",
        "/api2/json/nodes/pve1/qemu/9201/status/start",
        "/api2/json/nodes/pve1/qemu/9201/status/stop",
        "/api2/json/nodes/pve1/qemu/9201?purge=0&destroy-unreferenced-disks=0",
        "/api2/json/nodes/pve1/qemu/9200?purge=0&destroy-unreferenced-disks=0",
      ]);
      expect(mock.uploaded()).toContain('name="filename"');
      expect(mock.uploaded()).toContain("qcow2!!");
      expect(mock.uploaded()).not.toContain('name="artifactSize"');
      expect(prior.CLONE).toMatchObject({
        sourceVmid: "9200",
        destinationVmid: "9201",
        generatedUuid: "22222222-2222-2222-2222-222222222222",
        generatedCtime: "1700000000",
        configDigest: "d".repeat(40),
      });
    });
  });
  it("denies a replaced staged file before it sends an upload", async () => {
    await withImage(async (plan, mock) => {
      await writeFile(plan.stagePath, "changed", { mode: 0o600 });
      await expect(
        provider(mock.fetcher).executeLinuxImportPhase(
          context(plan, "UPLOAD", {}),
        ),
      ).rejects.toMatchObject({ code: "SAFETY_DENIED" });
      expect(mock.calls.filter((call) => call.method !== "GET")).toEqual([]);
    });
  });
  it("denies a missing phase grant before it sends an upload", async () => {
    await withImage(async (plan, mock) => {
      mock.state.overlay = "missing permission";
      await expect(
        provider(mock.fetcher).executeLinuxImportPhase(
          context(plan, "UPLOAD", {}),
        ),
      ).rejects.toMatchObject({ code: "SAFETY_DENIED" });
      expect(mock.calls.filter((call) => call.method !== "GET")).toEqual([]);
    });
  });
  it.each([
    "node inventory non-qemu type",
    "node inventory invalid vmid",
    "node inventory null type",
    "malformed node inventory",
    "cluster inventory omits type",
  ])("rejects %s before it dispatches an upload", async (overlay) => {
    await withImage(async (plan, mock) => {
      mock.state.overlay = overlay;
      await expect(
        provider(mock.fetcher).executeLinuxImportPhase(
          context(plan, "UPLOAD", {}),
        ),
      ).rejects.toMatchObject({ code: "SAFETY_DENIED" });
      expect(mock.calls.filter((call) => call.method !== "GET")).toEqual([]);
    });
  });
  it.each([
    "external pool member",
    "wrongtags",
    "extra disk",
    "seed",
    "pending",
    "HA",
  ])("rejects %s before clone deletion", async (overlay) => {
    await withImage(async (plan, mock) => {
      const prior = await completeBefore(mock, plan, "DESTROY_CLONE");
      mock.state.overlay = overlay;
      const writes = mock.calls.filter((call) => call.method !== "GET").length;
      await expect(
        provider(mock.fetcher).executeLinuxImportPhase(
          context(plan, "DESTROY_CLONE", prior),
        ),
      ).rejects.toMatchObject({ code: "SAFETY_DENIED" });
      expect(mock.calls.filter((call) => call.method !== "GET")).toHaveLength(
        writes,
      );
    });
  });
  it.each([
    "malformed cluster inventory",
    "malformed node inventory",
    "malformed stage inventory",
    "malformed target inventory",
  ])("rejects %s before clone deletion", async (overlay) => {
    await withImage(async (plan, mock) => {
      const prior = await completeBefore(mock, plan, "DESTROY_CLONE");
      mock.state.overlay = overlay;
      const writes = mock.calls.filter((call) => call.method !== "GET").length;
      await expect(
        provider(mock.fetcher).executeLinuxImportPhase(
          context(plan, "DESTROY_CLONE", prior),
        ),
      ).rejects.toMatchObject({ code: "SAFETY_DENIED" });
      expect(mock.calls.filter((call) => call.method !== "GET")).toHaveLength(
        writes,
      );
    });
  });
  it("binds the STAMP request digest to the saved CLONE config digest", async () => {
    await withImage(async (plan, mock) => {
      const prior = await completeBefore(mock, plan, "STAMP");
      const current = context(plan, "STAMP", prior);
      const receipt = await provider(mock.fetcher).executeLinuxImportPhase(
        current,
      );
      const dispatch = {
        ...receipt.dispatch,
        body: { ...receipt.dispatch.body!, digest: "f".repeat(40) },
      };
      const tampered = durable({
        ...receipt,
        dispatch,
        dispatchDigest: dispatchDigest(dispatch),
      });
      await expect(
        provider(mock.fetcher).inspectLinuxImportPhase({
          ...durable(current),
          receipt: tampered,
        }),
      ).resolves.toMatchObject({ status: "MISMATCH" });
    });
  });
  it("closes the staged descriptor when upload dispatch fails before body consumption", async () => {
    await withImage(async (plan, mock) => {
      const before = (await readdir("/proc/self/fd")).length;
      const rejecting: typeof fetch = async (input, init) =>
        init?.method === "POST"
          ? Promise.reject(new Error("connection refused"))
          : mock.fetcher(input, init);
      await expect(
        provider(rejecting).executeLinuxImportPhase(
          context(plan, "UPLOAD", {}),
        ),
      ).rejects.toMatchObject({ code: "SAFETY_DENIED" });
      await new Promise<void>((resolve) => setImmediate(resolve));
      expect((await readdir("/proc/self/fd")).length).toBeLessThanOrEqual(
        before,
      );
    });
  });
  it("denies malformed absence, a mismatched task receipt, and an oversized response", async () => {
    await withImage(async (plan, mock) => {
      mock.state.overlay = "malformed absence";
      await expect(
        provider(mock.fetcher).executeLinuxImportPhase(
          context(plan, "UPLOAD", {}),
        ),
      ).rejects.toMatchObject({ code: "SAFETY_DENIED" });
      expect(mock.calls.filter((call) => call.method !== "GET")).toEqual([]);
    });
    await withImage(async (plan, mock) => {
      const current = context(plan, "UPLOAD", {}),
        receipt = await provider(mock.fetcher).executeLinuxImportPhase(current);
      mock.state.overlay = "wrong UPID";
      await expect(
        provider(mock.fetcher).inspectLinuxImportPhase({ ...current, receipt }),
      ).resolves.toMatchObject({ status: "MISMATCH" });
    });
    await withImage(async (plan, mock) => {
      mock.state.overlay = "oversized response";
      await expect(
        provider(mock.fetcher).executeLinuxImportPhase(
          context(plan, "UPLOAD", {}),
        ),
      ).rejects.toMatchObject({ code: "SAFETY_DENIED" });
      expect(mock.calls.filter((call) => call.method !== "GET")).toEqual([]);
    });
  });
  it("rejects a NIC or extra disk before a resource can be treated as qualified", () => {
    expect(() =>
      qualifyLinuxImportQemuGraph(
        {
          bios: "seabios",
          boot: "order=scsi0",
          cores: 2,
          cpu: "kvm64",
          memory: "2048",
          scsihw: "virtio-scsi-pci",
          serial0: "socket",
          scsi0: "local-lvm:vm-9200-disk-0,size=8G",
          tags: "kiln",
          digest: "a".repeat(40),
          meta: "creation-qemu=11.0.0,ctime=1",
          smbios1: "uuid=11111111-1111-1111-1111-111111111111",
          vmgenid: "22222222-2222-2222-2222-222222222222",
          net0: "virtio=00:00:00:00:00:00",
        },
        {
          vmid: "9200",
          pending: [],
          snapshots: [],
          firewallOptions: {},
          firewallRules: [],
          firewallAliases: [],
          firewallIpsets: [],
          haResources: [],
          status: { status: "stopped" },
        },
        {
          vmid: "9200",
          storage: "local-lvm",
          volume: "vm-9200-disk-0",
          template: false,
          name: null,
          tags: ["kiln"],
          status: "stopped",
        },
      ),
    ).toThrow();
  });
});
