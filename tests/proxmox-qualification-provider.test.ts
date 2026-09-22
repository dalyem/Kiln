import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  canonicalQualificationPlan,
  canonicalQualificationDispatch,
  type QualificationExecutionContext,
  type QualificationPhaseName,
  type QualificationPlan,
  type QualificationReceipt,
} from "@kiln/core";
import { ProxmoxQualificationProvider } from "../packages/proxmox/src/qualification.js";

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
const storageDigest = "6".repeat(40);
const templateTags =
  "kiln;kiln-managed;kiln-installation-inst1;kiln-resource-image_template;kiln-resource-id-template1;kiln-qualification-nonce-template-nonce";
const probeTags =
  "kiln;kiln-managed;kiln-installation-inst1;kiln-resource-network_probe;kiln-resource-id-probe1;kiln-qualification-nonce-probe-nonce";

function plan(): QualificationPlan {
  const artifact = Buffer.alloc(104).toString("base64");
  const withoutDigest = {
    schemaVersion: 1 as const,
    installationId: "inst1",
    node: "pve1",
    pool: "kiln",
    poolNonce: "pool-nonce",
    poolComment: "kiln-qualification-run1;nonce=pool-nonce",
    stageStorage: "local",
    targetStorage: "local-lvm",
    pveVersion: "9.2.2" as const,
    storageConfigDigest: storageDigest,
    tokenIdentity: "qual@pam!run",
    stageVolumeId: "import/probe-run1.qcow2",
    templateVmid: "9100",
    probeVmid: "9101",
    templateResourceId: "template1",
    probeResourceId: "probe1",
    templateBootVolume: "base-9100-disk-0",
    probeBootVolume: "vm-9101-disk-0",
    templateNonce: "template-nonce",
    probeNonce: "probe-nonce",
    image: {
      id: "image1",
      manifest: {
        schemaVersion: 1 as const,
        name: "probe",
        version: "1",
        arch: "amd64" as const,
        artifactSha256: createHash("sha256")
          .update(Buffer.alloc(104))
          .digest("hex"),
        artifactSize: 104,
        sourceBuild: "test",
        capabilities: ["network_probe"],
        keyId: "operator",
      },
      manifestDigest: "a".repeat(64),
      signerFingerprint: "fingerprint",
      policyDigest: "b".repeat(64),
    },
    artifactBase64: artifact,
    artifactDisposition: "MANAGED_RETAINED_IMAGE_CACHE" as const,
    poolDisposition: "MANAGED_RETAINED_POOL" as const,
  };
  return {
    ...withoutDigest,
    canonicalDigest: canonicalQualificationPlan(withoutDigest),
  } as QualificationPlan;
}

function context(
  plan: QualificationPlan,
  phase: QualificationPhaseName,
  priorReceipts: Partial<Record<QualificationPhaseName, QualificationReceipt>>,
): QualificationExecutionContext {
  return {
    plan,
    phase,
    priorReceipts,
    requestDigest: createHash("sha256")
      .update(`${plan.canonicalDigest}:${phase}`)
      .digest("hex"),
  };
}

function missing(node: string, vmid: string) {
  return new Response(
    JSON.stringify({
      data: null,
      message: `Configuration file 'nodes/${node}/qemu-server/${vmid}.conf' does not exist\n`,
    }),
    { status: 500 },
  );
}

function envelope(data: unknown, status = 200) {
  return new Response(JSON.stringify({ data }), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function fixture(
  overrides: { existingTemplate?: boolean; genericMissing?: boolean } = {},
) {
  const state = {
    pool: false,
    stage: false,
    template: overrides.existingTemplate
      ? "vm"
      : ("absent" as "absent" | "vm" | "template"),
    probe: "absent" as "absent" | "vm",
    power: "stopped",
    tags: templateTags,
    stampDigest: "d".repeat(40),
    overlay: "",
    remainingProbeDisk: false,
  };
  const calls: Array<{ method: string; path: string }> = [];
  const tasks = new Map<string, { worker: string; id: string; pid: number }>();
  let nextPid = 1;
  const p = plan();
  const config = (vmid: string) => {
    const isTemplate = vmid === p.templateVmid;
    const mode = isTemplate ? state.template : state.probe;
    if (mode === "absent") return null;
    const volume = isTemplate
      ? state.template === "template"
        ? p.templateBootVolume
        : "vm-9100-disk-0"
      : p.probeBootVolume;
    const result = {
      bios: "seabios",
      scsihw: "virtio-scsi-single",
      boot: "order=scsi0",
      serial0: "socket",
      memory: "128",
      cores: 1,
      cpu: "kvm64",
      scsi0: `local-lvm:${volume},size=4M`,
      tags: isTemplate ? templateTags : state.tags,
      digest: isTemplate ? "c".repeat(40) : state.stampDigest,
      meta: "creation-qemu=11.0.0,ctime=1700000000",
      smbios1: `uuid=${isTemplate ? "11111111-1111-1111-1111-111111111111" : "22222222-2222-2222-2222-222222222222"}`,
      vmgenid: isTemplate
        ? "33333333-3333-3333-3333-333333333333"
        : "44444444-4444-4444-4444-444444444444",
      ...(!isTemplate ? { name: "Copy-of-VM-9100" } : {}),
      ...(isTemplate && state.template === "template" ? { template: 1 } : {}),
    };
    if (!isTemplate && state.overlay === "missing-managed")
      return { ...result, tags: result.tags.replace("kiln-managed;", "") };
    if (!isTemplate && state.overlay === "wrong-installation")
      return { ...result, tags: result.tags.replace("inst1", "foreign") };
    if (!isTemplate && state.overlay === "foreign-disk")
      return { ...result, scsi0: "local-lvm:vm-9999-disk-0,size=4M" };
    if (!isTemplate && state.overlay === "nic")
      return { ...result, net0: "virtio=BC:24:11:00:00:01,bridge=vmbr0" };
    if (!isTemplate && state.overlay === "uuid")
      return {
        ...result,
        smbios1: "uuid=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      };
    return result;
  };
  const fetcher: typeof fetch = async (input, init) => {
    const url = new URL(input.toString());
    const method = init?.method ?? "GET";
    const path = `${url.pathname}${url.search}`;
    calls.push({ method, path });
    const task = (worker: string, id: string) => {
      const pid = nextPid++;
      const upid = `UPID:pve1:${pid.toString(16).padStart(8, "0")}:00000002:00000003:${worker}:${id}:qual@pam!run:`;
      tasks.set(upid, { worker, id, pid });
      return envelope(upid);
    };
    if (method !== "GET") {
      if (method === "POST" && path === "/api2/json/pools") {
        state.pool = true;
        return envelope(null);
      }
      if (path.endsWith("/upload")) {
        state.stage = true;
        return task("imgcopy", "");
      }
      if (path.endsWith("/qemu")) {
        state.template = "vm";
        return task("qmcreate", p.templateVmid);
      }
      if (path.endsWith("/template")) {
        state.template = "template";
        return task("qmtemplate", p.templateVmid);
      }
      if (path.endsWith("/clone")) {
        state.probe = "vm";
        return task("qmclone", p.templateVmid);
      }
      if (method === "PUT" && path.endsWith("/config")) {
        state.tags = probeTags;
        state.stampDigest = "e".repeat(40);
        return envelope(null);
      }
      if (path.endsWith("/status/start")) {
        state.power = "running";
        return task("qmstart", p.probeVmid);
      }
      if (path.endsWith("/status/stop")) {
        state.power = "stopped";
        return task("qmstop", p.probeVmid);
      }
      if (
        method === "DELETE" &&
        path.startsWith(`/api2/json/nodes/pve1/qemu/${p.probeVmid}`)
      ) {
        state.probe = "absent";
        return task("qmdestroy", p.probeVmid);
      }
      if (
        method === "DELETE" &&
        path.startsWith(`/api2/json/nodes/pve1/qemu/${p.templateVmid}`)
      ) {
        state.template = "absent";
        return task("qmdestroy", p.templateVmid);
      }
      return envelope(null, 500);
    }
    if (path === "/api2/json/version") return envelope({ version: "9.2.2" });
    if (path === "/api2/json/access/permissions")
      return envelope({
        "/": {
          "Sys.Audit": 1,
          "Pool.Audit": 1,
          "Datastore.Audit": 1,
          "VM.Audit": state.overlay === "missing-audit" ? 0 : 1,
        },
      });
    if (path === "/api2/json/storage")
      return envelope([
        {
          storage: "local",
          type: "dir",
          path: "/var/lib/vz",
          content: "vztmpl,import,iso",
          digest: storageDigest,
        },
        {
          storage: "local-lvm",
          type: "lvmthin",
          vgname: "pve",
          thinpool: "data",
          content: "rootdir,images",
          digest: storageDigest,
        },
      ]);
    if (path === "/api2/json/nodes/pve1/storage")
      return envelope([
        { storage: "local", type: "dir", active: 1, enabled: 1, shared: 0 },
        {
          storage: "local-lvm",
          type: "lvmthin",
          active: 1,
          enabled: 1,
          shared: 0,
        },
      ]);
    const entries = [
      state.template !== "absent"
        ? { type: "qemu", vmid: 9100, node: "pve1" }
        : null,
      state.probe !== "absent"
        ? { type: "qemu", vmid: 9101, node: "pve1" }
        : null,
    ].filter(Boolean);
    if (
      path === "/api2/json/cluster/resources?type=vm" ||
      path === "/api2/json/nodes/pve1/qemu"
    )
      return envelope(entries);
    if (path === "/api2/json/pools/kiln")
      return state.pool
        ? envelope({ poolid: "kiln", comment: p.poolComment, members: entries })
        : new Response(
            JSON.stringify({
              data: null,
              message: "pool 'kiln' does not exist\n",
            }),
            { status: 500 },
          );
    if (path === "/api2/json/nodes/pve1/storage/local/content")
      return envelope(
        state.stage
          ? [{ volid: "local:import/probe-run1.qcow2", size: 104 }]
          : [],
      );
    if (path === "/api2/json/nodes/pve1/storage/local-lvm/content")
      return envelope(
        [
          state.template === "vm"
            ? { volid: "local-lvm:vm-9100-disk-0" }
            : state.template === "template"
              ? { volid: "local-lvm:base-9100-disk-0" }
              : null,
          state.probe === "vm" || state.remainingProbeDisk
            ? { volid: "local-lvm:vm-9101-disk-0" }
            : null,
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
            upid,
            node: "pve1",
            type: found.worker,
            id: found.id,
            pid: found.pid,
            pstart: 2,
            starttime: 3,
            user: "qual@pam",
            tokenid: "run",
            status: "stopped",
            exitstatus: "OK",
          })
        : envelope(null, 500);
    }
    const vmMatch = /^\/api2\/json\/nodes\/pve1\/qemu\/(9100|9101)\/(.+)$/.exec(
      url.pathname,
    );
    if (vmMatch) {
      const vmid = vmMatch[1]!;
      const endpoint = vmMatch[2]!;
      const current = config(vmid);
      if (!current && (endpoint === "config" || endpoint === "status/current"))
        return overrides.genericMissing
          ? envelope(null, 500)
          : missing("pve1", vmid);
      if (endpoint === "config") return envelope(current);
      if (endpoint === "status/current")
        return envelope({
          status: vmid === p.probeVmid ? state.power : "stopped",
        });
      if (endpoint === "pending")
        return envelope(
          current
            ? Object.entries(current).map(([key, value]) => ({
                key,
                value:
                  state.overlay === "pending" && key === "scsi0"
                    ? "foreign"
                    : value,
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
          ...(state.overlay === "snapshot" ? [{ name: "extra" }] : []),
        ]);
      if (endpoint === "firewall/options")
        return envelope({ digest: "f".repeat(40) });
      if (
        ["firewall/rules", "firewall/aliases", "firewall/ipset"].includes(
          endpoint,
        )
      )
        return envelope([]);
    }
    if (path === "/api2/json/cluster/ha/resources")
      return envelope(state.overlay === "ha" ? [{ sid: "vm:9101" }] : []);
    return envelope(null, 500);
  };
  return { p, calls, fetcher, state };
}

function provider(fetcher: typeof fetch) {
  return new ProxmoxQualificationProvider(
    {
      url: new URL("https://pve1.example:8006"),
      tokenId: "qual@pam!run",
      tokenSecret: "secret",
    },
    fetcher,
  );
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

async function completeBefore(
  mock: ReturnType<typeof fixture>,
  phase: QualificationPhaseName,
) {
  const prior: Partial<Record<QualificationPhaseName, QualificationReceipt>> =
    {};
  for (const name of phases.slice(0, phases.indexOf(phase))) {
    const current = context(mock.p, name, prior);
    const receipt = await provider(mock.fetcher).executeQualificationPhase(
      current,
    );
    const observation = await provider(mock.fetcher).inspectQualificationPhase(
      current,
      receipt,
    );
    if (observation.status !== "COMPLETED")
      throw new Error("fixture phase did not complete");
    prior[name] = { ...receipt, ...observation.receiptPatch };
  }
  return prior;
}

describe("Proxmox lifecycle qualification provider", () => {
  it("runs the ten qualified phases with durable receipts and no process-local ownership", async () => {
    const mock = fixture();
    const prior: Partial<Record<QualificationPhaseName, QualificationReceipt>> =
      {};
    for (const phase of phases) {
      const current = context(mock.p, phase, prior);
      const receipt = await provider(mock.fetcher).executeQualificationPhase(
        current,
      );
      expect(receipt.requestDigest).toBe(current.requestDigest);
      expect(receipt.dispatchDigest).toHaveLength(64);
      expect(receipt.dispatch).toBeDefined();
      const durableContext = reorder(current) as QualificationExecutionContext;
      const durableReceipt = reorder(receipt) as QualificationReceipt;
      const observation = await provider(
        mock.fetcher,
      ).inspectQualificationPhase(durableContext, durableReceipt);
      expect(observation.status, phase).toBe("COMPLETED");
      prior[phase] = reorder({
        ...durableReceipt,
        ...observation.receiptPatch,
      }) as QualificationReceipt;
    }
    expect(
      mock.calls
        .filter((call) => call.method !== "GET")
        .map((call) => call.path),
    ).toEqual([
      "/api2/json/pools",
      "/api2/json/nodes/pve1/storage/local/upload",
      "/api2/json/nodes/pve1/qemu",
      "/api2/json/nodes/pve1/qemu/9100/template",
      "/api2/json/nodes/pve1/qemu/9100/clone",
      "/api2/json/nodes/pve1/qemu/9101/config",
      "/api2/json/nodes/pve1/qemu/9101/status/start",
      "/api2/json/nodes/pve1/qemu/9101/status/stop",
      "/api2/json/nodes/pve1/qemu/9101?purge=0&destroy-unreferenced-disks=0",
      "/api2/json/nodes/pve1/qemu/9100?purge=0&destroy-unreferenced-disks=0",
    ]);
    expect(prior.CLONE).toMatchObject({
      sourceVmid: "9100",
      destinationVmid: "9101",
      generatedUuid: "22222222-2222-2222-2222-222222222222",
      generatedCtime: "1700000000",
    });
  });

  it.each([
    ["an existing planned VM", { existingTemplate: true }],
    ["a generic missing-config response", { genericMissing: true }],
  ])("rejects %s before any mutation", async (_name, options) => {
    const mock = fixture(options);
    await expect(
      provider(mock.fetcher).executeQualificationPhase(
        context(mock.p, "POOL_CREATE", {}),
      ),
    ).rejects.toMatchObject({ code: "SAFETY_DENIED" });
    expect(mock.calls.filter((call) => call.method !== "GET")).toEqual([]);
  });

  it.each([
    "missing-managed",
    "wrong-installation",
    "foreign-disk",
    "nic",
    "pending",
    "snapshot",
    "ha",
    "missing-audit",
  ])(
    "rejects %s before probe deletion without dispatching",
    async (overlay) => {
      const mock = fixture();
      const prior = await completeBefore(mock, "DESTROY_PROBE");
      mock.state.overlay = overlay;
      const before = mock.calls.filter((call) => call.method !== "GET").length;
      await expect(
        provider(mock.fetcher).executeQualificationPhase(
          context(mock.p, "DESTROY_PROBE", prior),
        ),
      ).rejects.toMatchObject({ code: "SAFETY_DENIED" });
      expect(mock.calls.filter((call) => call.method !== "GET")).toHaveLength(
        before,
      );
    },
  );

  it("rejects a changed generated identity after stamping", async () => {
    const mock = fixture();
    const prior = await completeBefore(mock, "STAMP");
    const current = context(mock.p, "STAMP", prior);
    const receipt = await provider(mock.fetcher).executeQualificationPhase(
      current,
    );
    mock.state.overlay = "uuid";
    await expect(
      provider(mock.fetcher).inspectQualificationPhase(current, receipt),
    ).resolves.not.toMatchObject({ status: "COMPLETED" });
  });

  it("rejects a rehashed receipt whose dispatch body changed", async () => {
    const mock = fixture();
    const current = context(mock.p, "POOL_CREATE", {});
    const receipt = await provider(mock.fetcher).executeQualificationPhase(
      current,
    );
    const dispatch = {
      ...receipt.dispatch!,
      body: { ...receipt.dispatch!.body!, comment: "foreign" },
    };
    const tampered = {
      ...receipt,
      dispatch,
      dispatchDigest: canonicalQualificationDispatch(dispatch),
    };
    await expect(
      provider(mock.fetcher).inspectQualificationPhase(current, tampered),
    ).resolves.toMatchObject({ status: "MISMATCH" });
  });

  it("does not complete probe deletion while its planned disk remains", async () => {
    const mock = fixture();
    const prior = await completeBefore(mock, "DESTROY_PROBE");
    const current = context(mock.p, "DESTROY_PROBE", prior);
    const receipt = await provider(mock.fetcher).executeQualificationPhase(
      current,
    );
    mock.state.remainingProbeDisk = true;
    await expect(
      provider(mock.fetcher).inspectQualificationPhase(current, receipt),
    ).resolves.not.toMatchObject({ status: "COMPLETED" });
  });

  it("rejects a credential identity that differs from the saved plan before observation", async () => {
    const mock = fixture();
    const mismatched = new ProxmoxQualificationProvider(
      {
        url: new URL("https://pve1.example:8006"),
        tokenId: "other@pam!run",
        tokenSecret: "secret",
      },
      mock.fetcher,
    );
    await expect(
      mismatched.executeQualificationPhase(context(mock.p, "POOL_CREATE", {})),
    ).rejects.toMatchObject({ code: "SAFETY_DENIED" });
    expect(mock.calls).toEqual([]);
  });
});
