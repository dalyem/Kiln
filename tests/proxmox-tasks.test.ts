import { describe, expect, it, vi } from "vitest";
import type { ProviderTaskHandle } from "@kiln/core";
import { ProxmoxProvider, parseProxmoxToken } from "@kiln/proxmox";

const taskId =
  "UPID:pve1:0000002A:0000002A:65A0BEEF:qmstart:100:alice@pam!submit:";
const handle: ProviderTaskHandle = {
  taskId,
  providerId: "proxmox",
  providerResourceId: "100",
  providerKind: "qemu",
  node: "pve1",
  action: "start",
  workerType: "qmstart",
  snapshotDigest: "a".repeat(64),
};
const userTaskId =
  "UPID:pve1:0000002A:0000002A:65A0BEEF:qmstart:100:alice@pam:";
const userHandle: ProviderTaskHandle = { ...handle, taskId: userTaskId };

function taskStatus(overrides: Record<string, unknown> = {}) {
  return {
    upid: taskId,
    node: "pve1",
    type: "qmstart",
    id: "100",
    pid: 42,
    pstart: 42,
    starttime: 0x65a0beef,
    user: "alice@pam",
    tokenid: "submit",
    status: "running",
    ...overrides,
  };
}

function providerFor(
  response: Response | (() => Response | Promise<Response>),
  calls: Array<{ path: string; method: string }>,
) {
  return new ProxmoxProvider(
    parseProxmoxToken(
      "https://pve.local:8006",
      "PVEAPIToken=reader@pam!rotated=secret",
    ),
    async (input, init) => {
      calls.push({
        path: new URL(input.toString()).pathname,
        method: init?.method ?? "GET",
      });
      return typeof response === "function" ? response() : response.clone();
    },
  );
}

function response(data: unknown, status = 200) {
  return new Response(JSON.stringify({ data }), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("Proxmox task reader", () => {
  it("reads a split-token task with a rotated reader token using GET only", async () => {
    const calls: Array<{ path: string; method: string }> = [];
    const provider = providerFor(response(taskStatus()), calls);

    await expect(provider.inspectOperation(handle)).resolves.toEqual({
      status: "RUNNING",
    });
    expect(calls).toEqual([
      {
        path: `/api2/json/nodes/pve1/tasks/${encodeURIComponent(taskId)}/status`,
        method: "GET",
      },
    ]);
  });

  it("accepts only stopped tasks with the exact OK exit status", async () => {
    const calls: Array<{ path: string; method: string }> = [];
    const provider = providerFor(
      response(taskStatus({ status: "stopped", exitstatus: "OK" })),
      calls,
    );

    await expect(provider.inspectOperation(handle)).resolves.toEqual({
      status: "SUCCEEDED",
    });
    expect(calls).toHaveLength(1);
  });

  it.each(["WARNINGS: 1", "backup failed"])(
    "treats stopped task exit status %s as failed",
    async (exitstatus) => {
      const calls: Array<{ path: string; method: string }> = [];
      const provider = providerFor(
        response(taskStatus({ status: "stopped", exitstatus })),
        calls,
      );

      await expect(provider.inspectOperation(handle)).resolves.toEqual({
        status: "FAILED",
      });
      expect(calls).toHaveLength(1);
    },
  );

  it.each([
    ["upid", `${taskId}extra`],
    ["node", "pve2"],
    ["id", "101"],
    ["type", "qmstop"],
    ["pid", 43],
    ["pstart", 43],
    ["starttime", 0x65a0bef0],
    ["user", "mallory@pam"],
    ["tokenid", "other-submit"],
  ])(
    "reports a terminal mismatch when the response %s contradicts the receipt",
    async (field, value) => {
      const calls: Array<{ path: string; method: string }> = [];
      const provider = providerFor(
        response(taskStatus({ [field]: value })),
        calls,
      );

      await expect(provider.inspectOperation(handle)).resolves.toEqual({
        status: "MISMATCH",
      });
      expect(calls).toHaveLength(1);
    },
  );

  it("rejects a non-string tokenid that is present on a user task", async () => {
    const calls: Array<{ path: string; method: string }> = [];
    const provider = providerFor(
      response(taskStatus({ upid: userTaskId, tokenid: null })),
      calls,
    );

    await expect(provider.inspectOperation(userHandle)).resolves.toEqual({
      status: "MISMATCH",
    });
    expect(calls).toHaveLength(1);
  });

  it("returns missing only for the task endpoint's explicit no-such-task response", async () => {
    const calls: Array<{ path: string; method: string }> = [];
    const provider = providerFor(
      new Response(JSON.stringify({ errors: { upid: "no such task" } }), {
        status: 400,
        headers: { "content-type": "application/json" },
      }),
      calls,
    );

    await expect(provider.inspectOperation(handle)).resolves.toEqual({
      status: "MISSING",
    });
    expect(calls).toHaveLength(1);
  });

  it.each([
    ["a generic not-found response", response({}, 404)],
    ["a malformed status body", response({ status: "running" })],
    ["a transport failure", () => Promise.reject(new Error("offline"))],
  ])("returns unknown for %s", async (_name, fixture) => {
    const calls: Array<{ path: string; method: string }> = [];
    const provider = providerFor(fixture, calls);

    await expect(provider.inspectOperation(handle)).resolves.toEqual({
      status: "UNKNOWN",
    });
    expect(calls).toHaveLength(1);
  });

  it("rejects an oversized task response", async () => {
    const calls: Array<{ path: string; method: string }> = [];
    const provider = providerFor(
      response(taskStatus({ ignored: "x".repeat(64 * 1024) })),
      calls,
    );

    await expect(provider.inspectOperation(handle)).resolves.toEqual({
      status: "UNKNOWN",
    });
    expect(calls).toHaveLength(1);
  });

  it("cancels a response with an invalid Content-Length", async () => {
    const calls: Array<{ path: string; method: string }> = [];
    let cancelled = false;
    const provider = providerFor(
      () =>
        new Response(
          new ReadableStream({
            cancel() {
              cancelled = true;
            },
          }),
          { headers: { "content-length": "not-a-length" } },
        ),
      calls,
    );

    await expect(provider.inspectOperation(handle)).resolves.toEqual({
      status: "UNKNOWN",
    });
    expect(cancelled).toBe(true);
    expect(calls).toHaveLength(1);
  });

  it("aborts a timed out task read and returns unknown", async () => {
    vi.useFakeTimers();
    let aborted = false;
    const provider = new ProxmoxProvider(
      parseProxmoxToken(
        "https://pve.local:8006",
        "PVEAPIToken=reader@pam!rotated=secret",
      ),
      async (_input, init) =>
        await new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            aborted = true;
            reject(new Error("aborted"));
          });
        }),
    );
    try {
      const observation = provider.inspectOperation(handle);
      await vi.advanceTimersByTimeAsync(5_000);
      await expect(observation).resolves.toEqual({ status: "UNKNOWN" });
      expect(aborted).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it.each([
    ["another provider", { providerId: "fake" }],
    ["a non-native kind", { providerKind: "fake" }],
    ["a missing node", { node: null }],
    [
      "an empty VMID",
      { taskId: taskId.replace(":100:", "::"), providerResourceId: "" },
    ],
    [
      "a VMID outside Proxmox's numeric range",
      {
        taskId: taskId.replace(":100:", ":1000000000:"),
        providerResourceId: "1000000000",
      },
    ],
    ["an invalid action", { action: "mutate" }],
    ["a missing worker type", { workerType: undefined }],
    ["an action that contradicts its worker type", { action: "destroy" }],
    [
      "an unqualified LXC worker",
      {
        providerKind: "lxc",
        workerType: "vzstart",
        taskId: taskId.replace("qmstart", "vzstart"),
      },
    ],
    [
      "an unqualified HA worker",
      { workerType: "hastart", taskId: taskId.replace("qmstart", "hastart") },
    ],
    ["a worker type that does not match the UPID", { workerType: "qmstop" }],
    ["a native ID that does not match the UPID", { providerResourceId: "101" }],
    [
      "a qmclone UPID bound to its source native ID",
      {
        taskId: taskId.replace("qmstart:100", "qmclone:100"),
        workerType: "qmclone",
        action: "create",
        providerResourceId: "101",
      },
    ],
    ["an invalid snapshot digest", { snapshotDigest: "digest" }],
    [
      "a traversal UPID",
      { taskId: taskId.replace(":100:", ":100/../../etc:") },
    ],
    ["a malformed UPID", { taskId: "UPID:pve1:not-a-pid" }],
  ])("does not request a task for %s", async (_name, change) => {
    const calls: Array<{ path: string; method: string }> = [];
    const provider = providerFor(response(taskStatus()), calls);

    await expect(
      provider.inspectOperation({ ...handle, ...change } as ProviderTaskHandle),
    ).resolves.toEqual({
      status: "UNKNOWN",
    });
    expect(calls).toEqual([]);
  });
});
