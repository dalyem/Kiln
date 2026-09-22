import { mkdtemp, lstat, readFile, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { LinuxImageStaging } from "@kiln/core";

async function* chunks(...values: string[]): AsyncIterable<Uint8Array> {
  for (const value of values) yield Buffer.from(value);
}

describe("Linux image staging", () => {
  it("writes an opaque private file and rejects a length mismatch", async () => {
    const root = await mkdtemp(join(tmpdir(), "kiln-staging-"));
    try {
      const staging = new LinuxImageStaging(root);
      const staged = await staging.stage(chunks("abc", "def"), 6);
      expect(staged.id).toMatch(/^lstg_[a-f0-9]{32}$/);
      expect(await readFile(staged.path, "utf8")).toBe("abcdef");
      expect((await lstat(staged.path)).mode & 0o077).toBe(0);
      await expect(staging.stage(chunks("abc"), 4)).rejects.toMatchObject({
        code: "INVALID_INPUT",
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
  it("does not follow a staged symlink during cleanup", async () => {
    const root = await mkdtemp(join(tmpdir(), "kiln-staging-"));
    try {
      const staging = new LinuxImageStaging(root);
      const id = "lstg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
      await symlink("/etc/passwd", join(root, id));
      await expect(staging.remove(id)).rejects.toMatchObject({
        code: "SAFETY_DENIED",
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("durable staging quota", () => {
  it("charges ready files across instances and forbids unjournaled cleanup", async () => {
    const root = await mkdtemp(join(tmpdir(), "kiln-staging-"));
    try {
      const first = new LinuxImageStaging(root, { maxBytes: 6, maxFiles: 2 });
      const staged = await first.stage(chunks("abcd"), 4);
      const restarted = new LinuxImageStaging(root, {
        maxBytes: 6,
        maxFiles: 2,
      });
      expect(await restarted.describe(staged.id)).toEqual(staged);
      await expect(restarted.stage(chunks("xyz"), 3)).rejects.toMatchObject({
        code: "CONFLICT",
      });
      await expect(restarted.remove(staged.id)).rejects.toMatchObject({
        code: "SAFETY_DENIED",
      });
      expect(await readFile(staged.path, "utf8")).toBe("abcd");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
  it("reserves the declared size before reading and prevents concurrent overcommit", async () => {
    const root = await mkdtemp(join(tmpdir(), "kiln-staging-"));
    let release!: () => void;
    let entered!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    async function* slow() {
      entered();
      await held;
      yield Buffer.from("abcd");
    }
    const first = new LinuxImageStaging(root, { maxBytes: 6 });
    const pending = first.stage(slow(), 4);
    try {
      await started;
      let read = false;
      async function* forbidden() {
        read = true;
        yield Buffer.from("xyz");
      }
      await expect(
        new LinuxImageStaging(root, { maxBytes: 6 }).stage(forbidden(), 3),
      ).rejects.toMatchObject({ code: "CONFLICT" });
      expect(read).toBe(false);
      release();
      await pending;
    } finally {
      release();
      await pending.catch(() => undefined);
      await rm(root, { recursive: true, force: true });
    }
  });
  it("retains a crashed reservation across restart and rejects incomplete stages", async () => {
    const { writeFile } = await import("node:fs/promises");
    const root = await mkdtemp(join(tmpdir(), "kiln-staging-"));
    const id = "lstg_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    try {
      await writeFile(
        join(root, id + ".json"),
        JSON.stringify({
          version: 1,
          id,
          size: 6,
          state: "RESERVED",
          sha256: null,
          idempotencyDigest: null,
          expectedSha256: null,
        }),
        { mode: 0o600 },
      );
      const staging = new LinuxImageStaging(root, { maxBytes: 6 });
      await expect(staging.describe(id)).rejects.toMatchObject({
        code: "SAFETY_DENIED",
      });
      await expect(staging.stage(chunks("a"), 1)).rejects.toMatchObject({
        code: "CONFLICT",
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
  it("releases failed incoming streams without publishing a stage", async () => {
    const { readdir } = await import("node:fs/promises");
    const root = await mkdtemp(join(tmpdir(), "kiln-staging-"));
    async function* interrupted() {
      yield Buffer.from("a");
      throw new Error("connection dropped");
    }
    try {
      const staging = new LinuxImageStaging(root, { maxBytes: 2 });
      await expect(staging.stage(interrupted(), 2)).rejects.toThrow(
        "connection dropped",
      );
      expect(await readdir(root)).toEqual([]);
      expect((await staging.stage(chunks("ab"), 2)).size).toBe(2);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
  it("rejects unknown allocations and symlinked ancestors", async () => {
    const { writeFile, mkdir } = await import("node:fs/promises");
    const root = await mkdtemp(join(tmpdir(), "kiln-staging-"));
    try {
      await writeFile(join(root, "unrecognized"), "keep", { mode: 0o600 });
      await expect(
        new LinuxImageStaging(root).stage(chunks("a"), 1),
      ).rejects.toMatchObject({ code: "SAFETY_DENIED" });
      expect(await readFile(join(root, "unrecognized"), "utf8")).toBe("keep");
      await mkdir(join(root, "real"), { mode: 0o700 });
      await symlink(join(root, "real"), join(root, "alias"));
      await expect(
        new LinuxImageStaging(join(root, "alias", "stage")).stage(
          chunks("a"),
          1,
        ),
      ).rejects.toMatchObject({ code: "SAFETY_DENIED" });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("retry and timeout boundaries", () => {
  const sha =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
  it("replays the same upload after restart without consuming quota or reading another body", async () => {
    const root = await mkdtemp(join(tmpdir(), "kiln-staging-"));
    try {
      const options = { idempotencyKey: "same-upload", expectedSha256: sha };
      const original = await new LinuxImageStaging(root, { maxBytes: 3 }).stage(
        chunks("abc"),
        3,
        options,
      );
      let consumed = false;
      async function* unexpected() {
        consumed = true;
        yield Buffer.alloc(0);
        throw new Error("must not consume replay");
      }
      const replay = await new LinuxImageStaging(root, { maxBytes: 3 }).stage(
        unexpected(),
        3,
        options,
      );
      expect(replay).toEqual(original);
      expect(consumed).toBe(false);
      await expect(
        new LinuxImageStaging(root).stage(chunks("abcd"), 4, options),
      ).rejects.toMatchObject({ code: "CONFLICT" });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
  it("rejects a mismatched declared hash without publishing and permits a corrected retry", async () => {
    const root = await mkdtemp(join(tmpdir(), "kiln-staging-"));
    try {
      const staging = new LinuxImageStaging(root, { maxBytes: 3 });
      const options = { idempotencyKey: "hash-check", expectedSha256: sha };
      await expect(
        staging.stage(chunks("abd"), 3, options),
      ).rejects.toMatchObject({ code: "INVALID_INPUT" });
      expect((await staging.stage(chunks("abc"), 3, options)).sha256).toBe(sha);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
  it("ends a stalled stream by deadline and releases its unpublished reservation", async () => {
    const { readdir } = await import("node:fs/promises");
    const root = await mkdtemp(join(tmpdir(), "kiln-staging-"));
    try {
      const staging = new LinuxImageStaging(root, { maxBytes: 3 });
      async function* stalled() {
        await new Promise<void>(() => {});
        yield Buffer.from("abc");
      }
      await expect(
        staging.stage(stalled(), 3, { timeoutMs: 10 }),
      ).rejects.toMatchObject({ code: "INVALID_INPUT", status: 408 });
      expect(await readdir(root)).toEqual([]);
      expect((await staging.stage(chunks("abc"), 3)).size).toBe(3);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
