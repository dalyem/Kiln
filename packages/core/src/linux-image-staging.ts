import { constants, type BigIntStats } from "node:fs";
import {
  mkdir,
  lstat,
  open,
  link,
  unlink,
  rename,
  readdir,
} from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { KilnError } from "./index.js";
import { maxImageFileArtifactBytes } from "./image-file.js";

export interface StagedLinuxImage {
  id: string;
  path: string;
  size: number;
  sha256: string;
}
interface Reservation {
  version: 1;
  id: string;
  size: number;
  state: "RESERVED" | "READY";
  sha256: string | null;
  idempotencyDigest: string | null;
  expectedSha256: string | null;
}
const idPattern = /^lstg_[a-f0-9]{32}$/;
const locks = new Map<string, Promise<void>>();
const denied = (message: string) =>
  new KilnError("SAFETY_DENIED", 403, message);

/** Single-writer appliance staging. Durable reservations count interrupted uploads toward quota. */
export class LinuxImageStaging {
  private readonly root: string;
  private readonly maxBytes: number;
  private readonly maxFiles: number;
  constructor(
    root: string,
    limits: { maxBytes?: number; maxFiles?: number } = {},
  ) {
    if (!root.startsWith("/"))
      throw denied("Linux image staging directory must be absolute");
    this.root = resolve(root);
    this.maxBytes = limits.maxBytes ?? 4 * 1024 * 1024 * 1024;
    this.maxFiles = limits.maxFiles ?? 8;
    if (
      !Number.isSafeInteger(this.maxBytes) ||
      this.maxBytes < 1 ||
      !Number.isSafeInteger(this.maxFiles) ||
      this.maxFiles < 1 ||
      this.maxFiles > 128
    )
      throw denied("Linux image staging quota is invalid");
  }

  async stage(
    body: AsyncIterable<Uint8Array>,
    contentLength: number | undefined,
    options: {
      idempotencyKey?: string;
      expectedSha256?: string;
      timeoutMs?: number;
    } = {},
  ): Promise<StagedLinuxImage> {
    if (
      !Number.isSafeInteger(contentLength) ||
      contentLength! < 1 ||
      contentLength! > maxImageFileArtifactBytes
    )
      throw new KilnError(
        "INVALID_INPUT",
        400,
        "Linux image Content-Length must be between 1 byte and 2 GiB",
      );
    const size = contentLength!;
    const timeoutMs = options.timeoutMs ?? 20 * 60_000;
    if (
      !Number.isSafeInteger(timeoutMs) ||
      timeoutMs < 1 ||
      timeoutMs > 20 * 60_000
    )
      throw denied("Linux image staging deadline is invalid");
    if (
      (options.idempotencyKey === undefined) !==
        (options.expectedSha256 === undefined) ||
      (options.idempotencyKey !== undefined &&
        (!/^[A-Za-z0-9._:-]{1,128}$/.test(options.idempotencyKey) ||
          !/^[a-f0-9]{64}$/.test(options.expectedSha256!)))
    )
      throw new KilnError(
        "INVALID_INPUT",
        400,
        "Linux image staging key and digest are invalid",
      );
    const idempotencyDigest = options.idempotencyKey
      ? createHash("sha256").update(options.idempotencyKey).digest("hex")
      : null;
    const id = `lstg_${idempotencyDigest ? idempotencyDigest.slice(0, 32) : randomUUID().replaceAll("-", "")}`;
    const reservation: Reservation = {
      version: 1,
      id,
      size,
      state: "RESERVED",
      sha256: null,
      idempotencyDigest,
      expectedSha256: options.expectedSha256 ?? null,
    };
    const replay = await this.lock(async () => {
      await this.privateRoot();
      const reservations = await this.inventory();
      const existing = reservations.find((row) => row.id === id);
      if (existing) {
        if (
          existing.idempotencyDigest !== idempotencyDigest ||
          existing.size !== size ||
          existing.expectedSha256 !== options.expectedSha256
        )
          throw new KilnError(
            "CONFLICT",
            409,
            "Linux image staging key was reused with a different payload",
          );
        if (existing.state !== "READY")
          throw new KilnError(
            "CONFLICT",
            409,
            "Linux image staging upload is incomplete; inspection is required",
          );
        return this.describe(id);
      }
      if (
        reservations.length >= this.maxFiles ||
        reservations.reduce((sum, row) => sum + row.size, 0) + size >
          this.maxBytes
      )
        throw new KilnError(
          "CONFLICT",
          409,
          "Linux image staging quota is exhausted",
        );
      await this.writeNew(`${id}.json`, reservation);
      await this.syncRoot();
      return null;
    });
    if (replay) return replay;
    const temporary = join(this.root, `.${id}.partial`);
    const finalPath = this.pathFor(id);
    let published = false;
    let temporaryOwned = false;
    let handle: Awaited<ReturnType<typeof open>> | undefined;
    try {
      handle = await open(
        temporary,
        constants.O_WRONLY |
          constants.O_CREAT |
          constants.O_EXCL |
          constants.O_NOFOLLOW,
        0o600,
      );
      temporaryOwned = true;
      let bytes = 0;
      const digest = createHash("sha256");
      for await (const chunk of boundedBody(body, timeoutMs)) {
        if (!(chunk instanceof Uint8Array))
          throw new KilnError(
            "INVALID_INPUT",
            400,
            "Linux image body is invalid",
          );
        bytes += chunk.byteLength;
        if (bytes > size)
          throw new KilnError(
            "INVALID_INPUT",
            400,
            "Linux image exceeds its declared size",
          );
        digest.update(chunk);
        let offset = 0;
        while (offset < chunk.byteLength) {
          const { bytesWritten } = await handle.write(
            chunk,
            offset,
            chunk.byteLength - offset,
          );
          if (!bytesWritten) throw denied("Linux image staging write failed");
          offset += bytesWritten;
        }
      }
      if (bytes !== size)
        throw new KilnError(
          "INVALID_INPUT",
          400,
          "Linux image Content-Length does not match its body",
        );
      const sha256 = digest.digest("hex");
      if (options.expectedSha256 && sha256 !== options.expectedSha256)
        throw new KilnError(
          "INVALID_INPUT",
          400,
          "Linux image upload digest does not match its declaration",
        );
      await handle.chmod(0o400);
      await handle.sync();
      await handle.close();
      handle = undefined;
      // link fails if the destination exists. Never replace an unrecognized file.
      await link(temporary, finalPath);
      published = true;
      await unlink(temporary);
      await this.syncRoot();
      await this.lock(async () => {
        const saved = await this.readReservation(id);
        if (saved.state !== "RESERVED" || saved.size !== size)
          throw denied("Linux image reservation changed");
        await this.writeNew(`.${id}.ready`, {
          ...reservation,
          state: "READY",
          sha256,
        });
        await rename(
          join(this.root, `.${id}.ready`),
          join(this.root, `${id}.json`),
        );
        await this.syncRoot();
      });
      return { id, path: finalPath, size, sha256 };
    } catch (error) {
      await handle?.close().catch(() => undefined);
      // Once published, retain the reservation and file for investigation on any failure.
      if (!published && temporaryOwned)
        await this.lock(async () => {
          try {
            await unlink(temporary).catch((err: NodeJS.ErrnoException) => {
              if (err.code !== "ENOENT") throw err;
            });
            // A conflicting destination is not ours and must not be removed or stop consuming quota.
            const conflict = await lstat(finalPath).catch(
              (err: NodeJS.ErrnoException) => {
                if (err.code !== "ENOENT") throw err;
                return null;
              },
            );
            if (!conflict) await unlink(join(this.root, `${id}.json`));
            await this.syncRoot();
          } catch {
            /* Keep an unresolved reservation charged against quota. */
          }
        });
      throw error;
    }
  }

  pathFor(id: string): string {
    if (!idPattern.test(id))
      throw new KilnError(
        "INVALID_INPUT",
        400,
        "Linux image staging ID is invalid",
      );
    return join(this.root, id);
  }

  async describe(id: string): Promise<StagedLinuxImage> {
    this.pathFor(id);
    await this.privateRoot();
    const saved = await this.readReservation(id);
    if (saved.state !== "READY" || !saved.sha256)
      throw denied("Linux image staging is not complete");
    const info = await lstat(this.pathFor(id), { bigint: true });
    this.privateFile(info);
    if (info.size !== BigInt(saved.size))
      throw denied("Linux image staging size changed");
    return {
      id,
      path: this.pathFor(id),
      size: saved.size,
      sha256: saved.sha256,
    };
  }

  /** Qualification stages are retained; deletion needs a future journaled retirement operation. */
  async remove(id: string): Promise<void> {
    this.pathFor(id);
    throw denied(
      "Linux image staging deletion is disabled while database claims may exist",
    );
  }

  private async inventory(): Promise<Reservation[]> {
    const names = await readdir(this.root);
    if (names.length > this.maxFiles * 4)
      throw denied("Linux image staging contains too many entries");
    const records: Reservation[] = [];
    for (const name of names)
      if (/^lstg_[a-f0-9]{32}\.json$/.test(name))
        records.push(await this.readReservation(name.slice(0, -5)));
    const expected = new Set(
      records.flatMap((row) => [
        row.id,
        `${row.id}.json`,
        `.${row.id}.partial`,
        `.${row.id}.ready`,
      ]),
    );
    if (names.some((name) => !expected.has(name)))
      throw denied("Linux image staging contains an unrecognized allocation");
    return records;
  }

  private async readReservation(id: string): Promise<Reservation> {
    const file = await open(
      join(this.root, `${id}.json`),
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    ).catch(() => {
      throw denied("Linux image staging reservation is missing");
    });
    try {
      const info = await file.stat({ bigint: true });
      this.privateFile(info);
      if (info.size > 4096n)
        throw denied("Linux image staging reservation is invalid");
      const raw = Buffer.alloc(Number(info.size));
      let offset = 0;
      while (offset < raw.length) {
        const { bytesRead } = await file.read(
          raw,
          offset,
          raw.length - offset,
          offset,
        );
        if (!bytesRead) throw denied("Linux image staging reservation changed");
        offset += bytesRead;
      }
      const after = await file.stat({ bigint: true });
      if (
        info.ino !== after.ino ||
        info.size !== after.size ||
        info.mtimeNs !== after.mtimeNs ||
        info.ctimeNs !== after.ctimeNs
      )
        throw denied("Linux image staging reservation changed");
      let row: Reservation;
      try {
        row = JSON.parse(raw.toString("utf8"));
      } catch {
        throw denied("Linux image staging reservation is invalid");
      }
      if (
        !row ||
        typeof row !== "object" ||
        Object.keys(row).sort().join(",") !==
          "expectedSha256,id,idempotencyDigest,sha256,size,state,version" ||
        row.version !== 1 ||
        row.id !== id ||
        (row.idempotencyDigest !== null &&
          (typeof row.idempotencyDigest !== "string" ||
            !/^[a-f0-9]{64}$/.test(row.idempotencyDigest) ||
            id !== `lstg_${row.idempotencyDigest.slice(0, 32)}`)) ||
        (row.idempotencyDigest === null) !== (row.expectedSha256 === null) ||
        (row.expectedSha256 !== null &&
          (typeof row.expectedSha256 !== "string" ||
            !/^[a-f0-9]{64}$/.test(row.expectedSha256))) ||
        (row.state === "READY" &&
          row.expectedSha256 !== null &&
          row.sha256 !== row.expectedSha256) ||
        !Number.isSafeInteger(row.size) ||
        row.size < 1 ||
        row.size > maxImageFileArtifactBytes ||
        !["RESERVED", "READY"].includes(row.state) ||
        (row.state === "READY"
          ? typeof row.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(row.sha256)
          : row.sha256 !== null)
      )
        throw denied("Linux image staging reservation is invalid");
      return row;
    } finally {
      await file.close();
    }
  }

  private async writeNew(name: string, value: unknown): Promise<void> {
    const file = await open(
      join(this.root, name),
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        constants.O_NOFOLLOW,
      0o600,
    );
    try {
      await file.writeFile(JSON.stringify(value));
      await file.sync();
    } finally {
      await file.close();
    }
  }
  private privateFile(info: BigIntStats): void {
    if (
      !info.isFile() ||
      info.uid !== BigInt(process.getuid!()) ||
      info.nlink !== 1n ||
      (info.mode & 0o077n) !== 0n
    )
      throw denied("Linux image staging file is not private");
  }
  private async privateRoot(): Promise<void> {
    // Validate all existing ancestors before recursive mkdir could follow a symlink.
    for (let path = this.root; ; path = dirname(path)) {
      const info = await lstat(path).catch((err: NodeJS.ErrnoException) => {
        if (err.code !== "ENOENT") throw err;
        return null;
      });
      if (
        info &&
        (!info.isDirectory() ||
          info.isSymbolicLink() ||
          ((info.mode & 0o022) !== 0 &&
            !((info.mode & 0o1000) !== 0 && info.uid === 0)))
      )
        throw denied("Linux image staging ancestor is unsafe");
      if (path === dirname(path)) break;
    }
    await mkdir(this.root, { recursive: true, mode: 0o700 });
    const root = await lstat(this.root);
    if (
      !root.isDirectory() ||
      root.isSymbolicLink() ||
      root.uid !== process.getuid!() ||
      (root.mode & 0o077) !== 0
    )
      throw denied("Linux image staging directory is not private");
  }
  private async syncRoot(): Promise<void> {
    const directory = await open(
      this.root,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  }
  private async lock<T>(action: () => Promise<T>): Promise<T> {
    const previous = locks.get(this.root) ?? Promise.resolve();
    let release!: () => void;
    const pending = new Promise<void>((resolve) => {
      release = resolve;
    });
    locks.set(this.root, pending);
    await previous;
    try {
      return await action();
    } finally {
      release();
      if (locks.get(this.root) === pending) locks.delete(this.root);
    }
  }
}

async function* boundedBody(
  body: AsyncIterable<Uint8Array>,
  timeoutMs: number,
): AsyncGenerator<Uint8Array> {
  if (!body || typeof body[Symbol.asyncIterator] !== "function")
    throw new KilnError(
      "INVALID_INPUT",
      400,
      "Linux image body must be a stream",
    );
  const iterator = body[Symbol.asyncIterator]();
  const deadline = Date.now() + timeoutMs;
  let completed = false;
  try {
    for (;;) {
      const remaining = deadline - Date.now();
      if (remaining <= 0)
        throw new KilnError(
          "INVALID_INPUT",
          408,
          "Linux image upload deadline exceeded",
        );
      let timer: ReturnType<typeof setTimeout> | undefined;
      const next = await Promise.race([
        iterator.next(),
        new Promise<never>((_resolve, reject) => {
          timer = setTimeout(
            () =>
              reject(
                new KilnError(
                  "INVALID_INPUT",
                  408,
                  "Linux image upload deadline exceeded",
                ),
              ),
            remaining,
          );
        }),
      ]).finally(() => clearTimeout(timer));
      if (next.done) {
        completed = true;
        return;
      }
      yield next.value;
    }
  } finally {
    // Never await return(): an interrupted async generator may itself be waiting forever.
    if (!completed) {
      const stream = body as AsyncIterable<Uint8Array> & {
        destroy?: () => void;
      };
      stream.destroy?.();
      void iterator.return?.().catch(() => undefined);
    }
  }
}
