import { execFile } from "node:child_process";
import { mkdtemp, rm, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { parseBuildMetadata, readBoundedRegularFile } from "./metadata.ts";

const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))); });

function metadata(): Buffer {
  return Buffer.from(JSON.stringify({
    schemaVersion: 1,
    name: "kiln-dev-base",
    arch: "amd64",
    profile: "debian13-nic-free-development-v1",
    recipe: "images/dev/build.sh",
    recipeSha256: "a".repeat(64),
    baseSha512: "b".repeat(128),
    kilndSha256: "c".repeat(64),
    artifactSha256: "d".repeat(64),
    packages: ["git\t1.0"],
    reproducible: false,
  }));
}

async function directory(): Promise<string> {
  const value = await mkdtemp(join(tmpdir(), "kiln-metadata-"));
  directories.push(value);
  return value;
}

describe("development image metadata files", () => {
  it("reads a valid regular file when ctime and mtime differ", async () => {
    const path = join(await directory(), "metadata.json");
    await writeFile(path, metadata(), { mode: 0o600 });
    await utimes(path, new Date(1_700_000_000_000), new Date(1_700_000_000_000));

    const bytes = await readBoundedRegularFile(path, 1024 * 1024, "metadata");

    expect(parseBuildMetadata(bytes)).toMatchObject({ name: "kiln-dev-base", profile: "debian13-nic-free-development-v1" });
  });

  it("rejects malformed metadata, a FIFO, and an oversized file", async () => {
    const root = await directory();
    const malformed = join(root, "malformed.json");
    await writeFile(malformed, "{}", { mode: 0o600 });
    expect(() => parseBuildMetadata(Buffer.from("{}"))).toThrow("schema");

    const fifo = join(root, "metadata.fifo");
    await promisify(execFile)("mkfifo", [fifo]);
    await expect(readBoundedRegularFile(fifo, 1024, "metadata")).rejects.toThrow("regular file");

    const oversized = join(root, "large.json");
    await writeFile(oversized, Buffer.alloc(33), { mode: 0o600 });
    await expect(readBoundedRegularFile(oversized, 32, "metadata")).rejects.toThrow("regular file");
    await expect(readBoundedRegularFile(malformed, 1024, "metadata")).resolves.toEqual(Buffer.from("{}"));
  });
});
