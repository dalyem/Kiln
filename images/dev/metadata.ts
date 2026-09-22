import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";

export interface BuildMetadata {
  schemaVersion: 1;
  name: "kiln-dev-base";
  arch: "amd64";
  profile: "debian13-nic-free-development-v1";
  recipe: "images/dev/build.sh";
  recipeSha256: string;
  baseSha512: string;
  kilndSha256: string;
  artifactSha256: string;
  packages: string[];
  reproducible: false;
}

const fields = ["schemaVersion", "name", "arch", "profile", "recipe", "recipeSha256", "baseSha512", "kilndSha256", "artifactSha256", "packages", "reproducible"];

export function parseBuildMetadata(bytes: Buffer): BuildMetadata {
  let value: unknown;
  try { value = JSON.parse(bytes.toString("utf8")); } catch { throw new Error("metadata is not valid JSON"); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("metadata schema is invalid");
  const metadata = value as Partial<BuildMetadata>;
  if (Object.keys(metadata).length !== fields.length || fields.some((field) => !(field in metadata)) || metadata.schemaVersion !== 1 || metadata.name !== "kiln-dev-base" || metadata.arch !== "amd64" || metadata.profile !== "debian13-nic-free-development-v1" || metadata.recipe !== "images/dev/build.sh" || metadata.reproducible !== false || !/^[a-f0-9]{64}$/.test(metadata.recipeSha256 ?? "") || !/^[a-f0-9]{128}$/.test(metadata.baseSha512 ?? "") || !/^[a-f0-9]{64}$/.test(metadata.kilndSha256 ?? "") || !/^[a-f0-9]{64}$/.test(metadata.artifactSha256 ?? "") || !Array.isArray(metadata.packages) || metadata.packages.length === 0 || metadata.packages.some((entry) => typeof entry !== "string" || !/^[^\t\n]+\t[^\t\n]+$/.test(entry))) throw new Error("metadata schema is invalid");
  return metadata as BuildMetadata;
}

export async function readBoundedRegularFile(path: string, maximumBytes: number, label: string): Promise<Buffer> {
  const before = await fileIdentity(path, maximumBytes, label);
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    if (!sameFile(before, await handle.stat({ bigint: true }))) throw new Error(`${label} changed while opening`);
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (!bytesRead) throw new Error(`${label} changed while reading`);
      offset += bytesRead;
    }
    if (!sameFile(before, await handle.stat({ bigint: true })) || !sameFile(before, await fileIdentity(path, maximumBytes, label))) throw new Error(`${label} changed while reading`);
    return bytes;
  } finally { await handle.close(); }
}

async function fileIdentity(path: string, maximumBytes: number, label: string): Promise<{ dev: bigint; ino: bigint; size: bigint; mtimeNs: bigint; ctimeNs: bigint }> {
  const info = await lstat(path, { bigint: true });
  if (!info.isFile() || info.isSymbolicLink() || info.size < 1n || info.size > BigInt(maximumBytes)) throw new Error(`${label} must be a regular file at most ${maximumBytes} bytes`);
  return { dev: info.dev, ino: info.ino, size: info.size, mtimeNs: info.mtimeNs, ctimeNs: info.ctimeNs };
}

function sameFile(left: { dev: bigint; ino: bigint; size: bigint; mtimeNs: bigint; ctimeNs: bigint }, right: { dev: bigint; ino: bigint; size: bigint; mtimeNs: bigint; ctimeNs: bigint }): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}
