import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { constants } from "node:fs";
import { execFile } from "node:child_process";
import { lstat, mkdtemp, open, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import { canonicalImageManifest, type ImageManifest, type TrustedImageKeys } from "../../packages/core/src/provenance.ts";
import { maxImageFileArtifactBytes, verifyImageFile } from "../../packages/core/src/image-file.ts";
import { parseBuildMetadata, readBoundedRegularFile } from "./metadata.ts";

function usage(): never { throw new Error("usage: npx tsx images/dev/sign.ts --artifact PATH --metadata PATH --version VERSION --key-id ID --private-key PATH --output-dir ABSENT_DIRECTORY"); }

async function main(): Promise<void> {
  const values = new Map<string, string>();
  for (let index = 2; index < process.argv.length; index += 2) {
    const key = process.argv[index]; const value = process.argv[index + 1];
    if (!key?.startsWith("--") || !value || values.has(key)) usage();
    values.set(key, value);
  }
  const required = ["--artifact", "--metadata", "--version", "--key-id", "--private-key", "--output-dir"];
  if (process.argv.length !== 14 || required.some((key) => !values.has(key))) usage();
  const artifactPath = values.get("--artifact")!;
  const metadataPath = values.get("--metadata")!;
  const outputDir = values.get("--output-dir")!;
  const artifact = await localImage(artifactPath);
  const metadata = await readMetadata(metadataPath);
  const artifactSha256 = await sha256File(artifactPath);
  if (metadata.value.artifactSha256 !== artifactSha256) throw new Error("metadata artifact digest does not match artifact");
  const manifest: ImageManifest = {
    schemaVersion: 1,
    name: "kiln-dev-base",
    version: values.get("--version")!,
    arch: "amd64",
    artifactSha256,
    artifactSize: Number(artifact.size),
    sourceBuild: `sha256:${createHash("sha256").update(metadata.bytes).digest("hex")}`,
    capabilities: ["development"],
    keyId: values.get("--key-id")!,
  };
  const privateKey = createPrivateKey((await readBoundedRegularFile(values.get("--private-key")!, 64 * 1024, "private key")).toString("utf8"));
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("private key is not Ed25519");
  const signature = sign(null, Buffer.from(canonicalImageManifest(manifest)), privateKey).toString("base64");
  const publicKeyPem = createPublicKey(privateKey).export({ type: "spki", format: "pem" }).toString();
  const keys: TrustedImageKeys = { [manifest.keyId]: { publicKeyPem, allowedNames: [manifest.name], allowedCapabilities: [...manifest.capabilities], allowedArchitectures: [manifest.arch] } };
  await verifyImageFile({ manifest, signature, artifactPath }, keys, new Date().toISOString());
  try { await lstat(outputDir); throw new Error("refusing to overwrite signature output directory"); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  const staging = await mkdtemp(join(dirname(outputDir), ".kiln-image-sign-"));
  try {
    await writeFile(`${staging}/manifest.json`, `${canonicalImageManifest(manifest)}\n`, { mode: 0o600, flag: "wx" });
    await writeFile(`${staging}/manifest.sig`, signature, { mode: 0o600, flag: "wx" });
    await writeFile(`${staging}/build-metadata.json`, metadata.bytes, { mode: 0o600, flag: "wx" });
    await publishDirectory(staging, outputDir);
  } catch (error) {
    await rm(staging, { recursive: true, force: true });
    throw error;
  }
}

async function readMetadata(path: string): Promise<{ bytes: Buffer; value: ReturnType<typeof parseBuildMetadata> }> {
  const bytes = await readBoundedRegularFile(path, 1024 * 1024, "metadata");
  return { bytes, value: parseBuildMetadata(bytes) };
}


async function localImage(path: string): Promise<{ dev: bigint; ino: bigint; size: bigint; mtimeNs: bigint; ctimeNs: bigint }> {
  const before = await lstat(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.size < 1n || before.size > BigInt(maxImageFileArtifactBytes)) throw new Error("artifact must be a regular file at most 2 GiB");
  return { dev: before.dev, ino: before.ino, size: before.size, mtimeNs: before.mtimeNs, ctimeNs: before.ctimeNs };
}

async function sha256File(path: string): Promise<string> {
  const before = await localImage(path);
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  const hash = createHash("sha256");
  try {
    const opened = await handle.stat({ bigint: true });
    if (!sameFile(before, opened)) throw new Error("artifact changed while opening");
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let offset = 0;
    while (offset < Number(before.size)) {
      const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.length, Number(before.size) - offset), offset);
      if (!bytesRead) throw new Error("artifact changed while reading");
      hash.update(buffer.subarray(0, bytesRead));
      offset += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    const pathAfter = await localImage(path);
    if (!sameFile(before, after) || !sameFile(before, pathAfter)) throw new Error("artifact changed while reading");
  } finally { await handle.close(); }
  return hash.digest("hex");
}

function sameFile(left: { dev: bigint; ino: bigint; size: bigint; mtimeNs: bigint; ctimeNs: bigint }, right: { dev: bigint; ino: bigint; size: bigint; mtimeNs: bigint; ctimeNs: bigint }): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

async function publishDirectory(staging: string, output: string): Promise<void> {
  const program = [
    "import ctypes, os, sys",
    "libc = ctypes.CDLL(None, use_errno=True)",
    "renameat2 = libc.renameat2",
    "renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]",
    "renameat2.restype = ctypes.c_int",
    "if renameat2(-100, os.fsencode(sys.argv[1]), -100, os.fsencode(sys.argv[2]), 1) != 0:",
    "    raise OSError(ctypes.get_errno(), 'publish signature directory')",
  ].join("\n");
  await promisify(execFile)("python3", ["-c", program, staging, output]);
}

void main().catch((error: unknown) => { process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; });
