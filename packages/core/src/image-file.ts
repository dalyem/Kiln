import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import {
  canonicalImageManifest,
  type ImageManifest,
  maxInlineImageArtifactBytes,
  type TrustedImageKeys,
  sha256,
  type VerifiedImage,
  verifyImageManifest,
} from "./provenance.js";

export const maxImageFileArtifactBytes = 2 * 1024 * 1024 * 1024;
const qcowHeaderBytes = 112;
const linuxVirtualDiskBytes = 8n * 1024n * 1024n * 1024n;

export interface ImageFileVerificationRequest {
  manifest: ImageManifest;
  signature: string;
  artifactPath: string;
}

interface FileIdentity {
  dev: bigint;
  ino: bigint;
  size: bigint;
  mtimeNs: bigint;
  ctimeNs: bigint;
}

/** Verifies a signed local Linux QCOW2 image without loading image bytes into memory. */
export async function verifyImageFile(
  request: ImageFileVerificationRequest,
  keys: TrustedImageKeys,
  now: string,
): Promise<VerifiedImage> {
  const manifest = structuredClone(request.manifest);
  const trustedKeys = structuredClone(keys);
  const artifactPath = request.artifactPath;
  if (/^https?:\/\//.test(artifactPath)) throw new Error("Image artifact must be a local file");
  if (manifest.arch !== "amd64" || manifest.name !== "kiln-dev-base" || !manifest.capabilities.includes("development"))
    throw new Error("Image artifact is not the required Linux development profile");
  const verification = verifyImageManifest(manifest, request.signature, trustedKeys, maxImageFileArtifactBytes);
  const before = await localRegularFile(artifactPath);
  if (before.size !== BigInt(manifest.artifactSize)) throw new Error("Image artifact does not match its manifest");

  let handle;
  try {
    handle = await open(artifactPath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch { throw new Error("Image artifact must be a regular local file"); }
  try {
    const openedBefore = identity(await handle.stat({ bigint: true }));
    if (!sameIdentity(before, openedBefore)) throw new Error("Image artifact changed while opening");
    const hash = createHash("sha256");
    const chunk = Buffer.allocUnsafe(64 * 1024);
    const header = Buffer.alloc(qcowHeaderBytes);
    let offset = 0;
    while (offset < manifest.artifactSize) {
      const length = Math.min(chunk.length, manifest.artifactSize - offset);
      const { bytesRead } = await handle.read(chunk, 0, length, offset);
      if (bytesRead === 0) throw new Error("Image artifact changed while reading");
      if (offset < qcowHeaderBytes) chunk.copy(header, offset, 0, Math.min(bytesRead, qcowHeaderBytes - offset));
      hash.update(chunk.subarray(0, bytesRead));
      offset += bytesRead;
    }
    if (offset < qcowHeaderBytes) throw new Error("Image artifact is not the required Linux QCOW2 profile");
    if (hash.digest("hex") !== manifest.artifactSha256) throw new Error("Image artifact digest does not match its manifest");
    assertLinuxQcow2Header(header);
    const openedAfter = identity(await handle.stat({ bigint: true }));
    const after = await localRegularFile(artifactPath);
    if (!sameIdentity(before, openedAfter) || !sameIdentity(before, after)) throw new Error("Image artifact changed while reading");
  } finally {
    await handle.close();
  }
  return {
    id: `img_${randomUUID().replaceAll("-", "")}`,
    manifest: structuredClone(manifest),
    manifestDigest: sha256(canonicalImageManifest(manifest)),
    signerFingerprint: sha256(verification.publicKey.export({ type: "spki", format: "der" })),
    policyDigest: sha256(JSON.stringify({
      keyId: manifest.keyId,
      allowedNames: verification.policy.allowedNames,
      allowedCapabilities: verification.policy.allowedCapabilities,
      allowedArchitectures: verification.policy.allowedArchitectures,
    })),
    importedAt: now,
  };
}

export function assertLinuxQcow2Header(header: Buffer): void {
  if (
    header.length < qcowHeaderBytes ||
    header.subarray(0, 4).toString("binary") !== "QFI\u00fb" ||
    header.readUInt32BE(4) !== 3 ||
    header.readBigUInt64BE(8) !== 0n ||
    header.readUInt32BE(16) !== 0 ||
    header.readUInt32BE(20) !== 16 ||
    header.readBigUInt64BE(24) !== linuxVirtualDiskBytes ||
    header.readUInt32BE(32) !== 0 ||
    header.readUInt32BE(60) !== 0 ||
    header.readBigUInt64BE(64) !== 0n ||
    header.readBigUInt64BE(72) !== 0n ||
    header.readBigUInt64BE(80) !== 0n ||
    header.readBigUInt64BE(88) !== 0n ||
    header.readUInt32BE(96) !== 4 ||
    ![104, 112].includes(header.readUInt32BE(100)) ||
    (header.readUInt32BE(100) === 112 && header.subarray(104, 112).some((byte) => byte !== 0))
  ) throw new Error("Image artifact is not the required Linux QCOW2 profile");
}

async function localRegularFile(path: string): Promise<FileIdentity> {
  let info;
  try { info = await lstat(path, { bigint: true }); } catch { throw new Error("Image artifact must be a regular local file"); }
  if (!info.isFile() || info.isSymbolicLink() || info.size < 1n || info.size > BigInt(maxImageFileArtifactBytes))
    throw new Error("Image artifact must be a regular local file");
  return identity(info);
}

function identity(info: { dev: bigint; ino: bigint; size: bigint; mtimeNs: bigint; ctimeNs: bigint }): FileIdentity {
  return { dev: info.dev, ino: info.ino, size: info.size, mtimeNs: info.mtimeNs, ctimeNs: info.ctimeNs };
}

function sameIdentity(left: FileIdentity, right: FileIdentity): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

export { maxInlineImageArtifactBytes };
