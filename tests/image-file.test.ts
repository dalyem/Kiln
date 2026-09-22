import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { chmod, mkdtemp, symlink, truncate, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  canonicalImageManifest,
  maxInlineImageArtifactBytes,
  verifyImageFile,
  verifyImageImport,
  type ImageManifest,
  type TrustedImageKeys,
} from "@kiln/core";

const virtualDiskBytes = 8n * 1024n * 1024n * 1024n;

function linuxQcow(overrides: Partial<{ backingOffset: bigint; backingSize: number; cryptMethod: number; snapshots: number; snapshotsOffset: bigint; incompatible: bigint; compatible: bigint; autoclear: bigint; headerLength: number; extension: number }> = {}): Buffer {
  const value = Buffer.alloc(112);
  value.write("QFI\u00fb", 0, "binary");
  value.writeUInt32BE(3, 4);
  value.writeBigUInt64BE(overrides.backingOffset ?? 0n, 8);
  value.writeUInt32BE(overrides.backingSize ?? 0, 16);
  value.writeUInt32BE(16, 20);
  value.writeBigUInt64BE(virtualDiskBytes, 24);
  value.writeUInt32BE(overrides.cryptMethod ?? 0, 32);
  value.writeUInt32BE(overrides.snapshots ?? 0, 60);
  value.writeBigUInt64BE(overrides.snapshotsOffset ?? 0n, 64);
  value.writeBigUInt64BE(overrides.incompatible ?? 0n, 72);
  value.writeBigUInt64BE(overrides.compatible ?? 0n, 80);
  value.writeBigUInt64BE(overrides.autoclear ?? 0n, 88);
  value.writeUInt32BE(4, 96);
  value.writeUInt32BE(overrides.headerLength ?? 112, 100);
  if (overrides.extension !== undefined) value[104] = overrides.extension;
  return value;
}

function signer(): { keys: TrustedImageKeys; signRequest: (artifact: Buffer, manifest?: Partial<ImageManifest>) => { manifest: ImageManifest; signature: string } } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const keys: TrustedImageKeys = {
    operator: {
      publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
      allowedNames: ["kiln-dev-base"],
      allowedCapabilities: ["development"],
      allowedArchitectures: ["amd64"],
    },
  };
  return {
    keys,
    signRequest: (artifact, overrides = {}) => {
      const manifest: ImageManifest = {
        schemaVersion: 1,
        name: "kiln-dev-base",
        version: "1",
        arch: "amd64",
        artifactSha256: createHash("sha256").update(artifact).digest("hex"),
        artifactSize: artifact.length,
        sourceBuild: "image-file-test",
        capabilities: ["development"],
        keyId: "operator",
        ...overrides,
      };
      return { manifest, signature: sign(null, Buffer.from(canonicalImageManifest(manifest)), privateKey).toString("base64") };
    },
  };
}

async function artifact(bytes: Buffer): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "kiln-image-file-"));
  const path = join(directory, "image.qcow2");
  await writeFile(path, bytes, { mode: 0o600 });
  return path;
}

describe("local image file verification", () => {
  it("streams a signed Linux image and returns copied verified metadata", async () => {
    const bytes = Buffer.concat([linuxQcow(), Buffer.alloc(128 * 1024)]);
    const path = await artifact(bytes);
    const signed = signer();
    const request = signed.signRequest(bytes);

    const verified = await verifyImageFile({ ...request, artifactPath: path }, signed.keys, "2026-09-21T00:00:00.000Z");

    expect(verified).toMatchObject({ manifest: request.manifest, importedAt: "2026-09-21T00:00:00.000Z" });
    expect(verified.manifest).not.toBe(request.manifest);
  });

  it("binds manifest and signer policy before the first await", async () => {
    const bytes = Buffer.concat([linuxQcow(), Buffer.alloc(128 * 1024)]);
    const path = await artifact(bytes);
    const signed = signer();
    const request = { ...signed.signRequest(bytes), artifactPath: path };
    const pending = verifyImageFile(request, signed.keys, "now");
    request.manifest.name = "changed";
    signed.keys.operator!.allowedCapabilities.length = 0;
    await expect(pending).resolves.toMatchObject({ manifest: { name: "kiln-dev-base", capabilities: ["development"] } });
  });

  it("rejects a changed, truncated, oversized, or linked artifact", async () => {
    const bytes = linuxQcow();
    const signed = signer();
    const changedPath = await artifact(Buffer.from(bytes));
    const changed = signed.signRequest(bytes);
    const altered = Buffer.from(bytes); altered[111] = (altered[111] ?? 0) ^ 1;
    await writeFile(changedPath, altered);
    await expect(verifyImageFile({ ...changed, artifactPath: changedPath }, signed.keys, "now")).rejects.toThrow("digest");

    const truncatedPath = await artifact(Buffer.from(bytes));
    const truncated = signed.signRequest(bytes);
    await truncate(truncatedPath, bytes.length - 1);
    await expect(verifyImageFile({ ...truncated, artifactPath: truncatedPath }, signed.keys, "now")).rejects.toThrow("does not match");

    const oversizedPath = await artifact(bytes);
    const oversized = signed.signRequest(bytes, { artifactSize: maxInlineImageArtifactBytes + 1 });
    await truncate(oversizedPath, 2 * 1024 * 1024 * 1024 + 1);
    await expect(verifyImageFile({ ...oversized, artifactPath: oversizedPath }, signed.keys, "now")).rejects.toThrow("regular local file");

    const linkPath = `${oversizedPath}.link`;
    await symlink(oversizedPath, linkPath);
    await expect(verifyImageFile({ ...signed.signRequest(bytes), artifactPath: linkPath }, signed.keys, "now")).rejects.toThrow("regular local file");
  });

  it("rejects unknown signer policy and a manifest outside the development profile", async () => {
    const bytes = linuxQcow();
    const path = await artifact(bytes);
    const signed = signer();
    const request = signed.signRequest(bytes);
    await expect(verifyImageFile({ ...request, artifactPath: path }, {}, "now")).rejects.toThrow("not trusted");
    await expect(verifyImageFile({ ...request, signature: `${request.signature.slice(0, -3)}AAA`, artifactPath: path }, signed.keys, "now")).rejects.toThrow("signature");

    const wrongCapability = signed.signRequest(bytes, { capabilities: ["execution"] });
    await expect(verifyImageFile({ ...wrongCapability, artifactPath: path }, { operator: { ...signed.keys.operator!, allowedCapabilities: ["development", "execution"] } }, "now")).rejects.toThrow("development profile");
  });

  it("accepts both header lengths and rejects unsupported QCOW2 features", async () => {
    const signed = signer();
    const compatible104 = linuxQcow({ headerLength: 104 });
    await expect(verifyImageFile({ ...signed.signRequest(compatible104), artifactPath: await artifact(compatible104) }, signed.keys, "now")).resolves.toBeDefined();
    for (const bytes of [linuxQcow({ backingOffset: 1n }), linuxQcow({ backingSize: 1 }), linuxQcow({ cryptMethod: 1 }), linuxQcow({ snapshots: 1 }), linuxQcow({ snapshotsOffset: 1n }), linuxQcow({ incompatible: 1n }), linuxQcow({ compatible: 1n }), linuxQcow({ autoclear: 1n }), linuxQcow({ extension: 1 })]) {
      const path = await artifact(bytes);
      await expect(verifyImageFile({ ...signed.signRequest(bytes), artifactPath: path }, signed.keys, "now")).rejects.toThrow("Linux QCOW2 profile");
    }
  });

  it("keeps the 128 KiB inline import ceiling", () => {
    const bytes = Buffer.alloc(maxInlineImageArtifactBytes + 1);
    const signed = signer();
    const request = signed.signRequest(bytes);
    expect(() => verifyImageImport({ ...request, artifactBase64: bytes.toString("base64") }, signed.keys, "now")).toThrow("Image manifest is invalid");
  });
});
