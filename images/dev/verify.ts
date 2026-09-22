import { createHash } from "node:crypto";
import { verifyImageFile } from "../../packages/core/src/image-file.ts";
import type { ImageManifest, TrustedImageKeys } from "../../packages/core/src/provenance.ts";
import { parseBuildMetadata, readBoundedRegularFile } from "./metadata.ts";

function usage(): never { throw new Error("usage: npx tsx images/dev/verify.ts --artifact PATH --metadata PATH --manifest PATH --signature PATH --trust PATH"); }

async function main(): Promise<void> {
  const values = new Map<string, string>();
  for (let index = 2; index < process.argv.length; index += 2) {
    const key = process.argv[index]; const value = process.argv[index + 1];
    if (!key?.startsWith("--") || !value || values.has(key)) usage();
    values.set(key, value);
  }
  if (process.argv.length !== 12 || ["--artifact", "--metadata", "--manifest", "--signature", "--trust"].some((key) => !values.has(key))) usage();
  const manifest = JSON.parse((await readBoundedRegularFile(values.get("--manifest")!, 128 * 1024, "manifest")).toString("utf8")) as ImageManifest;
  const keys = JSON.parse((await readBoundedRegularFile(values.get("--trust")!, 1024 * 1024, "trust policy")).toString("utf8")) as TrustedImageKeys;
  const signature = (await readBoundedRegularFile(values.get("--signature")!, 1024, "signature")).toString("utf8").trim();
  const metadata = await readBoundedRegularFile(values.get("--metadata")!, 1024 * 1024, "metadata");
  if (metadata.length < 1 || metadata.length > 1024 * 1024 || manifest.sourceBuild !== `sha256:${createHash("sha256").update(metadata).digest("hex")}`) throw new Error("metadata digest does not match manifest");
  const metadataValue = parseBuildMetadata(metadata);
  if (metadataValue.artifactSha256 !== manifest.artifactSha256) throw new Error("metadata artifact digest does not match manifest");
  const verified = await verifyImageFile({ manifest, signature, artifactPath: values.get("--artifact")! }, keys, new Date().toISOString());
  process.stdout.write(`${JSON.stringify({ manifestDigest: verified.manifestDigest, artifactSha256: verified.manifest.artifactSha256 })}\n`);
}


void main().catch((error: unknown) => { process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; });
