import { createHash, createPublicKey, randomUUID, verify } from "node:crypto";

export interface ImageManifest {
  schemaVersion: 1;
  name: string;
  version: string;
  arch: "amd64" | "arm64";
  artifactSha256: string;
  artifactSize: number;
  sourceBuild: string;
  capabilities: string[];
  keyId: string;
}

export interface VerifiedImage {
  id: string;
  manifest: ImageManifest;
  manifestDigest: string;
  signerFingerprint: string;
  policyDigest: string;
  importedAt: string;
}

export type AttachmentClass =
  | "BOOT_VOLUME"
  | "DATA_VOLUME"
  | "CLOUD_INIT"
  | "EFI"
  | "TPM"
  | "UNUSED_VOLUME"
  | "NIC"
  | "FIREWALL"
  | "HA"
  | "STORAGE_REFERENCE"
  | "BRIDGE_REFERENCE"
  | "ISO_REFERENCE";
export type AttachmentOwnership = "OWNED_CHILD" | "EXTERNAL_REFERENCE";
export interface ProvisioningAttachment {
  id: string;
  class: AttachmentClass;
  ownership: AttachmentOwnership;
  nativeId: string;
  attributes: Record<string, string | boolean | number | null>;
}

export interface TemplateImport {
  resourceId: string;
  imageId: string;
  imageManifestDigest: string;
  capabilities: string[];
  nonce: string;
  providerId: string;
  providerKind: string;
  providerResourceId: string;
  node: string | null;
  pool: string;
  attachments: ProvisioningAttachment[];
  state: "READY" | "UNKNOWN" | "QUARANTINED" | "RETIRED";
  createdAt: string;
}

export interface ProvisioningPlan {
  schemaVersion: 1;
  resourceId: string;
  templateResourceId: string;
  templateNonce: string;
  templateIntentDigest: string;
  imageManifestDigest: string;
  templateProviderId: string;
  templateProviderKind: string;
  templateProviderResourceId: string;
  templateNode: string | null;
  templatePool: string;
  templateAttachments: ProvisioningAttachment[];
  destinationNonce: string;
  providerId: string;
  providerKind: string;
  providerResourceId: string;
  node: string | null;
  pool: string;
  cloneMode: "FULL";
  attachments: ProvisioningAttachment[];
  canonicalDigest: string;
  createdAt: string;
}

export interface SafeProvenanceSummary {
  templateId: string;
  imageManifestDigest: string;
  planDigest: string;
  cloneMode: "FULL";
  attachmentClasses: AttachmentClass[];
}

export interface TrustedImageKey {
  publicKeyPem: string;
  allowedNames: string[];
  allowedCapabilities: string[];
  allowedArchitectures: Array<ImageManifest["arch"]>;
}
export type TrustedImageKeys = Readonly<Record<string, TrustedImageKey>>;
export interface ImageImportRequest {
  manifest: ImageManifest;
  signature: string;
  artifactBase64: string;
}

interface VerifiedImageManifest {
  policy: TrustedImageKey;
  publicKey: ReturnType<typeof createPublicKey>;
}

const identifier = /^[A-Za-z0-9._:-]{1,128}$/;
const digest = /^[a-f0-9]{64}$/;
export const maxInlineImageArtifactBytes = 128 * 1024;

export function validateTrustedImageKeys(keys: unknown): asserts keys is TrustedImageKeys {
  if (!keys || typeof keys !== "object" || Array.isArray(keys)) throw new Error("Trusted image keys must be an object");
  for (const [keyId, policy] of Object.entries(keys)) {
    if (!identifier.test(keyId) || !policy || typeof policy !== "object" || Array.isArray(policy)) throw new Error("Trusted image signer is invalid");
    const value = policy as Partial<TrustedImageKey>;
    if (typeof value.publicKeyPem !== "string" || !Array.isArray(value.allowedNames) || !Array.isArray(value.allowedCapabilities) || !Array.isArray(value.allowedArchitectures) || value.allowedNames.some((entry) => typeof entry !== "string" || !identifier.test(entry)) || value.allowedCapabilities.some((entry) => typeof entry !== "string" || !identifier.test(entry)) || value.allowedArchitectures.some((entry) => entry !== "amd64" && entry !== "arm64")) throw new Error("Trusted image signer is invalid");
    const publicKey = createPublicKey(value.publicKeyPem);
    if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("Trusted image signer is not Ed25519");
  }
}

export function canonicalImageManifest(manifest: ImageManifest): string {
  return JSON.stringify({
    schemaVersion: manifest.schemaVersion,
    name: manifest.name,
    version: manifest.version,
    arch: manifest.arch,
    artifactSha256: manifest.artifactSha256,
    artifactSize: manifest.artifactSize,
    sourceBuild: manifest.sourceBuild,
    capabilities: manifest.capabilities,
    keyId: manifest.keyId,
  });
}

/** Verifies manifest fields, signer policy, and the detached Ed25519 signature. */
export function verifyImageManifest(
  manifest: ImageManifest,
  signatureText: string,
  keys: TrustedImageKeys,
  maxArtifactBytes: number,
): VerifiedImageManifest {
  if (
    manifest.schemaVersion !== 1 ||
    !identifier.test(manifest.name) ||
    !identifier.test(manifest.version) ||
    !identifier.test(manifest.sourceBuild) ||
    !identifier.test(manifest.keyId) ||
    !digest.test(manifest.artifactSha256) ||
    !Number.isSafeInteger(manifest.artifactSize) ||
    manifest.artifactSize < 1 ||
    manifest.artifactSize > maxArtifactBytes ||
    !Array.isArray(manifest.capabilities) ||
    manifest.capabilities.length > 16 ||
    new Set(manifest.capabilities).size !== manifest.capabilities.length ||
    manifest.capabilities.some((capability) => !identifier.test(capability))
  ) throw new Error("Image manifest is invalid");
  try { validateTrustedImageKeys(keys); } catch { throw new Error("Image manifest signer is not trusted"); }
  const policy = keys[manifest.keyId];
  if (!policy) throw new Error("Image manifest signer is not trusted");
  if (!policy.allowedNames.includes(manifest.name) || !policy.allowedArchitectures.includes(manifest.arch) || manifest.capabilities.some((capability) => !policy.allowedCapabilities.includes(capability)))
    throw new Error("Image manifest exceeds signer policy");
  let publicKey;
  try { publicKey = createPublicKey(policy.publicKeyPem); } catch { throw new Error("Configured image signer is invalid"); }
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("Configured image signer is not Ed25519");
  const signature = decodeEd25519Signature(signatureText);
  if (!verify(null, Buffer.from(canonicalImageManifest(manifest)), publicKey, signature))
    throw new Error("Image manifest signature is invalid");
  return { policy, publicKey };
}

export function verifyImageImport(
  request: ImageImportRequest,
  keys: TrustedImageKeys,
  now: string,
): VerifiedImage {
  const manifest = request.manifest;
  const verification = verifyImageManifest(manifest, request.signature, keys, maxInlineImageArtifactBytes);
  let artifact: Buffer;
  try {
    artifact = Buffer.from(request.artifactBase64, "base64");
  } catch { throw new Error("Image import encoding is invalid"); }
  if (artifact.length !== manifest.artifactSize || artifact.length > maxInlineImageArtifactBytes)
    throw new Error("Image artifact does not match its manifest");
  if (createHash("sha256").update(artifact).digest("hex") !== manifest.artifactSha256)
    throw new Error("Image artifact digest does not match its manifest");
  return verifiedImage(manifest, verification, now);
}

function verifiedImage(manifest: ImageManifest, verification: VerifiedImageManifest, now: string): VerifiedImage {
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

function decodeEd25519Signature(value: string): Buffer {
  if (!/^[A-Za-z0-9+/]{86}==$/.test(value)) throw new Error("Image manifest signature is invalid");
  const signature = Buffer.from(value, "base64");
  if (signature.length !== 64) throw new Error("Image manifest signature is invalid");
  return signature;
}

export function canonicalPlanDigest(plan: Omit<ProvisioningPlan, "canonicalDigest">): string {
  return sha256(JSON.stringify({
    schemaVersion: plan.schemaVersion,
    resourceId: plan.resourceId,
    templateResourceId: plan.templateResourceId,
    templateNonce: plan.templateNonce,
    templateIntentDigest: plan.templateIntentDigest,
    imageManifestDigest: plan.imageManifestDigest,
    templateProviderId: plan.templateProviderId,
    templateProviderKind: plan.templateProviderKind,
    templateProviderResourceId: plan.templateProviderResourceId,
    templateNode: plan.templateNode,
    templatePool: plan.templatePool,
    templateAttachments: canonicalAttachmentEntries(plan.templateAttachments),
    destinationNonce: plan.destinationNonce,
    providerId: plan.providerId,
    providerKind: plan.providerKind,
    providerResourceId: plan.providerResourceId,
    node: plan.node,
    pool: plan.pool,
    cloneMode: plan.cloneMode,
    attachments: canonicalAttachmentEntries(plan.attachments),
    createdAt: plan.createdAt,
  }));
}

export function validAttachmentGraph(attachments: ProvisioningAttachment[]): boolean {
  const ids = new Set<string>();
  const nativeIds = new Set<string>();
  let boot = 0;
  for (const attachment of attachments) {
    if (!attachment || typeof attachment !== "object" || Object.keys(attachment).some((key) => !["id", "class", "ownership", "nativeId", "attributes"].includes(key)) || !identifier.test(attachment.id) || !identifier.test(attachment.nativeId) || ids.has(attachment.id) || nativeIds.has(attachment.nativeId)) return false;
    if (!["BOOT_VOLUME", "DATA_VOLUME", "CLOUD_INIT", "EFI", "TPM", "UNUSED_VOLUME", "NIC", "FIREWALL", "HA", "STORAGE_REFERENCE", "BRIDGE_REFERENCE", "ISO_REFERENCE"].includes(attachment.class) || !["OWNED_CHILD", "EXTERNAL_REFERENCE"].includes(attachment.ownership)) return false;
    ids.add(attachment.id);
    nativeIds.add(attachment.nativeId);
    if (!attachment.attributes || typeof attachment.attributes !== "object" || Array.isArray(attachment.attributes) || Object.keys(attachment.attributes).some((key) => !identifier.test(key) || !["string", "boolean", "number"].includes(typeof attachment.attributes[key]) || (typeof attachment.attributes[key] === "number" && !Number.isFinite(attachment.attributes[key])))) return false;
    if (attachment.class === "BOOT_VOLUME") {
      if (attachment.ownership !== "OWNED_CHILD") return false;
      boot += 1;
    }
    if (attachment.class === "DATA_VOLUME" && attachment.ownership === "EXTERNAL_REFERENCE") return false;
    if (attachment.class === "ISO_REFERENCE" && attachment.ownership !== "EXTERNAL_REFERENCE") return false;
    if (["STORAGE_REFERENCE", "BRIDGE_REFERENCE", "FIREWALL", "HA"].includes(attachment.class) && attachment.ownership !== "EXTERNAL_REFERENCE") return false;
  }
  return boot === 1;
}

export function canonicalAttachmentGraph(attachments: ProvisioningAttachment[]): string {
  return JSON.stringify(canonicalAttachmentEntries(attachments));
}

function canonicalAttachmentEntries(attachments: ProvisioningAttachment[]): Array<Record<string, unknown>> {
  return [...attachments].sort((left, right) => left.id.localeCompare(right.id)).map((attachment) => ({
    id: attachment.id,
    class: attachment.class,
    ownership: attachment.ownership,
    nativeId: attachment.nativeId,
    attributes: Object.fromEntries(Object.entries(attachment.attributes).sort(([left], [right]) => left.localeCompare(right))),
  }));
}

export function canonicalTemplateImportDigest(template: Pick<TemplateImport,
  "resourceId" | "imageId" | "imageManifestDigest" | "capabilities" | "nonce" |
  "providerId" | "providerKind" | "providerResourceId" | "node" | "pool" | "attachments"
>): string {
  return sha256(JSON.stringify({
    schemaVersion: 1,
    resourceId: template.resourceId,
    imageId: template.imageId,
    imageManifestDigest: template.imageManifestDigest,
    capabilities: [...template.capabilities],
    nonce: template.nonce,
    providerId: template.providerId,
    providerKind: template.providerKind,
    providerResourceId: template.providerResourceId,
    node: template.node,
    pool: template.pool,
    attachments: canonicalAttachmentEntries(template.attachments),
  }));
}

export function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}
