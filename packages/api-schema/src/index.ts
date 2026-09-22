import { z } from "zod";
export const resourceTypeSchema = z.enum([
  "development",
  "execution",
  "browser",
]);
export const gatewayCreateSchema = z.object({ node: z.string().min(1).max(128) }).strict();
export const doctorQuerySchema = z.object({ network: z.enum(["true", "false"]).optional(), node: z.string().min(1).max(128).optional() }).strict();
export const incidentsQuerySchema = z.object({ status: z.enum(["open", "all"]).default("open"), node: z.string().min(1).max(128).optional() }).strict();
export const resourceCreateSchema = z
  .object({
    type: resourceTypeSchema,
    projectId: z.string().min(1).default("default"),
    ttlSeconds: z.number().int().min(60).max(86400),
    profile: z.string().min(1).max(100).optional(),
    templateId: z.string().regex(/^tmpl_[a-f0-9]{32}$/).optional(),
  })
  .strict();
export const leaseSchema = z
  .object({
    ttlSeconds: z.number().int().min(60).max(86400),
  })
  .strict();
export const eventQuerySchema = z
  .object({
    after: z.coerce.number().int().min(0).default(0),
  })
  .strict();
const signalSchema = z.enum(["PASS", "FAIL", "UNKNOWN"]);
const identifierSchema = z.string().min(1).max(256).refine((value) => !/[\x00-\x1f\x7f\r\n]/.test(value));
export const gatewayEnrollmentSchema = z.object({
  installationId: identifierSchema,
  resourceId: identifierSchema,
  generation: identifierSchema,
  token: z.string().min(1).max(1024),
  publicKeyPem: z.string().min(1).max(8192),
  signature: z.string().min(1).max(2048),
}).strict();
export const gatewayChallengeSchema = z.object({ deviceId: identifierSchema }).strict();
export const gatewayRenewSchema = z.object({
  deviceId: identifierSchema,
  challengeId: identifierSchema,
  nonce: z.string().min(1).max(1024),
  signature: z.string().min(1).max(2048),
}).strict();
export const gatewayHeartbeatSchema = z.object({
  deviceId: identifierSchema,
  sequence: z.number().int().safe().min(1).max(2147483646),
  services: signalSchema,
  policy: signalSchema,
  reservation: signalSchema,
}).strict();
export const networkProbeCreateSchema = z.object({ profileId: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/) }).strict();
export const networkProbeResultSchema = z.object({
  planDigest: z.string().regex(/^[a-f0-9]{64}$/),
  results: z.array(z.object({
    id: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/),
    code: z.enum(["DNS_ANSWER", "DNS_EMPTY", "DNS_ERROR", "HTTPS_EXPECTED", "HTTPS_UNEXPECTED", "HTTPS_REDIRECT", "HTTPS_ERROR", "TCP_CONNECTED", "TCP_FAILED", "TIMEOUT"]),
    durationMs: z.number().int().min(0).max(30000),
  }).strict()).min(1).max(8),
}).strict();
export type ResourceCreateInput = z.infer<typeof resourceCreateSchema>;
const provenanceIdentifier = z.string().regex(/^[A-Za-z0-9._:-]{1,128}$/);
export const imageImportSchema = z.object({
  manifest: z.object({
    schemaVersion: z.literal(1),
    name: provenanceIdentifier,
    version: provenanceIdentifier,
    arch: z.enum(["amd64", "arm64"]),
    artifactSha256: z.string().regex(/^[a-f0-9]{64}$/),
    artifactSize: z.number().int().min(1).max(131072),
    sourceBuild: provenanceIdentifier,
    capabilities: z.array(provenanceIdentifier).max(16),
    keyId: provenanceIdentifier,
  }).strict(),
  signature: z.string().min(1).max(2048),
  artifactBase64: z.string().min(1).max(174764),
  node: z.string().min(1).max(128).optional(),
}).strict();
export const qualificationCreateSchema = imageImportSchema;
export const qualificationIdSchema = z.object({ id: z.string().regex(/^qual_[a-f0-9]{32}$/) }).strict();
export const linuxImportIdSchema = z.object({ id: z.string().regex(/^limp_[a-f0-9]{32}$/) }).strict();
export const linuxImportCreateSchema = z.object({
  stagingId: z.string().regex(/^lstg_[a-f0-9]{32}$/),
  manifest: z.object({ schemaVersion: z.literal(1), name: z.literal("kiln-dev-base"), version: provenanceIdentifier, arch: z.literal("amd64"), artifactSha256: z.string().regex(/^[a-f0-9]{64}$/), artifactSize: z.number().int().min(1).max(2147483648), sourceBuild: z.string().regex(/^sha256:[a-f0-9]{64}$/), capabilities: z.array(provenanceIdentifier).max(16), keyId: provenanceIdentifier }).strict(),
  signature: z.string().min(1).max(2048),
  buildMetadataBase64: z.string().min(1).max(1398104),
}).strict();
