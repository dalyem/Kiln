import { randomUUID } from "node:crypto";
import { and, asc, desc, eq, gt, inArray, lte, notInArray, sql } from "drizzle-orm";
import {
  integer,
  index,
  jsonb,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
} from "drizzle-orm/pg-core";
import { drizzle, type NodePgDatabase } from "drizzle-orm/node-postgres";
import { Pool, type PoolClient } from "pg";
import { readFile } from "node:fs/promises";
import { AsyncLocalStorage } from "node:async_hooks";
import { assertQualificationOwnership, canonicalAttachmentGraph, KilnError, qualificationPhases, type Event, type GatewayChallenge, type GatewayEnrollmentTokenRecord, type GatewayHealth, type GatewayIdentity, type GatewayIncident, type GatewayMetadata, type GatewaySignal, type LinuxImportAllocation, type LinuxImportPhase, type LinuxImportPhaseName, type LinuxImportPhaseStatus, type LinuxImportReceipt, type LinuxImportRun, type NetworkProbeRecord, type NetworkProbeResult, type Operation, type OperationSafeReason, type OperationSnapshot, type ProviderTaskHandle, type ProvisioningAttachment, type ProvisioningPlan, type QualificationPhase, type QualificationPhaseName, type QualificationReceipt, type QualificationRun, type Resource, type SafeProvenanceSummary, type Store, type TemplateImport, type VerifiedImage } from "@kiln/core";

export const installations = pgTable("installations", {
  id: text("id").primaryKey(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
});
export const resources = pgTable(
  "resources",
  {
    id: text("id").primaryKey(),
    installationId: text("installation_id").notNull(),
    projectId: text("project_id").notNull(),
    type: text("type").notNull(),
    ownership: text("ownership").notNull(),
    state: text("state").notNull(),
    providerId: text("provider_id").notNull(),
    providerResourceId: text("provider_resource_id").notNull(),
    providerKind: text("provider_kind").notNull(),
    node: text("node"),
    pool: text("pool").notNull(),
    createdBy: text("created_by").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    profile: text("profile"),
    provenanceRequired: integer("provenance_required").notNull().default(0),
  },
  (table) => [
    uniqueIndex("resources_provider_identity_kind").on(
      table.providerId,
      table.providerResourceId,
      table.providerKind,
    ),
  ],
);
export const idempotency = pgTable("idempotency", {
  key: text("key").primaryKey(),
  payload: text("payload").notNull(),
  resourceId: text("resource_id").notNull(),
});
export const events = pgTable("events", {
  id: integer("id").primaryKey().generatedAlwaysAsIdentity(),
  installationId: text("installation_id").notNull(),
  projectId: text("project_id"),
  resourceId: text("resource_id"),
  type: text("type").notNull(),
  timestamp: timestamp("timestamp", { withTimezone: true }).notNull(),
  payload: jsonb("payload").$type<Record<string, unknown>>().notNull(),
});
export const operations = pgTable("operations", {
  id: text("id").primaryKey(),
  resourceId: text("resource_id").notNull(),
  kind: text("kind").notNull(),
  status: text("status").notNull(),
  snapshot: jsonb("snapshot").$type<OperationSnapshot>(),
  taskHandle: jsonb("task_handle").$type<ProviderTaskHandle>(),
  safeReason: text("safe_reason"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
  submittedAt: timestamp("submitted_at", { withTimezone: true }),
  reconciliationDeadline: timestamp("reconciliation_deadline", { withTimezone: true }),
  completedAt: timestamp("completed_at", { withTimezone: true }),
});
export const leases = pgTable("leases", {
  resourceId: text("resource_id").primaryKey(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull(),
});
export const gateways = pgTable("gateways", {
  resourceId: text("resource_id").primaryKey(),
  node: text("node").notNull(),
  generation: text("generation").notNull(),
  expectedFingerprint: text("expected_fingerprint").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
});
export const gatewayHealth = pgTable("gateway_health", {
  resourceId: text("resource_id").primaryKey(),
  node: text("node").notNull(),
  status: text("status").notNull(),
  observedAt: timestamp("observed_at", { withTimezone: true }).notNull(),
  generation: text("generation"),
  expectedFingerprint: text("expected_fingerprint"),
  evidence: jsonb("evidence").$type<GatewayHealth["evidence"]>().notNull(),
});
export const gatewayIncidents = pgTable("gateway_incidents", {
  id: text("id").primaryKey(),
  node: text("node").notNull(),
  gatewayId: text("gateway_id"),
  code: text("code").notNull(),
  severity: text("severity").notNull(),
  status: text("status").notNull(),
  firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull(),
  lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull(),
  resolvedAt: timestamp("resolved_at", { withTimezone: true }),
  message: text("message").notNull(),
  guidance: jsonb("guidance").$type<string[]>().notNull(),
});
export const gatewayCa = pgTable("gateway_ca", {
  singleton: integer("singleton").primaryKey(),
  fingerprint: text("fingerprint").notNull(),
});
export const gatewayEnrollmentTokens = pgTable("gateway_enrollment_tokens", {
  resourceId: text("resource_id").primaryKey(),
  installationId: text("installation_id").notNull(),
  generation: text("generation").notNull(),
  tokenHash: text("token_hash").notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  publicKeyFingerprint: text("public_key_fingerprint"),
  deviceId: text("device_id"),
  certificateFingerprint: text("certificate_fingerprint"),
});
export const gatewayIdentities = pgTable("gateway_identities", {
  deviceId: text("device_id").primaryKey(),
  resourceId: text("resource_id").notNull(),
  installationId: text("installation_id").notNull(),
  generation: text("generation").notNull(),
  publicKeyPem: text("public_key_pem").notNull(),
  publicKeyFingerprint: text("public_key_fingerprint").notNull(),
  revokedAt: timestamp("revoked_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
  nextSequence: integer("next_sequence").notNull(),
  lastSeenAt: timestamp("last_seen_at", { withTimezone: true }),
  lastServices: text("last_services"),
  lastPolicy: text("last_policy"),
  lastReservation: text("last_reservation"),
}, (table) => [
  index("gateway_identities_resource_current").on(table.resourceId, table.createdAt.desc()),
  uniqueIndex("gateway_identities_one_active").on(table.resourceId).where(sql`${table.revokedAt} IS NULL`),
]);
export const gatewayCertificates = pgTable("gateway_certificates", {
  fingerprint: text("fingerprint").primaryKey(),
  deviceId: text("device_id").notNull(),
  certificatePem: text("certificate_pem").notNull(),
  issuedAt: timestamp("issued_at", { withTimezone: true }).notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  acceptedUntil: timestamp("accepted_until", { withTimezone: true }).notNull(),
  current: integer("current").notNull(),
});
export const gatewayChallenges = pgTable("gateway_challenges", {
  deviceId: text("device_id").primaryKey(),
  challengeId: text("challenge_id").notNull(),
  nonce: text("nonce").notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
});
export const networkProbes = pgTable("network_probes", {
  resourceId: text("resource_id").primaryKey(),
  installationId: text("installation_id").notNull(),
  gatewayId: text("gateway_id").notNull(),
  gatewayGeneration: text("gateway_generation").notNull(),
  gatewayConfigFingerprint: text("gateway_config_fingerprint").notNull(),
  node: text("node").notNull(),
  profileId: text("profile_id").notNull(),
  profileDigest: text("profile_digest").notNull(),
  plan: jsonb("plan").$type<NetworkProbeRecord["plan"]>().notNull(),
  planDigest: text("plan_digest").notNull(),
  state: text("state").notNull(),
  tokenHash: text("token_hash"),
  tokenExpiresAt: timestamp("token_expires_at", { withTimezone: true }),
  resultDigest: text("result_digest"),
  results: jsonb("results").$type<NetworkProbeResult[]>(),
  receivedAt: timestamp("received_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
});
export const provenanceImages = pgTable("provenance_images", {
  id: text("id").primaryKey(),
  manifest: jsonb("manifest").$type<VerifiedImage["manifest"]>().notNull(),
  manifestDigest: text("manifest_digest").notNull().unique(),
  signerFingerprint: text("signer_fingerprint").notNull(),
  policyDigest: text("policy_digest").notNull(),
  importedAt: timestamp("imported_at", { withTimezone: true }).notNull(),
});
export const templateImports = pgTable("template_imports", {
  resourceId: text("resource_id").primaryKey(),
  imageId: text("image_id").notNull(),
  imageManifestDigest: text("image_manifest_digest").notNull(),
  capabilities: jsonb("capabilities").$type<string[]>().notNull(),
  nonce: text("nonce").notNull().unique(),
  providerId: text("provider_id").notNull(),
  providerKind: text("provider_kind").notNull(),
  providerResourceId: text("provider_resource_id").notNull(),
  node: text("node"),
  pool: text("pool").notNull(),
  attachments: jsonb("attachments").$type<ProvisioningAttachment[]>().notNull(),
  state: text("state").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
});
export const provisioningPlans = pgTable("provisioning_plans", {
  resourceId: text("resource_id").primaryKey(),
  templateResourceId: text("template_resource_id").notNull(),
  canonicalDigest: text("canonical_digest").notNull().unique(),
  plan: jsonb("plan").$type<ProvisioningPlan>().notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
});
export const ownedAttachmentIdentities = pgTable("owned_attachment_identities", {
  nativeId: text("native_id").primaryKey(),
  resourceId: text("resource_id").notNull().references(() => resources.id, { onDelete: "restrict" }),
});
export const qualificationRuns = pgTable("qualification_runs", {
  id: text("id").primaryKey(),
  installationId: text("installation_id").notNull().unique(),
  idempotencyKey: text("idempotency_key").notNull(),
  normalizedPayload: text("normalized_payload").notNull(),
  status: text("status").notNull(),
  plan: jsonb("plan").$type<QualificationRun["plan"]>().notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
  completedAt: timestamp("completed_at", { withTimezone: true }),
});
export const qualificationPhaseRows = pgTable("qualification_phases", {
  runId: text("run_id").notNull().references(() => qualificationRuns.id, { onDelete: "restrict" }),
  name: text("name").notNull(),
  status: text("status").notNull(),
  intentDigest: text("intent_digest").notNull(),
  receipt: jsonb("receipt").$type<QualificationReceipt>(),
  safeReason: text("safe_reason"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
  reconciliationDeadline: timestamp("reconciliation_deadline", { withTimezone: true }).notNull(),
  submittedAt: timestamp("submitted_at", { withTimezone: true }),
  completedAt: timestamp("completed_at", { withTimezone: true }),
}, (table) => [uniqueIndex("qualification_phase_run_name").on(table.runId, table.name)]);
export const qualificationAllocations = pgTable("qualification_allocations", {
  id: text("id").primaryKey(),
  runId: text("run_id").notNull().references(() => qualificationRuns.id, { onDelete: "restrict" }),
  kind: text("kind").notNull(),
  identity: text("identity").notNull(),
  intentDigest: text("intent_digest").notNull(),
  state: text("state").notNull(),
  receipt: jsonb("receipt").$type<QualificationReceipt>(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
}, (table) => [uniqueIndex("qualification_allocation_run_kind").on(table.runId, table.kind)]);
export const linuxImportRuns = pgTable("linux_import_runs", {
  id: text("id").primaryKey(), installationId: text("installation_id").notNull(), idempotencyKey: text("idempotency_key").notNull(), normalizedPayload: text("normalized_payload").notNull(), status: text("status").notNull(), plan: jsonb("plan").$type<LinuxImportRun["plan"]>().notNull(), createdAt: timestamp("created_at", { withTimezone: true }).notNull(), completedAt: timestamp("completed_at", { withTimezone: true }),
});
export const linuxImportPhaseRows = pgTable("linux_import_phases", {
  runId: text("run_id").notNull(), name: text("name").notNull(), status: text("status").notNull(), intentDigest: text("intent_digest").notNull(), receipt: jsonb("receipt").$type<LinuxImportReceipt>(), safeReason: text("safe_reason"), createdAt: timestamp("created_at", { withTimezone: true }).notNull(), reconciliationDeadline: timestamp("reconciliation_deadline", { withTimezone: true }).notNull(), submittedAt: timestamp("submitted_at", { withTimezone: true }), completedAt: timestamp("completed_at", { withTimezone: true }),
}, (table) => [uniqueIndex("linux_import_phase_run_name").on(table.runId, table.name)]);
export const linuxImportAllocations = pgTable("linux_import_allocations", {
  id: text("id").primaryKey(), runId: text("run_id").notNull(), kind: text("kind").notNull(), identity: text("identity").notNull(), intentDigest: text("intent_digest").notNull(), state: text("state").notNull(), createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
}, (table) => [uniqueIndex("linux_import_allocation_run_kind").on(table.runId, table.kind), uniqueIndex("linux_import_allocation_identity").on(table.identity)]);
export const provisioningAttachments = pgTable("provisioning_attachments", {
  resourceId: text("resource_id").notNull(),
  attachmentId: text("attachment_id").notNull(),
  nativeId: text("native_id").notNull(),
  attachment: jsonb("attachment").$type<ProvisioningAttachment>().notNull(),
}, (table) => [
  uniqueIndex("provenance_attachment_resource_id").on(table.resourceId, table.attachmentId),
  uniqueIndex("provenance_owned_attachment_native_id").on(table.nativeId).where(sql`(${table.attachment}->>'ownership') = 'OWNED_CHILD'`),
]);
export function initialMigration(): Promise<string> {
  return readFile(
    new URL("../drizzle/0000_initial.sql", import.meta.url),
    "utf8",
  );
}
export async function gatewayMonitoringMigration(): Promise<string> {
  return readFile(new URL("../drizzle/0001_gateway_monitoring.sql", import.meta.url), "utf8");
}
export async function gatewayHealthAttestationMigration(): Promise<string> {
  return readFile(new URL("../drizzle/0002_gateway_health_attestation.sql", import.meta.url), "utf8");
}
export async function gatewayIdentityMigration(): Promise<string> {
  return readFile(new URL("../drizzle/0003_gateway_identity.sql", import.meta.url), "utf8");
}
export async function networkProbeMigration(): Promise<string> {
  return readFile(new URL("../drizzle/0004_network_probes.sql", import.meta.url), "utf8");
}
export async function providerOperationMigration(): Promise<string> {
  return readFile(new URL("../drizzle/0005_provider_operations.sql", import.meta.url), "utf8");
}
export async function imageProvenanceMigration(): Promise<string> {
  return readFile(new URL("../drizzle/0006_image_provenance.sql", import.meta.url), "utf8");
}
export async function proxmoxQualificationMigration(): Promise<string> {
  return readFile(new URL("../drizzle/0007_proxmox_qualification.sql", import.meta.url), "utf8");
}
export async function linuxImageImportMigration(): Promise<string> {
  return readFile(new URL("../drizzle/0008_linux_image_import.sql", import.meta.url), "utf8");
}
function toOperation(row: typeof operations.$inferSelect): Operation {
  return {
    id: row.id,
    resourceId: row.resourceId,
    kind: row.kind as Operation["kind"],
    status: row.status as Operation["status"],
    snapshot: row.snapshot ?? null,
    taskHandle: row.taskHandle ?? null,
    safeReason: row.safeReason as OperationSafeReason | null,
    createdAt: row.createdAt.toISOString(),
    submittedAt: row.submittedAt?.toISOString() ?? null,
    reconciliationDeadline: row.reconciliationDeadline?.toISOString() ?? null,
    completedAt: row.completedAt?.toISOString() ?? null,
  };
}
function qualificationRun(row: typeof qualificationRuns.$inferSelect): QualificationRun {
  return { id: row.id, installationId: row.installationId, idempotencyKey: row.idempotencyKey, normalizedPayload: row.normalizedPayload, status: row.status as QualificationRun["status"], plan: row.plan, createdAt: row.createdAt.toISOString(), completedAt: row.completedAt?.toISOString() ?? null };
}
function qualificationPhase(row: typeof qualificationPhaseRows.$inferSelect): QualificationPhase {
  return { runId: row.runId, name: row.name as QualificationPhaseName, status: row.status as QualificationPhase["status"], intentDigest: row.intentDigest, receipt: row.receipt ?? null, safeReason: row.safeReason, createdAt: row.createdAt.toISOString(), reconciliationDeadline: row.reconciliationDeadline.toISOString(), submittedAt: row.submittedAt?.toISOString() ?? null, completedAt: row.completedAt?.toISOString() ?? null };
}
function linuxImportRun(row: typeof linuxImportRuns.$inferSelect): LinuxImportRun { return { id: row.id, installationId: row.installationId, idempotencyKey: row.idempotencyKey, normalizedPayload: row.normalizedPayload, status: row.status as LinuxImportRun["status"], plan: row.plan, createdAt: row.createdAt.toISOString(), completedAt: row.completedAt?.toISOString() ?? null }; }
function linuxImportPhase(row: typeof linuxImportPhaseRows.$inferSelect): LinuxImportPhase { return { runId: row.runId, name: row.name as LinuxImportPhaseName, status: row.status as LinuxImportPhase["status"], intentDigest: row.intentDigest, receipt: row.receipt ?? null, safeReason: row.safeReason, createdAt: row.createdAt.toISOString(), reconciliationDeadline: row.reconciliationDeadline.toISOString(), submittedAt: row.submittedAt?.toISOString() ?? null, completedAt: row.completedAt?.toISOString() ?? null }; }
function toNetworkProbe(row: typeof networkProbes.$inferSelect): NetworkProbeRecord {
  return { resourceId: row.resourceId, installationId: row.installationId, gatewayId: row.gatewayId, gatewayGeneration: row.gatewayGeneration, gatewayConfigFingerprint: row.gatewayConfigFingerprint, node: row.node, profileId: row.profileId, profileDigest: row.profileDigest, plan: row.plan, planDigest: row.planDigest, state: row.state as NetworkProbeRecord["state"], tokenHash: row.tokenHash ?? null, tokenExpiresAt: row.tokenExpiresAt?.toISOString() ?? null, resultDigest: row.resultDigest ?? null, results: row.results ?? null, receivedAt: row.receivedAt?.toISOString() ?? null, createdAt: row.createdAt.toISOString() };
}

function toResource(row: typeof resources.$inferSelect): Resource {
  return {
    ...row,
    type: row.type as Resource["type"],
    ownership: row.ownership as Resource["ownership"],
    state: row.state as Resource["state"],
    createdAt: row.createdAt.toISOString(),
    expiresAt: row.expiresAt?.toISOString() ?? null,
    provenanceRequired: row.provenanceRequired === 1,
  };
}
function resourceValues(resource: Resource) {
  const { provenanceRequired, ...values } = resource;
  return { ...values, provenanceRequired: provenanceRequired ? 1 : 0, createdAt: new Date(resource.createdAt), expiresAt: resource.expiresAt ? new Date(resource.expiresAt) : null };
}
function toCertificate(row: typeof gatewayCertificates.$inferSelect): GatewayIdentity["currentCertificate"] {
  return { fingerprint: row.fingerprint, certificatePem: row.certificatePem, issuedAt: row.issuedAt.toISOString(), expiresAt: row.expiresAt.toISOString(), acceptedUntil: row.acceptedUntil.toISOString() };
}
async function identityFromDatabase(db: Pick<NodePgDatabase, "select">, resourceId: string): Promise<GatewayIdentity | null> {
  const rows = await db.select().from(gatewayIdentities).where(eq(gatewayIdentities.resourceId, resourceId)).orderBy(desc(gatewayIdentities.createdAt));
  const row = rows.find((candidate) => !candidate.revokedAt) ?? rows[0];
  if (!row) return null;
  const certificates = await db.select().from(gatewayCertificates).where(eq(gatewayCertificates.deviceId, row.deviceId));
  const current = certificates.find((certificate) => certificate.current === 1);
  if (!current) throw new Error("Gateway identity has no current certificate");
  const previous = certificates.find((certificate) => certificate.current === 0) ?? null;
  return { deviceId: row.deviceId, resourceId: row.resourceId, installationId: row.installationId, generation: row.generation, publicKeyPem: row.publicKeyPem, publicKeyFingerprint: row.publicKeyFingerprint, revokedAt: row.revokedAt?.toISOString() ?? null, createdAt: row.createdAt.toISOString(), currentCertificate: toCertificate(current), previousCertificate: previous ? toCertificate(previous) : null, nextSequence: row.nextSequence, lastSeenAt: row.lastSeenAt?.toISOString() ?? null, lastServices: row.lastServices as GatewaySignal | null, lastPolicy: row.lastPolicy as GatewaySignal | null, lastReservation: row.lastReservation as GatewaySignal | null };
}
function qualificationChildren(run: QualificationRun): Array<{ nativeId: string; resourceId: string }> {
  const p = run.plan;
  return [
    { nativeId: `${p.targetStorage}:vm-${p.templateVmid}-disk-0`, resourceId: p.templateResourceId },
    { nativeId: `${p.targetStorage}:${p.templateBootVolume}`, resourceId: p.templateResourceId },
    { nativeId: `${p.targetStorage}:${p.probeBootVolume}`, resourceId: p.probeResourceId },
  ];
}
function linuxImportChildren(run: LinuxImportRun): Array<{ nativeId: string; resourceId: string }> {
  const p = run.plan;
  return [
    { nativeId: `${p.targetStorage}:vm-${p.templateVmid}-disk-0`, resourceId: p.templateResourceId },
    { nativeId: `${p.targetStorage}:base-${p.templateVmid}-disk-0`, resourceId: p.templateResourceId },
    { nativeId: `${p.targetStorage}:vm-${p.cloneVmid}-disk-0`, resourceId: p.cloneResourceId },
  ];
}
function linuxImportDeadline(name: LinuxImportPhaseName, now: Date): Date {
  return new Date(now.getTime() + (name === "UPLOAD" ? 25 : 15) * 60_000);
}
function linuxImportAffectedAllocation(name: LinuxImportPhaseName): LinuxImportAllocation["kind"] | null {
  if (name === "UPLOAD") return "STAGING";
  if (["IMPORT", "TEMPLATE", "DESTROY_TEMPLATE"].includes(name)) return "TEMPLATE_DISK";
  if (["CLONE", "DESTROY_CLONE"].includes(name)) return "CLONE_DISK";
  return null;
}
export class MemoryStore implements Store {
  private installation: string | null = null;
  private readonly data = new Map<string, Resource>();
  private readonly keys = new Map<
    string,
    { payload: string; resourceId: string }
  >();
  private readonly log: Event[] = [];
  private readonly operationLog = new Map<string, Operation>();
  private readonly imageLog = new Map<string, VerifiedImage>();
  private readonly templateLog = new Map<string, TemplateImport>();
  private readonly planLog = new Map<string, ProvisioningPlan>();
  private readonly attachmentLog = new Map<string, ProvisioningAttachment[]>();
  private readonly attachmentOwners = new Map<string, string>();
  private readonly leaseLog = new Map<string, string>();
  private readonly gatewayLog = new Map<string, GatewayMetadata>();
  private readonly healthLog = new Map<string, GatewayHealth>();
  private readonly incidentLog = new Map<string, GatewayIncident>();
  private readonly gatewayCaFingerprint: { value: string | null } = { value: null };
  private readonly enrollmentTokens = new Map<string, GatewayEnrollmentTokenRecord>();
  private readonly identities = new Map<string, GatewayIdentity>();
  private readonly challenges = new Map<string, GatewayChallenge>();
  private readonly probeLog = new Map<string, NetworkProbeRecord>();
  private readonly qualificationRuns = new Map<string, QualificationRun>();
  private readonly qualificationPhases = new Map<string, QualificationPhase>();
  private readonly qualificationAllocations = new Map<string, import("@kiln/core").QualificationAllocation>();
  private readonly linuxImports = new Map<string, LinuxImportRun>();
  private readonly linuxImportPhases = new Map<string, LinuxImportPhase>();
  private readonly linuxImportAllocations = new Map<string, LinuxImportAllocation>();
  private readonly locks = new Map<string, Promise<void>>();
  private readonly operationLocks = new Map<string, Promise<void>>();
  private readonly eventBatch = new AsyncLocalStorage<{ events: Array<Omit<Event, "id">> }>();
  async initializeInstallation(configuredId?: string): Promise<string> {
    if (!this.installation) this.installation = configuredId ?? randomUUID();
    if (configuredId && configuredId !== this.installation)
      throw new Error(
        "Configured installation ID does not match persisted installation",
      );
    return this.installation;
  }
  async installationId(): Promise<string> {
    return this.initializeInstallation();
  }
  persistenceKind(): "memory" { return "memory"; }
  async getResource(id: string): Promise<Resource | null> {
    const resource = this.data.get(id);
    return resource ? structuredClone(resource) : null;
  }
  async listResources(projectId: string): Promise<Resource[]> {
    return [...this.data.values()].filter(
      (resource) => resource.projectId === projectId,
    ).map((resource) => structuredClone(resource));
  }
  async createResource(
    resource: Resource,
    key: string,
    payload: string,
  ): Promise<{ resource: Resource; replayed: boolean }> {
    if (resource.type === "gateway" || resource.type === "network_probe")
      throw new KilnError("SAFETY_DENIED", 403, "Gateway records require the protected gateway store path");
    const existing = this.keys.get(key);
    if (existing) {
      if (existing.payload !== payload)
        throw new KilnError("IDEMPOTENCY_CONFLICT", 409, "Idempotency key was used with a different request");
      return { resource: structuredClone(this.data.get(existing.resourceId)!), replayed: true };
    }
    this.data.set(resource.id, structuredClone(resource));
    this.keys.set(key, { payload, resourceId: resource.id });
    return { resource: structuredClone(resource), replayed: false };
  }
  async importVerifiedImage(input: { image: VerifiedImage; template: TemplateImport; resource: Resource; operation: Operation; attachments: ProvisioningAttachment[]; idempotencyKey: string; normalizedPayload: string; event: Omit<Event, "id"> }): Promise<{ template: TemplateImport; replayed: boolean }> {
    return this.withOperationLock("image-import-catalog", async () => {
    const existing = this.keys.get(input.idempotencyKey);
    if (existing) {
      if (existing.payload !== input.normalizedPayload) throw new KilnError("IDEMPOTENCY_CONFLICT", 409, "Idempotency key was used with a different request");
      const template = this.templateLog.get(existing.resourceId);
      if (!template) throw new Error("Image import idempotency record is incomplete");
      return { template: structuredClone(template), replayed: true };
    }
    for (const image of this.imageLog.values()) {
      if (image.manifest.name === input.image.manifest.name && image.manifest.version === input.image.manifest.version && image.manifest.arch === input.image.manifest.arch)
        throw new KilnError("CONFLICT", 409, "Image name, version, and architecture are already immutable");
    }
    if (this.imageLog.has(input.image.id) || this.templateLog.has(input.template.resourceId)) throw new Error("Image template already exists");
    for (const attachment of input.attachments) if (attachment.ownership === "OWNED_CHILD" && this.attachmentOwners.has(attachment.nativeId)) throw new KilnError("SAFETY_DENIED", 403, "Owned attachment already belongs to another resource");
    const batch = { events: [] as Array<Omit<Event, "id">> };
    await this.eventBatch.run(batch, async () => { await this.appendEvent(input.event); });
    this.data.set(input.resource.id, structuredClone(input.resource));
    this.imageLog.set(input.image.id, structuredClone(input.image));
    this.templateLog.set(input.template.resourceId, structuredClone({ ...input.template, state: "UNKNOWN" }));
    this.operationLog.set(input.operation.id, structuredClone(input.operation));
    for (const attachment of input.attachments) if (attachment.ownership === "OWNED_CHILD") this.attachmentOwners.set(attachment.nativeId, input.resource.id);
    this.keys.set(input.idempotencyKey, { payload: input.normalizedPayload, resourceId: input.resource.id });
    this.log.push(...batch.events.map((item, index) => ({ ...item, id: this.log.length + index + 1 })));
    return { template: structuredClone({ ...input.template, state: "UNKNOWN" }), replayed: false };
    });
  }
  async getTemplateImport(resourceId: string): Promise<TemplateImport | null> {
    const template = this.templateLog.get(resourceId);
    if (!template || template.attachments.some((attachment) => attachment.ownership === "OWNED_CHILD" && this.attachmentOwners.get(attachment.nativeId) !== resourceId)) return null;
    return structuredClone(template);
  }
  async getVerifiedImage(id: string): Promise<VerifiedImage | null> {
    const image = this.imageLog.get(id);
    return image ? structuredClone(image) : null;
  }
  async createLinuxImportRun(input: { run: LinuxImportRun; resources: Resource[]; allocations: LinuxImportAllocation[]; event: Omit<Event, "id"> }): Promise<{ run: LinuxImportRun; replayed: boolean }> {
    const vmids = [...new Set([input.run.plan.templateVmid, input.run.plan.cloneVmid])].sort();
    return this.withOperationLocks(vmids.map((vmid) => `linux-import-vmid:${input.run.installationId}:${vmid}`), async () => {
      const replay = [...this.linuxImports.values()].find((run) => run.installationId === input.run.installationId && run.idempotencyKey === input.run.idempotencyKey);
      if (replay) { if (replay.normalizedPayload !== input.run.normalizedPayload) throw new KilnError("CONFLICT", 409, "Linux image import idempotency key was reused"); return { run: structuredClone(replay), replayed: true }; }
      const existing = [...this.linuxImports.values()].find((run) => run.installationId === input.run.installationId && run.plan.stageId === input.run.plan.stageId);
      if (existing) throw new KilnError("CONFLICT", 409, "Linux image staging ID is already reserved");
      const children = linuxImportChildren(input.run);
      if (input.resources.length !== 2 || new Set(input.resources.map((resource) => `${resource.providerId}:${resource.providerKind}:${resource.providerResourceId}`)).size !== 2 || input.allocations.length !== 3 || new Set(input.allocations.map((allocation) => allocation.identity)).size !== 3 || input.resources.some((resource) => this.data.has(resource.id) || [...this.data.values()].some((existing) => existing.providerId === resource.providerId && existing.providerKind === resource.providerKind && existing.providerResourceId === resource.providerResourceId)) || children.some((child) => this.attachmentOwners.has(child.nativeId))) throw new KilnError("CONFLICT", 409, "Linux image import reservations conflict with an owned resource");
      await this.appendEvent(input.event);
      for (const resource of input.resources) this.data.set(resource.id, structuredClone(resource));
      for (const child of children) this.attachmentOwners.set(child.nativeId, child.resourceId);
      for (const allocation of input.allocations) this.linuxImportAllocations.set(allocation.id, structuredClone(allocation));
      this.linuxImports.set(input.run.id, structuredClone(input.run));
      return { run: structuredClone(input.run), replayed: false };
    });
  }
  async getLinuxImportRun(id: string): Promise<LinuxImportRun | null> { const run = this.linuxImports.get(id); return run ? structuredClone(run) : null; }
  async listActiveLinuxImportRuns(): Promise<LinuxImportRun[]> { return [...this.linuxImports.values()].filter((run) => run.status === "ACTIVE").map((run) => structuredClone(run)); }
  async listLinuxImportPhases(runId: string): Promise<LinuxImportPhase[]> { return [...this.linuxImportPhases.values()].filter((phase) => phase.runId === runId).map((phase) => structuredClone(phase)); }
  async getLinuxImportProof(id: string) { const run = this.linuxImports.get(id); if (!run) throw new KilnError("SAFETY_DENIED", 403, "Linux image import is missing"); return structuredClone({ resources: [run.plan.templateResourceId, run.plan.cloneResourceId].flatMap((resourceId) => this.data.has(resourceId) ? [this.data.get(resourceId)!] : []), allocations: [...this.linuxImportAllocations.values()].filter((allocation) => allocation.runId === id), children: linuxImportChildren(run).flatMap((child) => this.attachmentOwners.get(child.nativeId) === child.resourceId ? [child] : []), phases: [...this.linuxImportPhases.values()].filter((phase) => phase.runId === id) }); }
  async getLinuxImportPhase(runId: string, name: LinuxImportPhaseName): Promise<LinuxImportPhase | null> { const phase = this.linuxImportPhases.get(`${runId}:${name}`); return phase ? structuredClone(phase) : null; }
  async beginLinuxImportPhase(input: { runId: string; name: LinuxImportPhaseName; intentDigest: string; event: Omit<Event, "id"> }): Promise<{ phase: LinuxImportPhase; dispatch: boolean }> { return this.withOperationLock(`linux-import-run:${input.runId}`, async () => { const existing = this.linuxImportPhases.get(`${input.runId}:${input.name}`); if (existing) return { phase: structuredClone(existing), dispatch: false }; const run = this.linuxImports.get(input.runId); const index = (await import("@kiln/core")).linuxImportPhases.indexOf(input.name); if (!run || run.status !== "ACTIVE" || index < 0 || (await import("@kiln/core")).linuxImportPhases.slice(0, index).some((name) => this.linuxImportPhases.get(`${input.runId}:${name}`)?.status !== "COMPLETED") || [...this.linuxImportPhases.values()].some((phase) => phase.runId === input.runId && ["INTENT", "SUBMITTED"].includes(phase.status))) throw new KilnError("SAFETY_DENIED", 403, "Linux image import phase is out of order"); const now = new Date(); const phase: LinuxImportPhase = { runId: input.runId, name: input.name, status: "INTENT", intentDigest: input.intentDigest, receipt: null, safeReason: null, createdAt: now.toISOString(), reconciliationDeadline: linuxImportDeadline(input.name, now).toISOString(), submittedAt: null, completedAt: null }; await this.appendEvent(input.event); this.linuxImportPhases.set(`${input.runId}:${input.name}`, phase); return { phase: structuredClone(phase), dispatch: true }; }); }
  async submitLinuxImportPhase(runId: string, name: LinuxImportPhaseName, receipt: LinuxImportReceipt, event: Omit<Event, "id">): Promise<void> { await this.updateLinuxImportPhase(runId, name, "INTENT", { status: "SUBMITTED", receipt, submittedAt: new Date().toISOString() }, event); }
  async completeLinuxImportPhase(runId: string, name: LinuxImportPhaseName, event: Omit<Event, "id">, receiptPatch?: Pick<LinuxImportReceipt, "generatedUuid" | "generatedCtime" | "responseDigest" | "configDigest">): Promise<void> { await this.withOperationLock(`linux-import-run:${runId}`, async () => { const phase = this.linuxImportPhases.get(`${runId}:${name}`); const run = this.linuxImports.get(runId); if (!phase?.receipt || phase.status !== "SUBMITTED" || !run) throw new KilnError("SAFETY_DENIED", 403, "Linux image import receipt is missing"); const allocation = [...this.linuxImportAllocations.values()].find((item) => item.runId === runId && ((name === "UPLOAD" && item.kind === "STAGING") || (["IMPORT", "TEMPLATE", "DESTROY_TEMPLATE"].includes(name) && item.kind === "TEMPLATE_DISK") || (["CLONE", "DESTROY_CLONE"].includes(name) && item.kind === "CLONE_DISK"))); if ((["UPLOAD", "IMPORT", "TEMPLATE", "CLONE", "DESTROY_CLONE", "DESTROY_TEMPLATE"] as LinuxImportPhaseName[]).includes(name) && !allocation) throw new KilnError("SAFETY_DENIED", 403, "Linux image import allocation is missing"); await this.appendEvent(event); this.linuxImportPhases.set(`${runId}:${name}`, { ...phase, status: "COMPLETED", completedAt: new Date().toISOString(), receipt: { ...phase.receipt, ...(receiptPatch ?? {}) } }); if (allocation) { const state = name.startsWith("DESTROY") ? "DESTROYED" : "RETAINED"; const identity = name === "TEMPLATE" ? `${run.plan.targetStorage}:base-${run.plan.templateVmid}-disk-0` : allocation.identity; this.linuxImportAllocations.set(allocation.id, { ...allocation, state, identity }); } if (name === "DESTROY_CLONE" || name === "DESTROY_TEMPLATE") { const resourceId = name === "DESTROY_CLONE" ? run.plan.cloneResourceId : run.plan.templateResourceId; const resource = this.data.get(resourceId); if (!resource) throw new KilnError("SAFETY_DENIED", 403, "Linux image import resource is missing"); this.data.set(resourceId, { ...resource, state: "DESTROYED" }); } if (name === "DESTROY_TEMPLATE") this.linuxImports.set(runId, { ...run, status: "COMPLETED", completedAt: new Date().toISOString() }); }); }
  async markLinuxImportPhaseUnknown(runId: string, name: LinuxImportPhaseName, reason: string, event: Omit<Event, "id">): Promise<void> { const phase = this.linuxImportPhases.get(`${runId}:${name}`); if (!phase || !["INTENT", "SUBMITTED"].includes(phase.status)) return; await this.updateLinuxImportPhase(runId, name, phase.status, { status: "UNKNOWN", safeReason: reason }, event); }
  private async updateLinuxImportPhase(runId: string, name: LinuxImportPhaseName, expected: LinuxImportPhaseStatus, patch: Partial<LinuxImportPhase>, event: Omit<Event, "id">): Promise<void> { await this.withOperationLock(`linux-import-run:${runId}`, async () => { const phase = this.linuxImportPhases.get(`${runId}:${name}`); if (!phase || phase.status !== expected) throw new KilnError("SAFETY_DENIED", 403, "Linux image import phase changed concurrently"); const run = this.linuxImports.get(runId)!; if (patch.status === "UNKNOWN") { const kind = linuxImportAffectedAllocation(name); if (kind) { const allocation = [...this.linuxImportAllocations.values()].find((item) => item.runId === runId && item.kind === kind); if (allocation) this.linuxImportAllocations.set(allocation.id, { ...allocation, state: "UNKNOWN" }); } const resourceId = ["IMPORT", "TEMPLATE", "DESTROY_TEMPLATE"].includes(name) ? run.plan.templateResourceId : ["CLONE", "STAMP", "START", "STOP", "DESTROY_CLONE"].includes(name) ? run.plan.cloneResourceId : null; if (resourceId) { const resource = this.data.get(resourceId); if (resource) this.data.set(resource.id, { ...resource, state: "QUARANTINED" }); } this.linuxImports.set(runId, { ...run, status: "UNKNOWN" }); } await this.appendEvent(event); this.linuxImportPhases.set(`${runId}:${name}`, structuredClone({ ...phase, ...patch })); if (patch.status === "COMPLETED" && name === "DESTROY_TEMPLATE") this.linuxImports.set(runId, { ...run, status: "COMPLETED", completedAt: new Date().toISOString() }); }); }
  async createQualificationRun(input: { run: QualificationRun; resources: Resource[]; allocations: import("@kiln/core").QualificationAllocation[]; event: Omit<Event, "id"> }): Promise<{ run: QualificationRun; replayed: boolean }> {
    return this.withOperationLock(`qualification:${input.run.installationId}`, async () => {
      const existing = [...this.qualificationRuns.values()].find((run) => run.installationId === input.run.installationId);
      if (existing) {
        if (existing.idempotencyKey !== input.run.idempotencyKey || existing.normalizedPayload !== input.run.normalizedPayload) throw new KilnError("CONFLICT", 409, "An installation already has a qualification run");
        return { run: structuredClone(existing), replayed: true };
      }
      if (input.resources.length !== 2 || input.resources.some((resource) => this.data.has(resource.id))) throw new KilnError("SAFETY_DENIED", 403, "Qualification resources are invalid");
      const children = qualificationChildren(input.run);
      if (children.some((child) => this.attachmentOwners.has(child.nativeId))) throw new KilnError("SAFETY_DENIED", 403, "Qualification child already has an owner");
      await this.appendEvent(input.event);
      for (const child of children) this.attachmentOwners.set(child.nativeId, child.resourceId);
      this.qualificationRuns.set(input.run.id, structuredClone(input.run));
      for (const resource of input.resources) this.data.set(resource.id, structuredClone(resource));
      for (const allocation of input.allocations) this.qualificationAllocations.set(allocation.id, structuredClone(allocation));
      return { run: structuredClone(input.run), replayed: false };
    });
  }
  async getQualificationProof(runId: string) {
    return this.withOperationLock(`qualification-run:${runId}`, async () => this.qualificationProof(runId));
  }
  private qualificationProof(runId: string) {
      const run = this.qualificationRuns.get(runId);
      if (!run) throw new KilnError("SAFETY_DENIED", 403, "Qualification run is missing");
      return structuredClone({
        resources: [run.plan.templateResourceId, run.plan.probeResourceId].flatMap((id) => this.data.has(id) ? [this.data.get(id)!] : []),
        allocations: [...this.qualificationAllocations.values()].filter((row) => row.runId === runId),
        phases: [...this.qualificationPhases.values()].filter((row) => row.runId === runId),
        children: qualificationChildren(run).flatMap((child) => this.attachmentOwners.has(child.nativeId) ? [{ nativeId: child.nativeId, resourceId: this.attachmentOwners.get(child.nativeId)! }] : []),
      });
  }
  async getQualificationRun(runId: string): Promise<QualificationRun | null> { const run = this.qualificationRuns.get(runId); return run ? structuredClone(run) : null; }
  async getQualificationRunByInstallation(installationId: string): Promise<QualificationRun | null> { const run = [...this.qualificationRuns.values()].find((candidate) => candidate.installationId === installationId); return run ? structuredClone(run) : null; }
  async getQualificationPhase(runId: string, name: QualificationPhaseName): Promise<QualificationPhase | null> { const phase = this.qualificationPhases.get(`${runId}:${name}`); return phase ? structuredClone(phase) : null; }
  async listQualificationAllocations(runId: string): Promise<import("@kiln/core").QualificationAllocation[]> { return [...this.qualificationAllocations.values()].filter((allocation) => allocation.runId === runId).map((allocation) => structuredClone(allocation)); }
  async completeQualificationAllocation(runId: string, kind: "POOL" | "STAGING", receipt: QualificationReceipt | null): Promise<void> { await this.withOperationLock(`qualification-allocation:${runId}:${kind}`, async () => { const allocation = [...this.qualificationAllocations.values()].find((candidate) => candidate.runId === runId && candidate.kind === kind); if (!allocation || allocation.state !== "INTENT") throw new Error("Qualification allocation cannot complete"); this.qualificationAllocations.set(allocation.id, structuredClone({ ...allocation, state: "RETAINED", receipt: structuredClone(receipt) })); }); }
  async completeQualificationPhaseAndAllocation(runId: string, name: QualificationPhaseName, kind: "POOL" | "STAGING", event: Omit<Event, "id">, receiptPatch?: import("@kiln/core").QualificationInspection["receiptPatch"]): Promise<void> { await this.withOperationLock(`qualification-run:${runId}`, async () => { const phase = this.qualificationPhases.get(`${runId}:${name}`); const allocation = [...this.qualificationAllocations.values()].find((candidate) => candidate.runId === runId && candidate.kind === kind); if (phase?.status === "COMPLETED" && allocation?.state === "RETAINED") return; if (!phase || phase.status !== "SUBMITTED" || !allocation || allocation.state !== "INTENT") throw new Error("Qualification phase cannot complete atomically"); assertQualificationOwnership(this.qualificationRuns.get(runId)!, this.qualificationProof(runId)); await this.appendEvent(event); this.qualificationPhases.set(`${runId}:${name}`, structuredClone({ ...phase, status: "COMPLETED", completedAt: new Date().toISOString(), ...(receiptPatch ? { receipt: { ...phase.receipt!, ...receiptPatch } } : {}) })); this.qualificationAllocations.set(allocation.id, structuredClone({ ...allocation, state: "RETAINED", receipt: structuredClone({ ...phase.receipt!, ...(receiptPatch ?? {}) }) })); }); }
  async beginQualificationPhase(input: { runId: string; name: QualificationPhaseName; intentDigest: string; event: Omit<Event, "id"> }): Promise<{ phase: QualificationPhase; dispatch: boolean }> {
    return this.withOperationLock(`qualification-run:${input.runId}`, async () => {
      const key = `${input.runId}:${input.name}`; const existing = this.qualificationPhases.get(key);
      if (existing) return { phase: structuredClone(existing), dispatch: false };
      const run = this.qualificationRuns.get(input.runId); const phaseIndex = qualificationPhases.indexOf(input.name);
      if (!run || run.status !== "ACTIVE" || phaseIndex < 0 || qualificationPhases.slice(0, phaseIndex).some((name) => this.qualificationPhases.get(`${input.runId}:${name}`)?.status !== "COMPLETED") || [...this.qualificationPhases.values()].some((phase) => phase.runId === input.runId && ["INTENT", "SUBMITTED"].includes(phase.status))) throw new KilnError("SAFETY_DENIED", 403, "Qualification phase is out of order");
      assertQualificationOwnership(run, this.qualificationProof(input.runId));
      const phase: QualificationPhase = { runId: input.runId, name: input.name, status: "INTENT", intentDigest: input.intentDigest, receipt: null, safeReason: null, createdAt: new Date().toISOString(), reconciliationDeadline: new Date(Date.now() + 15 * 60_000).toISOString(), submittedAt: null, completedAt: null };
      await this.appendEvent(input.event); this.qualificationPhases.set(key, structuredClone(phase)); return { phase, dispatch: true };
    });
  }
  async submitQualificationPhase(runId: string, name: QualificationPhaseName, receipt: QualificationReceipt, event: Omit<Event, "id">): Promise<void> { await this.transitionQualificationPhase(runId, name, "INTENT", { status: "SUBMITTED", receipt: structuredClone(receipt), submittedAt: new Date().toISOString() }, event); }
  async completeQualificationPhase(runId: string, name: QualificationPhaseName, event: Omit<Event, "id">, receiptPatch?: import("@kiln/core").QualificationInspection["receiptPatch"]): Promise<void> { const phase = await this.getQualificationPhase(runId, name); if (phase?.status === "COMPLETED") return; if (!phase || phase.status !== "SUBMITTED") throw new Error("Qualification phase cannot complete"); await this.transitionQualificationPhase(runId, name, phase.status, { status: "COMPLETED", completedAt: new Date().toISOString(), ...(receiptPatch && phase.receipt ? { receipt: { ...phase.receipt, ...receiptPatch } } : {}) }, event); }
  async markQualificationPhaseUnknown(runId: string, name: QualificationPhaseName, reason: string, event: Omit<Event, "id">): Promise<void> { const phase = await this.getQualificationPhase(runId, name); if (!phase || !["INTENT", "SUBMITTED"].includes(phase.status)) return; await this.transitionQualificationPhase(runId, name, phase.status, { status: "UNKNOWN", safeReason: reason }, event); }
  private async transitionQualificationPhase(runId: string, name: QualificationPhaseName, expected: QualificationPhase["status"], patch: Partial<QualificationPhase>, event: Omit<Event, "id">): Promise<void> { await this.withOperationLock(`qualification-run:${runId}`, async () => { const key = `${runId}:${name}`; const current = this.qualificationPhases.get(key); if (current?.status === patch.status) return; if (!current || current.status !== expected) throw new Error("Qualification phase changed concurrently"); if (patch.status === "COMPLETED") assertQualificationOwnership(this.qualificationRuns.get(runId)!, this.qualificationProof(runId)); await this.appendEvent(event); this.qualificationPhases.set(key, structuredClone({ ...current, ...patch })); const run = this.qualificationRuns.get(runId); if (run && name === "DESTROY_PROBE" && patch.status === "COMPLETED") { const resource = this.data.get(run.plan.probeResourceId); if (resource) this.data.set(resource.id, { ...resource, state: "DESTROYED" }); } if (run && patch.status === "UNKNOWN") { this.qualificationRuns.set(runId, { ...run, status: "UNKNOWN" }); const kind = name === "POOL_CREATE" ? "POOL" : name === "UPLOAD" ? "STAGING" : null; if (kind) { const allocation = [...this.qualificationAllocations.values()].find((item) => item.runId === runId && item.kind === kind); if (allocation) this.qualificationAllocations.set(allocation.id, { ...allocation, state: "UNKNOWN", receipt: current.receipt }); } } if (run && name === "DESTROY_TEMPLATE" && patch.status === "COMPLETED") { this.qualificationRuns.set(runId, { ...run, status: "COMPLETED", completedAt: new Date().toISOString() }); for (const id of [run.plan.templateResourceId, run.plan.probeResourceId]) { const resource = this.data.get(id); if (resource) this.data.set(id, { ...resource, state: "DESTROYED" }); } } }); }
  async completeTemplateImport(resource: Resource, templateId: string, operationId: string, event: Omit<Event, "id">): Promise<void> {
    await this.withOperationLock(`template:${templateId}`, async () => {
      const template = this.templateLog.get(templateId);
      const operation = this.operationLog.get(operationId);
      if (!template || template.state !== "UNKNOWN" || !operation || operation.resourceId !== resource.id || resource.id !== templateId || !["INTENT", "SUBMITTED"].includes(operation.status)) throw new Error("Template import was not ready to complete");
      const batch = { events: [] as Array<Omit<Event, "id">> };
      await this.eventBatch.run(batch, async () => { await this.appendEvent(event); });
      if (this.templateLog.get(templateId)?.state !== "UNKNOWN" || !["INTENT", "SUBMITTED"].includes(this.operationLog.get(operationId)?.status ?? "")) throw new Error("Template import was not ready to complete");
      operation.status = "COMPLETED";
      operation.completedAt = new Date().toISOString();
      template.state = "READY";
      this.operationLog.set(operationId, structuredClone(operation));
      this.templateLog.set(templateId, structuredClone(template));
      this.data.set(resource.id, structuredClone(resource));
      this.log.push(...batch.events.map((item, index) => ({ ...item, id: this.log.length + index + 1 })));
    });
  }
  async createProvenancedResource(input: { resource: Resource; plan: ProvisioningPlan; idempotencyKey: string; normalizedPayload: string; operation: Operation; event: Omit<Event, "id"> }): Promise<{ resource: Resource; operation: Operation; replayed: boolean }> {
    return this.withOperationLock(`template:${input.plan.templateResourceId}`, async () => {
      const existing = this.keys.get(input.idempotencyKey);
      if (existing) {
        if (existing.payload !== input.normalizedPayload) throw new KilnError("IDEMPOTENCY_CONFLICT", 409, "Idempotency key was used with a different request");
        const resource = this.data.get(existing.resourceId);
        const operation = [...this.operationLog.values()].find((candidate) => candidate.resourceId === existing.resourceId && candidate.kind === "create");
        if (!resource || !operation) throw new Error("Provenance idempotency record is incomplete");
        return { resource: structuredClone(resource), operation: structuredClone(operation), replayed: true };
      }
      const template = this.templateLog.get(input.plan.templateResourceId);
      if (!template || template.state !== "READY") throw new KilnError("SAFETY_DENIED", 403, "Template is not eligible for provisioning");
      for (const attachment of input.plan.attachments) {
        if (attachment.ownership === "OWNED_CHILD" && this.attachmentOwners.has(attachment.nativeId))
          throw new KilnError("SAFETY_DENIED", 403, "Owned attachment already belongs to another resource");
      }
      const batch = { events: [] as Array<Omit<Event, "id">> };
      await this.eventBatch.run(batch, async () => { await this.appendEvent(input.event); });
      this.data.set(input.resource.id, structuredClone(input.resource));
      this.keys.set(input.idempotencyKey, { payload: input.normalizedPayload, resourceId: input.resource.id });
      this.planLog.set(input.resource.id, structuredClone(input.plan));
      this.attachmentLog.set(input.resource.id, structuredClone(input.plan.attachments));
      this.operationLog.set(input.operation.id, structuredClone(input.operation));
      for (const attachment of input.plan.attachments) if (attachment.ownership === "OWNED_CHILD") this.attachmentOwners.set(attachment.nativeId, input.resource.id);
      this.log.push(...batch.events.map((item, index) => ({ ...item, id: this.log.length + index + 1 })));
      return { resource: structuredClone(input.resource), operation: structuredClone(input.operation), replayed: false };
    });
  }
  async getProvisioningPlan(resourceId: string): Promise<ProvisioningPlan | null> {
    const plan = this.planLog.get(resourceId);
    const attachments = this.attachmentLog.get(resourceId);
    if (!plan || !attachments || canonicalAttachmentGraph(plan.attachments) !== canonicalAttachmentGraph(attachments)) return null;
    if (plan.attachments.some((attachment) => attachment.ownership === "OWNED_CHILD" && this.attachmentOwners.get(attachment.nativeId) !== resourceId)) return null;
    return structuredClone(plan);
  }
  async provenanceSummary(resourceId: string): Promise<SafeProvenanceSummary | null> {
    const plan = this.planLog.get(resourceId);
    return plan ? { templateId: plan.templateResourceId, imageManifestDigest: plan.imageManifestDigest, planDigest: plan.canonicalDigest, cloneMode: plan.cloneMode, attachmentClasses: plan.attachments.map((attachment) => attachment.class) } : null;
  }
  async retireTemplate(resourceId: string, event: Omit<Event, "id">): Promise<void> {
    await this.withOperationLock(`template:${resourceId}`, async () => {
      const template = this.templateLog.get(resourceId);
      if (!template) throw new KilnError("NOT_FOUND", 404, "Template was not found");
      if ([...this.operationLog.values()].some((operation) => operation.resourceId === resourceId && ["INTENT", "SUBMITTED", "UNKNOWN"].includes(operation.status))) throw new KilnError("CONFLICT", 409, "Template has an unresolved import operation");
      for (const plan of this.planLog.values()) {
        if (plan.templateResourceId !== resourceId) continue;
        const resource = this.data.get(plan.resourceId);
        const unresolved = [...this.operationLog.values()].some((operation) => operation.resourceId === plan.resourceId && ["INTENT", "SUBMITTED", "UNKNOWN"].includes(operation.status));
        if (!resource || resource.state !== "DESTROYED" || unresolved) throw new KilnError("CONFLICT", 409, "Template has live or unresolved clone plans");
      }
      const batch = { events: [] as Array<Omit<Event, "id">> };
      await this.eventBatch.run(batch, async () => { await this.appendEvent(event); });
      template.state = "RETIRED";
      this.templateLog.set(resourceId, structuredClone(template));
      this.log.push(...batch.events.map((item, index) => ({ ...item, id: this.log.length + index + 1 })));
    });
  }
  async idempotentResource(key: string, payload: string): Promise<Resource | null> {
    const existing = this.keys.get(key);
    if (!existing) return null;
    if (existing.payload !== payload)
      throw new KilnError("IDEMPOTENCY_CONFLICT", 409, "Idempotency key was used with a different request");
    const resource = this.data.get(existing.resourceId);
    return resource ? structuredClone(resource) : null;
  }
  async createNetworkProbe(resource: Resource, probe: NetworkProbeRecord, key: string, payload: string, savedEvent: Omit<Event, "id">): Promise<{ resource: Resource; probe: NetworkProbeRecord; replayed: boolean }> {
    const existing = this.keys.get(key);
    if (existing) {
      if (existing.payload !== payload) throw new KilnError("IDEMPOTENCY_CONFLICT", 409, "Idempotency key was used with a different request");
      const existingResource = this.data.get(existing.resourceId);
      const existingProbe = this.probeLog.get(existing.resourceId);
      if (!existingResource || !existingProbe) throw new Error("Network probe idempotency record is incomplete");
      return { resource: existingResource, probe: structuredClone(existingProbe), replayed: true };
    }
    const batch = { events: [] as Array<Omit<Event, "id">> };
    await this.eventBatch.run(batch, async () => { await this.appendEvent(savedEvent); });
    this.data.set(resource.id, structuredClone(resource));
    this.keys.set(key, { payload, resourceId: resource.id });
    this.probeLog.set(resource.id, structuredClone(probe));
    this.log.push(...batch.events.map((item, index) => ({ ...item, id: this.log.length + index + 1 })));
    return { resource: structuredClone(resource), probe: structuredClone(probe), replayed: false };
  }
  async getNetworkProbe(resourceId: string): Promise<NetworkProbeRecord | null> { const probe = this.probeLog.get(resourceId); return probe ? structuredClone(probe) : null; }
  async listNetworkProbes(gatewayId?: string): Promise<NetworkProbeRecord[]> { return [...this.probeLog.values()].filter((probe) => !gatewayId || probe.gatewayId === gatewayId).map((probe) => structuredClone(probe)); }
  async issueNetworkProbeToken(resourceId: string, hash: string, expiresAt: string, savedEvent: Omit<Event, "id">): Promise<void> {
    const probe = this.probeLog.get(resourceId); if (!probe) throw new KilnError("NOT_FOUND", 404, "Network probe not found");
    await this.commitGatewayMutation(savedEvent, () => { probe.tokenHash = hash; probe.tokenExpiresAt = expiresAt; this.probeLog.set(resourceId, structuredClone(probe)); });
  }
  async acceptNetworkProbeResult(input: { resourceId: string; planDigest: string; resultDigest: string; results: NetworkProbeResult[]; receivedAt: string; event: Omit<Event, "id"> }): Promise<{ probe: NetworkProbeRecord; replayed: boolean }> {
    const probe = this.probeLog.get(input.resourceId); if (!probe || probe.planDigest !== input.planDigest) throw new KilnError("CONFLICT", 409, "Network probe plan changed");
    if (probe.resultDigest) { if (probe.resultDigest !== input.resultDigest) throw new KilnError("CONFLICT", 409, "Network probe already has a different result"); return { probe: structuredClone(probe), replayed: true }; }
    await this.commitGatewayMutation(input.event, () => { probe.state = "COMPLETED"; probe.resultDigest = input.resultDigest; probe.results = structuredClone(input.results); probe.receivedAt = input.receivedAt; this.probeLog.set(input.resourceId, structuredClone(probe)); });
    return { probe: structuredClone(probe), replayed: false };
  }
  async timeoutNetworkProbe(resourceId: string, state: "TIMED_OUT" | "INVALIDATED" | "CANCELLED", savedEvent: Omit<Event, "id">): Promise<NetworkProbeRecord | null> {
    const probe = this.probeLog.get(resourceId); if (!probe || probe.state !== "PENDING") return probe ? structuredClone(probe) : null;
    await this.commitGatewayMutation(savedEvent, () => { probe.state = state; this.probeLog.set(resourceId, structuredClone(probe)); });
    return structuredClone(probe);
  }
  async expiredNetworkProbes(now: string): Promise<NetworkProbeRecord[]> { return [...this.probeLog.values()].filter((probe) => {
    const resource = this.data.get(probe.resourceId);
    if (!resource || ["DESTROYED", "QUARANTINED", "LOST"].includes(resource.state)) return false;
    return probe.state === "COMPLETED" || probe.state === "CANCELLED" || probe.state === "INVALIDATED" || ((probe.state === "PENDING" || probe.state === "TIMED_OUT") && probe.plan.expiresAt <= now);
  }).map((probe) => structuredClone(probe)); }
  async updateResource(resource: Resource): Promise<void> {
    this.data.set(resource.id, structuredClone(resource));
  }
  async appendEvent(event: Omit<Event, "id">): Promise<Event> {
    const batch = this.eventBatch.getStore();
    if (batch) {
      batch.events.push(event);
      return { ...event, id: 0 };
    }
    const saved = { ...event, id: this.log.length + 1 };
    this.log.push(saved);
    return saved;
  }
  async commitTransition(
    resource: Resource,
    event: Omit<Event, "id">,
  ): Promise<Event> {
    this.data.set(resource.id, structuredClone(resource));
    if (resource.expiresAt) this.leaseLog.set(resource.id, resource.expiresAt);
    return this.appendEvent(event);
  }
  async events(projectId: string, after: number): Promise<Event[]> {
    return this.log.filter(
      (event) => event.id > after && event.projectId === projectId,
    );
  }
  async expired(now: string): Promise<Resource[]> {
    return [...this.data.values()].filter(
      (r) =>
        r.ownership !== "EXTERNAL" &&
        r.type !== "gateway" &&
        r.expiresAt !== null &&
        r.expiresAt <= now &&
        !["DESTROYED", "LOST", "QUARANTINED"].includes(r.state),
    );
  }
  async beginOperation(
    operation: { resourceId: string; kind: Operation["kind"]; snapshot?: OperationSnapshot; reconciliationDeadline?: string; event?: Omit<Event, "id"> },
  ): Promise<Operation> {
    return this.withOperationLock(operation.resourceId, async () => {
      if (await this.unresolvedOperation(operation.resourceId))
        throw new KilnError("OPERATION_UNRESOLVED", 409, "Resource has an unresolved provider operation");
      const saved: Operation = {
        resourceId: operation.resourceId,
        kind: operation.kind,
        id: randomUUID(),
        status: "INTENT",
        snapshot: operation.snapshot ? structuredClone(operation.snapshot) : null,
        taskHandle: null,
        safeReason: null,
        createdAt: new Date().toISOString(),
        submittedAt: null,
        reconciliationDeadline: operation.reconciliationDeadline ?? null,
        completedAt: null,
      };
      const batch = { events: [] as Array<Omit<Event, "id">> };
      if (operation.event) await this.eventBatch.run(batch, async () => { await this.appendEvent(operation.event!); });
      if (await this.unresolvedOperation(operation.resourceId))
        throw new KilnError("OPERATION_UNRESOLVED", 409, "Resource has an unresolved provider operation");
      this.operationLog.set(saved.id, structuredClone(saved));
      this.log.push(...batch.events.map((item, index) => ({ ...item, id: this.log.length + index + 1 })));
      return structuredClone(saved);
    });
  }
  async listOperations(resourceId: string, limit?: number): Promise<Operation[]> {
    return [...this.operationLog.values()].filter((operation) => operation.resourceId === resourceId).sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, limit).map((operation) => structuredClone(operation));
  }
  async getOperation(id: string): Promise<Operation | null> { const operation = this.operationLog.get(id); return operation ? structuredClone(operation) : null; }
  async unresolvedOperation(resourceId: string): Promise<Operation | null> {
    const operation = [...this.operationLog.values()].find((candidate) => candidate.resourceId === resourceId && ["INTENT", "SUBMITTED", "UNKNOWN"].includes(candidate.status));
    return operation ? structuredClone(operation) : null;
  }
  async submittedOperations(): Promise<Operation[]> {
    return [...this.operationLog.values()].filter((operation) => operation.status === "SUBMITTED").map((operation) => structuredClone(operation));
  }
  async markOperationSubmitted(id: string, handle: ProviderTaskHandle, savedEvent: Omit<Event, "id">): Promise<void> {
    const batch = { events: [] as Array<Omit<Event, "id">> };
    await this.eventBatch.run(batch, async () => { await this.appendEvent(savedEvent); });
    const operation = this.operationLog.get(id);
    if (!operation || operation.status !== "INTENT") throw new Error("Operation was not ready to submit");
    operation.status = "SUBMITTED";
    operation.taskHandle = structuredClone(handle);
    operation.submittedAt = new Date().toISOString();
    this.log.push(...batch.events.map((item, index) => ({ ...item, id: this.log.length + index + 1 })));
  }
  async completeOperation(id: string): Promise<void> {
    const operation = this.operationLog.get(id);
    if (!operation || !["INTENT", "SUBMITTED"].includes(operation.status)) throw new Error("Operation was not ready to complete");
    operation.status = "COMPLETED";
    operation.completedAt = new Date().toISOString();
  }
  async completeOperationTransition(
    id: string,
    resource: Resource,
    event: Omit<Event, "id">,
  ): Promise<Event> {
    const batch = { events: [] as Array<Omit<Event, "id">> };
    await this.eventBatch.run(batch, async () => { await this.appendEvent(event); });
    const operation = this.operationLog.get(id);
    if (!operation || !["INTENT", "SUBMITTED"].includes(operation.status)) throw new Error("Operation was not ready to complete");
    operation.status = "COMPLETED";
    operation.completedAt = new Date().toISOString();
    this.data.set(resource.id, structuredClone(resource));
    if (resource.expiresAt) this.leaseLog.set(resource.id, resource.expiresAt);
    const saved = { ...batch.events[0]!, id: this.log.length + 1 };
    this.log.push(saved);
    return saved;
  }
  async completeNetworkProbeOperationTransition(id: string, resource: Resource, savedEvent: Omit<Event, "id">): Promise<Event> {
    const probe = this.probeLog.get(resource.id);
    if (!probe) throw new Error("Network probe not found");
    const batch = { events: [] as Array<Omit<Event, "id">> };
    await this.eventBatch.run(batch, async () => { await this.appendEvent(savedEvent); });
    const operation = this.operationLog.get(id);
    if (!operation || !["INTENT", "SUBMITTED"].includes(operation.status)) throw new Error("Operation was not ready to complete");
    operation.status = "COMPLETED";
    operation.completedAt = new Date().toISOString();
    this.data.set(resource.id, structuredClone(resource));
    if (resource.expiresAt) this.leaseLog.set(resource.id, resource.expiresAt);
    if (probe.state === "PENDING") { probe.state = "CANCELLED"; this.probeLog.set(resource.id, structuredClone(probe)); }
    const event = { ...batch.events[0]!, id: this.log.length + 1 };
    this.log.push(event);
    return event;
  }
  async markOperationUnknown(id: string, reason: OperationSafeReason = "DISPATCH_UNKNOWN", savedEvent?: Omit<Event, "id">): Promise<void> {
    const batch = { events: [] as Array<Omit<Event, "id">> };
    if (savedEvent) await this.eventBatch.run(batch, async () => { await this.appendEvent(savedEvent); });
    const operation = this.operationLog.get(id);
    if (!operation) throw new Error("Operation not found");
    if (operation.status === "COMPLETED") return;
    operation.status = "UNKNOWN";
    operation.safeReason = reason;
    this.log.push(...batch.events.map((item, index) => ({ ...item, id: this.log.length + index + 1 })));
  }
  async completedOperation(
    resourceId: string,
    kind: Operation["kind"],
  ): Promise<Operation | null> {
    const operation = [...this.operationLog.values()].find(
        (operation) =>
          operation.resourceId === resourceId &&
          operation.kind === kind &&
          operation.status === "COMPLETED",
      );
    return operation ? structuredClone(operation) : null;
  }
  async upsertLease(resourceId: string, expiresAt: string): Promise<void> {
    this.leaseLog.set(resourceId, expiresAt);
  }
  async createGateway(resource: Resource, metadata: GatewayMetadata, key: string, payload: string): Promise<{ resource: Resource; replayed: boolean }> {
    const existing = this.keys.get(key);
    if (existing) {
      if (existing.payload !== payload) throw new KilnError("IDEMPOTENCY_CONFLICT", 409, "Idempotency key was used with a different request");
      return { resource: structuredClone(this.data.get(existing.resourceId)!), replayed: true };
    }
    if ([...this.gatewayLog.values()].some((gateway) => gateway.node === metadata.node))
      throw new KilnError("CONFLICT", 409, "Gateway node already has a protected gateway");
    this.data.set(resource.id, structuredClone(resource));
    this.keys.set(key, { payload, resourceId: resource.id });
    this.gatewayLog.set(resource.id, metadata);
    return { resource: structuredClone(resource), replayed: false };
  }
  async getGateway(resourceId: string): Promise<GatewayMetadata | null> { return this.gatewayLog.get(resourceId) ?? null; }
  async listGateways(): Promise<Array<{ resource: Resource; metadata: GatewayMetadata; health: GatewayHealth | null }>> {
    return [...this.gatewayLog.values()].flatMap((metadata) => {
      const resource = this.data.get(metadata.resourceId);
      return resource ? [{ resource, metadata, health: this.healthLog.get(resource.id) ?? null }] : [];
    });
  }
  async saveGatewayScan(health: GatewayHealth, incidents: GatewayIncident[], eventsToSave: Array<Omit<Event, "id">>): Promise<void> {
    const batch = { events: [] as Array<Omit<Event, "id">> };
    await this.eventBatch.run(batch, async () => {
      for (const event of eventsToSave) await this.appendEvent(event);
    });
    const savedEvents = batch.events.map((event, index) => ({
      ...event,
      id: this.log.length + index + 1,
    }));
    this.healthLog.set(health.resourceId, health);
    for (const incident of incidents) this.incidentLog.set(incident.id, incident);
    this.log.push(...savedEvents);
  }
  async listGatewayIncidents(node?: string): Promise<GatewayIncident[]> {
    return [...this.incidentLog.values()].filter((incident) => !node || incident.node === node);
  }
  async bindGatewayCaFingerprint(fingerprint: string): Promise<void> {
    if (this.gatewayCaFingerprint.value && this.gatewayCaFingerprint.value !== fingerprint)
      throw new Error("Configured gateway CA does not match the persisted gateway CA fingerprint");
    this.gatewayCaFingerprint.value = fingerprint;
  }
  async issueGatewayEnrollmentToken(token: GatewayEnrollmentTokenRecord, savedEvent: Omit<Event, "id">): Promise<void> {
    await this.commitGatewayMutation(savedEvent, () => this.enrollmentTokens.set(token.resourceId, { ...token }));
  }
  async getGatewayEnrollmentToken(resourceId: string): Promise<GatewayEnrollmentTokenRecord | null> {
    const token = this.enrollmentTokens.get(resourceId);
    return token ? structuredClone(token) : null;
  }
  async getGatewayIdentity(resourceId: string): Promise<GatewayIdentity | null> {
    const identity = this.identities.get(resourceId);
    return identity ? structuredClone(identity) : null;
  }
  async getGatewayCertificate(fingerprint: string): Promise<GatewayIdentity["currentCertificate"] | null> {
    for (const identity of this.identities.values()) {
      for (const certificate of [identity.currentCertificate, identity.previousCertificate]) if (certificate?.fingerprint === fingerprint) return structuredClone(certificate);
    }
    return null;
  }
  async gatewayIdentityRequired(resourceId: string): Promise<boolean> { return this.enrollmentTokens.has(resourceId) || this.identities.has(resourceId); }
  async enrollGatewayIdentity(input: { tokenHash: string; publicKeyPem: string; publicKeyFingerprint: string; identity: GatewayIdentity; event: Omit<Event, "id">; now: string }): Promise<{ identity: GatewayIdentity; certificate: GatewayIdentity["currentCertificate"]; replayed: boolean }> {
    const token = this.enrollmentTokens.get(input.identity.resourceId);
    if (!token || token.tokenHash !== input.tokenHash || Date.parse(token.expiresAt) < Date.parse(input.now))
      throw new KilnError("UNAUTHENTICATED", 401, "Gateway enrollment token is invalid or expired");
    const existing = this.identities.get(input.identity.resourceId);
    if (existing && !existing.revokedAt) {
      if (token.publicKeyFingerprint !== input.publicKeyFingerprint || existing.publicKeyFingerprint !== input.publicKeyFingerprint || Date.parse(existing.currentCertificate.expiresAt) < Date.parse(input.now))
        throw new KilnError("UNAUTHENTICATED", 401, "Gateway enrollment token cannot be replayed");
      const certificate = [existing.currentCertificate, existing.previousCertificate].find((candidate) => candidate?.fingerprint === token.certificateFingerprint);
      if (!certificate) throw new KilnError("UNAUTHENTICATED", 401, "Gateway enrollment token cannot be replayed");
      return { identity: structuredClone(existing), certificate: structuredClone(certificate), replayed: true };
    }
    await this.commitGatewayMutation(input.event, () => {
      token.publicKeyFingerprint = input.publicKeyFingerprint;
      token.deviceId = input.identity.deviceId;
      token.certificateFingerprint = input.identity.currentCertificate.fingerprint;
      this.identities.set(input.identity.resourceId, structuredClone(input.identity));
    });
    return { identity: structuredClone(input.identity), certificate: structuredClone(input.identity.currentCertificate), replayed: false };
  }
  async issueGatewayChallenge(input: GatewayChallenge, now: string): Promise<GatewayChallenge> {
    const existing = this.challenges.get(input.deviceId);
    if (existing && Date.parse(existing.expiresAt) >= Date.parse(now)) return structuredClone(existing);
    this.challenges.set(input.deviceId, structuredClone(input));
    return input;
  }
  async renewGatewayIdentity(input: { identity: GatewayIdentity; challengeId: string; nonce: string; event: Omit<Event, "id">; now: string }): Promise<GatewayIdentity> {
    const challenge = this.challenges.get(input.identity.deviceId);
    if (!challenge || challenge.challengeId !== input.challengeId || challenge.nonce !== input.nonce || Date.parse(challenge.expiresAt) < Date.parse(input.now))
      throw new KilnError("UNAUTHENTICATED", 401, "Gateway renewal challenge is invalid or expired");
    const current = this.identities.get(input.identity.resourceId);
    if (!current || current.deviceId !== input.identity.deviceId || current.revokedAt)
      throw new KilnError("UNAUTHENTICATED", 401, "Gateway identity is not authorized");
    await this.commitGatewayMutation(input.event, () => {
      this.challenges.delete(input.identity.deviceId);
      this.identities.set(input.identity.resourceId, structuredClone(input.identity));
    });
    return structuredClone(input.identity);
  }
  async revokeGatewayIdentity(resourceId: string, revokedAt: string, savedEvent: Omit<Event, "id">): Promise<void> {
    const identity = this.identities.get(resourceId);
    await this.commitGatewayMutation(savedEvent, () => {
      if (identity) { identity.revokedAt = revokedAt; this.identities.set(resourceId, identity); }
      const token = this.enrollmentTokens.get(resourceId);
      if (token) this.enrollmentTokens.set(resourceId, { ...token, tokenHash: "", expiresAt: revokedAt, publicKeyFingerprint: null, deviceId: null, certificateFingerprint: null });
    });
  }
  async recordGatewayHeartbeat(input: { deviceId: string; certificateFingerprint: string; sequence: number; services: GatewaySignal; policy: GatewaySignal; reservation: GatewaySignal; receivedAt: string; event: Omit<Event, "id"> }): Promise<GatewayIdentity> {
    const current = [...this.identities.values()].find((identity) => identity.deviceId === input.deviceId);
    if (!current || current.revokedAt || input.sequence < current.nextSequence)
      throw new KilnError("UNAUTHENTICATED", 401, "Gateway heartbeat is not authorized");
    const validCertificate = [current.currentCertificate, current.previousCertificate].filter((certificate): certificate is NonNullable<typeof certificate> => Boolean(certificate)).some((certificate) => certificate.fingerprint === input.certificateFingerprint && Date.parse(certificate.acceptedUntil) >= Date.parse(input.receivedAt));
    if (!validCertificate) throw new KilnError("UNAUTHENTICATED", 401, "Gateway certificate is not authorized");
    await this.commitGatewayMutation(input.event, () => {
      current.nextSequence = input.sequence + 1;
      current.lastSeenAt = input.receivedAt;
      current.lastServices = input.services;
      current.lastPolicy = input.policy;
      current.lastReservation = input.reservation;
      this.identities.set(current.resourceId, current);
    });
    return structuredClone(current);
  }
  private async commitGatewayMutation(event: Omit<Event, "id">, mutate: () => void): Promise<void> {
    const batch = { events: [] as Array<Omit<Event, "id">> };
    await this.eventBatch.run(batch, async () => { await this.appendEvent(event); });
    mutate();
    this.log.push(...batch.events.map((saved, index) => ({ ...saved, id: this.log.length + index + 1 })));
  }
  private async withOperationLock<T>(id: string, task: () => Promise<T>): Promise<T> {
    const previous = this.operationLocks.get(id) ?? Promise.resolve();
    let release!: () => void;
    const next = new Promise<void>((resolve) => {
      release = resolve;
    });
    this.operationLocks.set(id, next);
    await previous;
    try {
      return await task();
    } finally {
      release();
      if (this.operationLocks.get(id) === next) this.operationLocks.delete(id);
    }
  }
  private async withOperationLocks<T>(ids: string[], task: () => Promise<T>): Promise<T> {
    const [id, ...rest] = ids;
    if (!id) return task();
    return this.withOperationLock(id, () => this.withOperationLocks(rest, task));
  }
  async withResourceLock<T>(id: string, task: () => Promise<T>): Promise<T> {
    const previous = this.locks.get(id) ?? Promise.resolve();
    let release!: () => void;
    const next = new Promise<void>((resolve) => {
      release = resolve;
    });
    this.locks.set(id, next);
    await previous;
    try {
      return await task();
    } finally {
      release();
      if (this.locks.get(id) === next) this.locks.delete(id);
    }
  }
}
function linuxImportDefersRecovery(
  resource: typeof resources.$inferSelect,
  runs: Array<{ installationId: string; plan: LinuxImportRun["plan"] }>,
): boolean {
  if (
    resource.createdBy !== "linux-image-import" ||
    resource.profile !== "proxmox-linux-image-import" ||
    resource.providerId !== "proxmox" ||
    resource.providerKind !== "qemu" ||
    resource.provenanceRequired !== 1 ||
    resource.ownership !== "KILN_MANAGED" ||
    resource.projectId !== "infrastructure" ||
    resource.expiresAt !== null
  )
    return false;
  return runs.some((run) => {
    if (
      run.installationId !== resource.installationId ||
      run.plan.installationId !== resource.installationId
    )
      return false;
    const template = resource.id === run.plan.templateResourceId;
    const clone = resource.id === run.plan.cloneResourceId;
    if (template === clone) return false;
    return (
      resource.type === (template ? "image_template" : "execution") &&
      resource.providerResourceId ===
        (template ? run.plan.templateVmid : run.plan.cloneVmid) &&
      resource.node === run.plan.node &&
      resource.pool === run.plan.pool
    );
  });
}
export class DrizzleStore implements Store {
  private readonly db: NodePgDatabase;
  private readonly pool: Pool;
  private writerClient: PoolClient | null = null;
  private readonly locks = new Map<string, Promise<void>>();
  constructor(databaseUrl: string) {
    this.pool = new Pool({ connectionString: databaseUrl });
    this.db = drizzle(this.pool);
  }
  async initializeInstallation(configuredId?: string): Promise<string> {
    const found = await this.db.select().from(installations).limit(1);
    if (found[0]) {
      if (configuredId && configuredId !== found[0].id)
        throw new Error(
          "Configured installation ID does not match persisted installation",
        );
      return found[0].id;
    }
    const id = configuredId ?? randomUUID();
    await this.db.insert(installations).values({ id, createdAt: new Date() });
    return id;
  }
  async installationId(): Promise<string> {
    return this.initializeInstallation();
  }
  persistenceKind(): "postgres" { return "postgres"; }
  async getResource(id: string): Promise<Resource | null> {
    const row = (
      await this.db
        .select()
        .from(resources)
        .where(eq(resources.id, id))
        .limit(1)
    )[0];
    return row ? toResource(row) : null;
  }
  async listResources(projectId: string): Promise<Resource[]> {
    return (
      await this.db
        .select()
        .from(resources)
        .where(eq(resources.projectId, projectId))
    ).map(toResource);
  }
  async createResource(
    resource: Resource,
    key: string,
    payload: string,
  ): Promise<{ resource: Resource; replayed: boolean }> {
    if (resource.type === "gateway" || resource.type === "network_probe")
      throw new KilnError("SAFETY_DENIED", 403, "Gateway records require the protected gateway store path");
    return this.db.transaction(async (tx) => {
      await tx.insert(resources).values(resourceValues(resource));
      const reservation = await tx
        .insert(idempotency)
        .values({ key, payload, resourceId: resource.id })
        .onConflictDoNothing()
        .returning();
      if (!reservation[0]) {
        await tx.delete(resources).where(eq(resources.id, resource.id));
        const existing = (
          await tx
            .select()
            .from(idempotency)
            .where(eq(idempotency.key, key))
            .limit(1)
        )[0]!;
        if (existing.payload !== payload)
          throw new KilnError("IDEMPOTENCY_CONFLICT", 409, "Idempotency key was used with a different request");
        const row = (
          await tx
            .select()
            .from(resources)
            .where(eq(resources.id, existing.resourceId))
            .limit(1)
        )[0];
        if (!row) throw new Error("Idempotency record references no resource");
        return { resource: toResource(row), replayed: true };
      }
      return { resource, replayed: false };
    });
  }
  async importVerifiedImage(input: { image: VerifiedImage; template: TemplateImport; resource: Resource; operation: Operation; attachments: ProvisioningAttachment[]; idempotencyKey: string; normalizedPayload: string; event: Omit<Event, "id"> }): Promise<{ template: TemplateImport; replayed: boolean }> {
    return this.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`image-import:${input.idempotencyKey}`}))`);
      await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`image-version:${input.image.manifest.name}:${input.image.manifest.version}:${input.image.manifest.arch}`}))`);
      const existing = (await tx.select().from(idempotency).where(eq(idempotency.key, input.idempotencyKey)).limit(1))[0];
      if (existing) {
        if (existing.payload !== input.normalizedPayload) throw new KilnError("IDEMPOTENCY_CONFLICT", 409, "Idempotency key was used with a different request");
        const template = (await tx.select().from(templateImports).where(eq(templateImports.resourceId, existing.resourceId)).limit(1))[0];
        if (!template) throw new Error("Image import idempotency record is incomplete");
        return { template: { ...template, node: template.node ?? null, capabilities: template.capabilities, attachments: template.attachments, createdAt: template.createdAt.toISOString(), state: template.state as TemplateImport["state"] }, replayed: true };
      }
      const catalog = await tx.select().from(provenanceImages);
      if (catalog.some((image) => image.manifest.name === input.image.manifest.name && image.manifest.version === input.image.manifest.version && image.manifest.arch === input.image.manifest.arch))
        throw new KilnError("CONFLICT", 409, "Image name, version, and architecture are already immutable");
      const templateOwnedIds = input.attachments.filter((attachment) => attachment.ownership === "OWNED_CHILD").map((attachment) => attachment.nativeId);
      if (templateOwnedIds.length && (await tx.select().from(ownedAttachmentIdentities).where(inArray(ownedAttachmentIdentities.nativeId, templateOwnedIds)).limit(1))[0]) throw new KilnError("SAFETY_DENIED", 403, "Owned attachment already belongs to another resource");
      await tx.insert(resources).values(resourceValues({ ...input.resource, expiresAt: null }));
      await tx.insert(provenanceImages).values({ id: input.image.id, manifest: input.image.manifest, manifestDigest: input.image.manifestDigest, signerFingerprint: input.image.signerFingerprint, policyDigest: input.image.policyDigest, importedAt: new Date(input.image.importedAt) });
      await tx.insert(templateImports).values({ ...input.template, capabilities: input.template.capabilities, attachments: input.attachments, state: "UNKNOWN", createdAt: new Date(input.template.createdAt) });
      if (templateOwnedIds.length) await tx.insert(ownedAttachmentIdentities).values(templateOwnedIds.map((nativeId) => ({ nativeId, resourceId: input.resource.id })));
      await tx.insert(operations).values({ ...input.operation, createdAt: new Date(input.operation.createdAt), submittedAt: null, reconciliationDeadline: input.operation.reconciliationDeadline ? new Date(input.operation.reconciliationDeadline) : null, completedAt: null });
      await tx.insert(idempotency).values({ key: input.idempotencyKey, payload: input.normalizedPayload, resourceId: input.resource.id });
      await tx.insert(events).values({ ...input.event, timestamp: new Date(input.event.timestamp) });
      return { template: { ...input.template, state: "UNKNOWN" }, replayed: false };
    });
  }
  async getTemplateImport(resourceId: string): Promise<TemplateImport | null> {
    const row = (await this.db.select().from(templateImports).where(eq(templateImports.resourceId, resourceId)).limit(1))[0];
    if (!row) return null;
    const owned = row.attachments.filter((attachment) => attachment.ownership === "OWNED_CHILD").map((attachment) => attachment.nativeId);
    const identities = owned.length ? await this.db.select().from(ownedAttachmentIdentities).where(inArray(ownedAttachmentIdentities.nativeId, owned)) : [];
    if (identities.length !== owned.length || identities.some((identity) => identity.resourceId !== resourceId)) return null;
    return { ...row, node: row.node ?? null, capabilities: row.capabilities, attachments: row.attachments, createdAt: row.createdAt.toISOString(), state: row.state as TemplateImport["state"] };
  }
  async getVerifiedImage(id: string): Promise<VerifiedImage | null> {
    const row = (await this.db.select().from(provenanceImages).where(eq(provenanceImages.id, id)).limit(1))[0];
    return row ? { id: row.id, manifest: row.manifest, manifestDigest: row.manifestDigest, signerFingerprint: row.signerFingerprint, policyDigest: row.policyDigest, importedAt: row.importedAt.toISOString() } : null;
  }
  async createLinuxImportRun(input: { run: LinuxImportRun; resources: Resource[]; allocations: LinuxImportAllocation[]; event: Omit<Event, "id"> }): Promise<{ run: LinuxImportRun; replayed: boolean }> {
    return this.db.transaction(async (tx) => {
      const vmids = [...new Set([input.run.plan.templateVmid, input.run.plan.cloneVmid])].sort();
      for (const vmid of vmids) await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`linux-import-vmid:${input.run.installationId}:${vmid}`}))`);
      await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`linux-import-stage:${input.run.installationId}:${input.run.plan.stageId}`}))`);
      await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`linux-import-idempotency:${input.run.installationId}:${input.run.idempotencyKey}`}))`);
      const old = (await tx.select().from(linuxImportRuns).where(and(eq(linuxImportRuns.installationId, input.run.installationId), eq(linuxImportRuns.idempotencyKey, input.run.idempotencyKey))).limit(1))[0];
      if (old) {
        if (old.normalizedPayload !== input.run.normalizedPayload) throw new KilnError("CONFLICT", 409, "Linux image import idempotency key was reused");
        return { run: linuxImportRun(old), replayed: true };
      }
      const stage = (await tx.select().from(linuxImportRuns).where(and(eq(linuxImportRuns.installationId, input.run.installationId), sql`${linuxImportRuns.plan}->>'stageId' = ${input.run.plan.stageId}`)).limit(1))[0];
      if (stage) throw new KilnError("CONFLICT", 409, "Linux image staging ID is already reserved");
      const children = linuxImportChildren(input.run);
      const conflicts = await tx.select().from(ownedAttachmentIdentities).where(inArray(ownedAttachmentIdentities.nativeId, children.map((item) => item.nativeId))).limit(1);
      const vmidConflict = await tx.select().from(resources).where(and(eq(resources.providerId, "proxmox"), eq(resources.providerKind, "qemu"), inArray(resources.providerResourceId, vmids))).limit(1);
      if (input.resources.length !== 2 || vmids.length !== 2 || input.allocations.length !== 3 || new Set(input.allocations.map((item) => item.identity)).size !== 3 || conflicts[0] || vmidConflict[0]) throw new KilnError("CONFLICT", 409, "Linux image import reservations conflict with an owned resource");
      await tx.insert(linuxImportRuns).values({ ...input.run, createdAt: new Date(input.run.createdAt), completedAt: null });
      await tx.insert(resources).values(input.resources.map(resourceValues));
      await tx.insert(ownedAttachmentIdentities).values(children);
      await tx.insert(linuxImportAllocations).values(input.allocations.map((entry) => ({ ...entry, createdAt: new Date(entry.createdAt) })));
      await tx.insert(events).values({ ...input.event, timestamp: new Date(input.event.timestamp) });
      return { run: input.run, replayed: false };
    });
  }
  async getLinuxImportRun(id: string): Promise<LinuxImportRun | null> { const row = (await this.db.select().from(linuxImportRuns).where(eq(linuxImportRuns.id, id)).limit(1))[0]; return row ? linuxImportRun(row) : null; }
  async listActiveLinuxImportRuns(): Promise<LinuxImportRun[]> { return (await this.db.select().from(linuxImportRuns).where(eq(linuxImportRuns.status, "ACTIVE"))).map(linuxImportRun); }
  async listLinuxImportPhases(runId: string): Promise<LinuxImportPhase[]> { return (await this.db.select().from(linuxImportPhaseRows).where(eq(linuxImportPhaseRows.runId, runId))).map(linuxImportPhase); }
  async getLinuxImportProof(id: string) { return this.db.transaction(async (tx) => { const row = (await tx.select().from(linuxImportRuns).where(eq(linuxImportRuns.id, id)).limit(1).for("update"))[0]; if (!row) throw new KilnError("SAFETY_DENIED", 403, "Linux image import is missing"); const run = linuxImportRun(row); const children = linuxImportChildren(run); return { resources: (await tx.select().from(resources).where(inArray(resources.id, [run.plan.templateResourceId, run.plan.cloneResourceId])).for("update")).map(toResource), allocations: (await tx.select().from(linuxImportAllocations).where(eq(linuxImportAllocations.runId, id)).for("update")).map((item) => ({ ...item, kind: item.kind as LinuxImportAllocation["kind"], state: item.state as LinuxImportAllocation["state"], createdAt: item.createdAt.toISOString() })), children: await tx.select().from(ownedAttachmentIdentities).where(inArray(ownedAttachmentIdentities.nativeId, children.map((item) => item.nativeId))).for("update"), phases: (await tx.select().from(linuxImportPhaseRows).where(eq(linuxImportPhaseRows.runId, id)).for("update")).map(linuxImportPhase) }; }); }
  async getLinuxImportPhase(runId: string, name: LinuxImportPhaseName): Promise<LinuxImportPhase | null> { const row = (await this.db.select().from(linuxImportPhaseRows).where(and(eq(linuxImportPhaseRows.runId, runId), eq(linuxImportPhaseRows.name, name))).limit(1))[0]; return row ? linuxImportPhase(row) : null; }
  async beginLinuxImportPhase(input: { runId: string; name: LinuxImportPhaseName; intentDigest: string; event: Omit<Event, "id"> }): Promise<{ phase: LinuxImportPhase; dispatch: boolean }> { return this.db.transaction(async (tx) => { await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`linux-import-run:${input.runId}`}))`); const old = (await tx.select().from(linuxImportPhaseRows).where(and(eq(linuxImportPhaseRows.runId, input.runId), eq(linuxImportPhaseRows.name, input.name))).limit(1))[0]; if (old) return { phase: linuxImportPhase(old), dispatch: false }; const run = (await tx.select().from(linuxImportRuns).where(and(eq(linuxImportRuns.id, input.runId), eq(linuxImportRuns.status, "ACTIVE"))).limit(1))[0]; const index = (await import("@kiln/core")).linuxImportPhases.indexOf(input.name); const prior = await tx.select().from(linuxImportPhaseRows).where(eq(linuxImportPhaseRows.runId, input.runId)); if (!run || index < 0 || prior.some((entry) => ["INTENT", "SUBMITTED", "UNKNOWN"].includes(entry.status)) || (await import("@kiln/core")).linuxImportPhases.slice(0, index).some((name) => prior.find((entry) => entry.name === name)?.status !== "COMPLETED")) throw new KilnError("SAFETY_DENIED", 403, "Linux image import phase is out of order"); const now = new Date(); const phase: LinuxImportPhase = { runId: input.runId, name: input.name, status: "INTENT", intentDigest: input.intentDigest, receipt: null, safeReason: null, createdAt: now.toISOString(), reconciliationDeadline: linuxImportDeadline(input.name, now).toISOString(), submittedAt: null, completedAt: null }; await tx.insert(linuxImportPhaseRows).values({ ...phase, createdAt: now, reconciliationDeadline: new Date(phase.reconciliationDeadline), submittedAt: null, completedAt: null }); await tx.insert(events).values({ ...input.event, timestamp: new Date(input.event.timestamp) }); return { phase, dispatch: true }; }); }
  async submitLinuxImportPhase(runId: string, name: LinuxImportPhaseName, receipt: LinuxImportReceipt, event: Omit<Event, "id">): Promise<void> { await this.linuxImportTransition(runId, name, "INTENT", { status: "SUBMITTED", receipt, submittedAt: new Date() }, event); }
  async completeLinuxImportPhase(runId: string, name: LinuxImportPhaseName, event: Omit<Event, "id">, receiptPatch?: Pick<LinuxImportReceipt, "generatedUuid" | "generatedCtime" | "responseDigest" | "configDigest">): Promise<void> { await this.db.transaction(async (tx) => { await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`linux-import-run:${runId}`}))`); const phase = (await tx.select().from(linuxImportPhaseRows).where(and(eq(linuxImportPhaseRows.runId, runId), eq(linuxImportPhaseRows.name, name), eq(linuxImportPhaseRows.status, "SUBMITTED"))).limit(1))[0]; const runRow = (await tx.select().from(linuxImportRuns).where(eq(linuxImportRuns.id, runId)).limit(1))[0]; if (!phase?.receipt || !runRow) throw new KilnError("SAFETY_DENIED", 403, "Linux image import receipt is missing"); const run = linuxImportRun(runRow); const kind = name === "UPLOAD" ? "STAGING" : ["IMPORT", "TEMPLATE", "DESTROY_TEMPLATE"].includes(name) ? "TEMPLATE_DISK" : ["CLONE", "DESTROY_CLONE"].includes(name) ? "CLONE_DISK" : null; if (kind) { const allocation = (await tx.select().from(linuxImportAllocations).where(and(eq(linuxImportAllocations.runId, runId), eq(linuxImportAllocations.kind, kind))).limit(1))[0]; if (!allocation) throw new KilnError("SAFETY_DENIED", 403, "Linux image import allocation is missing"); const state = name.startsWith("DESTROY") ? "DESTROYED" : "RETAINED"; const identity = name === "TEMPLATE" ? `${run.plan.targetStorage}:base-${run.plan.templateVmid}-disk-0` : allocation.identity; await tx.update(linuxImportAllocations).set({ state, identity }).where(eq(linuxImportAllocations.id, allocation.id)); } const receipt = { ...phase.receipt, ...(receiptPatch ?? {}) }; await tx.update(linuxImportPhaseRows).set({ status: "COMPLETED", completedAt: new Date(), receipt }).where(and(eq(linuxImportPhaseRows.runId, runId), eq(linuxImportPhaseRows.name, name))); if (name === "DESTROY_CLONE" || name === "DESTROY_TEMPLATE") await tx.update(resources).set({ state: "DESTROYED" }).where(eq(resources.id, name === "DESTROY_CLONE" ? run.plan.cloneResourceId : run.plan.templateResourceId)); if (name === "DESTROY_TEMPLATE") await tx.update(linuxImportRuns).set({ status: "COMPLETED", completedAt: new Date() }).where(eq(linuxImportRuns.id, runId)); await tx.insert(events).values({ ...event, timestamp: new Date(event.timestamp) }); }); }
  async markLinuxImportPhaseUnknown(runId: string, name: LinuxImportPhaseName, reason: string, event: Omit<Event, "id">): Promise<void> { const phase = await this.getLinuxImportPhase(runId, name); if (phase && ["INTENT", "SUBMITTED"].includes(phase.status)) await this.linuxImportTransition(runId, name, phase.status, { status: "UNKNOWN", safeReason: reason }, event); }
  private async linuxImportTransition(runId: string, name: LinuxImportPhaseName, expected: LinuxImportPhaseStatus, patch: Record<string, unknown>, event: Omit<Event, "id">): Promise<void> { await this.db.transaction(async (tx) => { await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`linux-import-run:${runId}`}))`); const result = await tx.update(linuxImportPhaseRows).set(patch).where(and(eq(linuxImportPhaseRows.runId, runId), eq(linuxImportPhaseRows.name, name), eq(linuxImportPhaseRows.status, expected))).returning(); if (!result[0]) throw new KilnError("SAFETY_DENIED", 403, "Linux image import phase changed concurrently"); if (patch.status === "UNKNOWN") { const runRow = (await tx.select().from(linuxImportRuns).where(eq(linuxImportRuns.id, runId)).limit(1))[0]; if (!runRow) throw new KilnError("SAFETY_DENIED", 403, "Linux image import run is missing"); const run = linuxImportRun(runRow); const kind = linuxImportAffectedAllocation(name); if (kind) await tx.update(linuxImportAllocations).set({ state: "UNKNOWN" }).where(and(eq(linuxImportAllocations.runId, runId), eq(linuxImportAllocations.kind, kind))); const resourceId = ["IMPORT", "TEMPLATE", "DESTROY_TEMPLATE"].includes(name) ? run.plan.templateResourceId : ["CLONE", "STAMP", "START", "STOP", "DESTROY_CLONE"].includes(name) ? run.plan.cloneResourceId : null; if (resourceId) await tx.update(resources).set({ state: "QUARANTINED" }).where(eq(resources.id, resourceId)); await tx.update(linuxImportRuns).set({ status: "UNKNOWN" }).where(eq(linuxImportRuns.id, runId)); } if (name === "DESTROY_TEMPLATE" && patch.status === "COMPLETED") await tx.update(linuxImportRuns).set({ status: "COMPLETED", completedAt: new Date() }).where(eq(linuxImportRuns.id, runId)); await tx.insert(events).values({ ...event, timestamp: new Date(event.timestamp) }); }); }
  async createQualificationRun(input: { run: QualificationRun; resources: Resource[]; allocations: import("@kiln/core").QualificationAllocation[]; event: Omit<Event, "id"> }): Promise<{ run: QualificationRun; replayed: boolean }> {
    return this.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`qualification:${input.run.installationId}`}))`);
      const existing = (await tx.select().from(qualificationRuns).where(eq(qualificationRuns.installationId, input.run.installationId)).limit(1))[0];
      if (existing) {
        if (existing.idempotencyKey !== input.run.idempotencyKey || existing.normalizedPayload !== input.run.normalizedPayload) throw new KilnError("CONFLICT", 409, "An installation already has a qualification run");
        return { run: qualificationRun(existing), replayed: true };
      }
      if (input.resources.length !== 2 || input.allocations.length !== 2) throw new KilnError("SAFETY_DENIED", 403, "Qualification allocations are invalid");
      const children = qualificationChildren(input.run);
      if ((await tx.select().from(ownedAttachmentIdentities).where(inArray(ownedAttachmentIdentities.nativeId, children.map((child) => child.nativeId))).limit(1))[0]) throw new KilnError("SAFETY_DENIED", 403, "Qualification child already has an owner");
      await tx.insert(qualificationRuns).values({ ...input.run, createdAt: new Date(input.run.createdAt), completedAt: null });
      await tx.insert(resources).values(input.resources.map((resource) => resourceValues({ ...resource, expiresAt: null })));
      await tx.insert(ownedAttachmentIdentities).values(children);
      await tx.insert(qualificationAllocations).values(input.allocations.map((allocation) => ({ ...allocation, receipt: null, createdAt: new Date(allocation.createdAt) })));
      await tx.insert(events).values({ ...input.event, timestamp: new Date(input.event.timestamp) });
      return { run: structuredClone(input.run), replayed: false };
    });
  }
  async getQualificationProof(runId: string) {
    return this.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`qualification-run:${runId}`}))`);
      return this.readQualificationProof(tx, runId);
    });
  }
  private async readQualificationProof(tx: Pick<NodePgDatabase, "select">, runId: string) {
      const row = (await tx.select().from(qualificationRuns).where(eq(qualificationRuns.id, runId)).limit(1).for("update"))[0];
      if (!row) throw new KilnError("SAFETY_DENIED", 403, "Qualification run is missing");
      const run = qualificationRun(row);
      const resourceRows = await tx.select().from(resources).where(inArray(resources.id, [run.plan.templateResourceId, run.plan.probeResourceId])).for("update");
      const allocations = await tx.select().from(qualificationAllocations).where(eq(qualificationAllocations.runId, runId)).for("update");
      const phases = await tx.select().from(qualificationPhaseRows).where(eq(qualificationPhaseRows.runId, runId)).for("update");
      const children = await tx.select().from(ownedAttachmentIdentities).where(inArray(ownedAttachmentIdentities.nativeId, qualificationChildren(run).map((child) => child.nativeId))).for("update");
      return { resources: resourceRows.map(toResource),
        allocations: allocations.map((row) => ({ ...row, kind: row.kind as "POOL" | "STAGING", state: row.state as "INTENT" | "RETAINED" | "UNKNOWN", createdAt: row.createdAt.toISOString() })),
        phases: phases.map(qualificationPhase), children };
  }
  private async validateQualificationProof(tx: Pick<NodePgDatabase, "select">, runId: string): Promise<void> {
    const row = (await tx.select().from(qualificationRuns).where(eq(qualificationRuns.id, runId)).limit(1).for("update"))[0];
    if (!row) throw new KilnError("SAFETY_DENIED", 403, "Qualification run is missing");
    assertQualificationOwnership(qualificationRun(row), await this.readQualificationProof(tx, runId));
  }
  async getQualificationRun(runId: string): Promise<QualificationRun | null> { const row = (await this.db.select().from(qualificationRuns).where(eq(qualificationRuns.id, runId)).limit(1))[0]; return row ? qualificationRun(row) : null; }
  async getQualificationRunByInstallation(installationId: string): Promise<QualificationRun | null> { const row = (await this.db.select().from(qualificationRuns).where(eq(qualificationRuns.installationId, installationId)).limit(1))[0]; return row ? qualificationRun(row) : null; }
  async getQualificationPhase(runId: string, name: QualificationPhaseName): Promise<QualificationPhase | null> { const row = (await this.db.select().from(qualificationPhaseRows).where(and(eq(qualificationPhaseRows.runId, runId), eq(qualificationPhaseRows.name, name))).limit(1))[0]; return row ? qualificationPhase(row) : null; }
  async listQualificationAllocations(runId: string): Promise<import("@kiln/core").QualificationAllocation[]> { const rows = await this.db.select().from(qualificationAllocations).where(eq(qualificationAllocations.runId, runId)); return rows.map((row) => ({ id: row.id, runId: row.runId, kind: row.kind as "POOL" | "STAGING", identity: row.identity, intentDigest: row.intentDigest, state: row.state as "INTENT" | "RETAINED" | "UNKNOWN", receipt: row.receipt ?? null, createdAt: row.createdAt.toISOString() })); }
  async completeQualificationAllocation(runId: string, kind: "POOL" | "STAGING", receipt: QualificationReceipt | null): Promise<void> { const changed = await this.db.update(qualificationAllocations).set({ state: "RETAINED", receipt }).where(and(eq(qualificationAllocations.runId, runId), eq(qualificationAllocations.kind, kind), eq(qualificationAllocations.state, "INTENT"))).returning({ id: qualificationAllocations.id }); if (!changed[0]) throw new Error("Qualification allocation cannot complete"); }
  async completeQualificationPhaseAndAllocation(runId: string, name: QualificationPhaseName, kind: "POOL" | "STAGING", event: Omit<Event, "id">, receiptPatch?: import("@kiln/core").QualificationInspection["receiptPatch"]): Promise<void> {
    await this.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`qualification-run:${runId}`}))`);
      const phase = (await tx.select().from(qualificationPhaseRows).where(and(eq(qualificationPhaseRows.runId, runId), eq(qualificationPhaseRows.name, name))).limit(1))[0];
      const allocation = (await tx.select().from(qualificationAllocations).where(and(eq(qualificationAllocations.runId, runId), eq(qualificationAllocations.kind, kind))).limit(1))[0];
      if (phase?.status === "COMPLETED" && allocation?.state === "RETAINED") return;
      if (!phase?.receipt || phase.status !== "SUBMITTED" || allocation?.state !== "INTENT") throw new Error("Qualification phase cannot complete atomically");
      await this.validateQualificationProof(tx, runId);
      const receipt = { ...phase.receipt, ...(receiptPatch ?? {}) };
      await tx.update(qualificationPhaseRows).set({ status: "COMPLETED", completedAt: new Date(), receipt }).where(and(eq(qualificationPhaseRows.runId, runId), eq(qualificationPhaseRows.name, name)));
      await tx.update(qualificationAllocations).set({ state: "RETAINED", receipt }).where(eq(qualificationAllocations.id, allocation.id));
      await tx.insert(events).values({ ...event, timestamp: new Date(event.timestamp) });
    });
  }
  async beginQualificationPhase(input: { runId: string; name: QualificationPhaseName; intentDigest: string; event: Omit<Event, "id"> }): Promise<{ phase: QualificationPhase; dispatch: boolean }> {
    return this.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`qualification-run:${input.runId}`}))`);
      const existing = (await tx.select().from(qualificationPhaseRows).where(and(eq(qualificationPhaseRows.runId, input.runId), eq(qualificationPhaseRows.name, input.name))).limit(1))[0];
      if (existing) return { phase: qualificationPhase(existing), dispatch: false };
      const run = (await tx.select().from(qualificationRuns).where(and(eq(qualificationRuns.id, input.runId), eq(qualificationRuns.status, "ACTIVE"))).limit(1))[0];
      const phaseIndex = qualificationPhases.indexOf(input.name);
      const prior = await tx.select().from(qualificationPhaseRows).where(eq(qualificationPhaseRows.runId, input.runId));
      if (!run || phaseIndex < 0 || qualificationPhases.slice(0, phaseIndex).some((name) => prior.find((phase) => phase.name === name)?.status !== "COMPLETED") || prior.some((phase) => ["INTENT", "SUBMITTED"].includes(phase.status))) throw new KilnError("SAFETY_DENIED", 403, "Qualification phase is out of order");
      await this.validateQualificationProof(tx, input.runId);
      const phase: QualificationPhase = { runId: input.runId, name: input.name, status: "INTENT", intentDigest: input.intentDigest, receipt: null, safeReason: null, createdAt: new Date().toISOString(), reconciliationDeadline: new Date(Date.now() + 15 * 60_000).toISOString(), submittedAt: null, completedAt: null };
      await tx.insert(qualificationPhaseRows).values({ ...phase, createdAt: new Date(phase.createdAt), reconciliationDeadline: new Date(phase.reconciliationDeadline), submittedAt: null, completedAt: null }); await tx.insert(events).values({ ...input.event, timestamp: new Date(input.event.timestamp) }); return { phase, dispatch: true };
    });
  }
  async submitQualificationPhase(runId: string, name: QualificationPhaseName, receipt: QualificationReceipt, event: Omit<Event, "id">): Promise<void> { await this.updateQualificationPhase(runId, name, ["INTENT"], { status: "SUBMITTED", receipt, submittedAt: new Date() }, event); }
  async completeQualificationPhase(runId: string, name: QualificationPhaseName, event: Omit<Event, "id">, receiptPatch?: import("@kiln/core").QualificationInspection["receiptPatch"]): Promise<void> {
    await this.updateQualificationPhase(runId, name, ["SUBMITTED"], { status: "COMPLETED", completedAt: new Date() }, event, false, receiptPatch);
  }
  async markQualificationPhaseUnknown(runId: string, name: QualificationPhaseName, reason: string, event: Omit<Event, "id">): Promise<void> {
    await this.updateQualificationPhase(runId, name, ["INTENT", "SUBMITTED"], { status: "UNKNOWN", safeReason: reason }, event, true);
  }
  private async updateQualificationPhase(runId: string, name: QualificationPhaseName, statuses: string[], patch: Record<string, unknown>, event: Omit<Event, "id">, allowNoop = false, receiptPatch?: import("@kiln/core").QualificationInspection["receiptPatch"]): Promise<void> {
    await this.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`qualification-run:${runId}`}))`);
      const phase = (await tx.select().from(qualificationPhaseRows).where(and(eq(qualificationPhaseRows.runId, runId), eq(qualificationPhaseRows.name, name))).limit(1))[0];
      if (phase?.status === patch.status) return;
      if (!phase || !statuses.includes(phase.status)) { if (allowNoop) return; throw new Error("Qualification phase changed concurrently"); }
      if (patch.status === "COMPLETED") await this.validateQualificationProof(tx, runId);
      if (receiptPatch) { if (!phase.receipt) throw new Error("Qualification receipt is missing"); patch = { ...patch, receipt: { ...phase.receipt, ...receiptPatch } }; }
      await tx.update(qualificationPhaseRows).set(patch).where(and(eq(qualificationPhaseRows.runId, runId), eq(qualificationPhaseRows.name, name)));
      const run = (await tx.select().from(qualificationRuns).where(eq(qualificationRuns.id, runId)).limit(1))[0];
      if (!run) throw new Error("Qualification run is missing");
      if (patch.status === "UNKNOWN") {
        await tx.update(qualificationRuns).set({ status: "UNKNOWN" }).where(eq(qualificationRuns.id, runId));
        const kind = name === "POOL_CREATE" ? "POOL" : name === "UPLOAD" ? "STAGING" : null;
        if (kind) await tx.update(qualificationAllocations).set({ state: "UNKNOWN", receipt: phase.receipt }).where(and(eq(qualificationAllocations.runId, runId), eq(qualificationAllocations.kind, kind)));
      }
      if (patch.status === "COMPLETED" && ["DESTROY_PROBE", "DESTROY_TEMPLATE"].includes(name)) {
        const resourceId = name === "DESTROY_PROBE" ? run.plan.probeResourceId : run.plan.templateResourceId;
        await tx.update(resources).set({ state: "DESTROYED" }).where(eq(resources.id, resourceId));
        if (name === "DESTROY_TEMPLATE") await tx.update(qualificationRuns).set({ status: "COMPLETED", completedAt: new Date() }).where(eq(qualificationRuns.id, runId));
      }
      await tx.insert(events).values({ ...event, timestamp: new Date(event.timestamp) });
    });
  }
  async completeTemplateImport(resource: Resource, templateId: string, operationId: string, event: Omit<Event, "id">): Promise<void> {
    await this.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`template:${templateId}`}))`);
      const template = (await tx.select().from(templateImports).where(and(eq(templateImports.resourceId, templateId), eq(templateImports.state, "UNKNOWN"))).limit(1))[0];
      if (!template || resource.id !== templateId) throw new Error("Template import was not ready to complete");
      const completed = await tx.update(operations).set({ status: "COMPLETED", completedAt: new Date() }).where(and(eq(operations.id, operationId), eq(operations.resourceId, templateId), inArray(operations.status, ["INTENT", "SUBMITTED"]))).returning({ id: operations.id });
      if (!completed[0]) throw new Error("Template import was not ready to complete");
      await tx.update(resources).set(resourceValues({ ...resource, expiresAt: null })).where(eq(resources.id, resource.id));
      await tx.update(templateImports).set({ state: "READY" }).where(eq(templateImports.resourceId, templateId));
      await tx.insert(events).values({ ...event, timestamp: new Date(event.timestamp) });
    });
  }
  async createProvenancedResource(input: { resource: Resource; plan: ProvisioningPlan; idempotencyKey: string; normalizedPayload: string; operation: Operation; event: Omit<Event, "id"> }): Promise<{ resource: Resource; operation: Operation; replayed: boolean }> {
    return this.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`template:${input.plan.templateResourceId}`}))`);
      const existing = (await tx.select().from(idempotency).where(eq(idempotency.key, input.idempotencyKey)).limit(1))[0];
      if (existing) {
        if (existing.payload !== input.normalizedPayload) throw new KilnError("IDEMPOTENCY_CONFLICT", 409, "Idempotency key was used with a different request");
        const resourceRow = (await tx.select().from(resources).where(eq(resources.id, existing.resourceId)).limit(1))[0];
        const operationRow = (await tx.select().from(operations).where(and(eq(operations.resourceId, existing.resourceId), eq(operations.kind, "create"))).limit(1))[0];
        if (!resourceRow || !operationRow) throw new Error("Provenance idempotency record is incomplete");
        return { resource: toResource(resourceRow), operation: toOperation(operationRow), replayed: true };
      }
      const template = (await tx.select().from(templateImports).where(and(eq(templateImports.resourceId, input.plan.templateResourceId), eq(templateImports.state, "READY"))).limit(1))[0];
      if (!template) throw new KilnError("SAFETY_DENIED", 403, "Template is not eligible for provisioning");
      const ownedIds = input.plan.attachments.filter((attachment) => attachment.ownership === "OWNED_CHILD").map((attachment) => attachment.nativeId);
      if (ownedIds.length) {
        const conflict = (await tx.select().from(ownedAttachmentIdentities).where(inArray(ownedAttachmentIdentities.nativeId, ownedIds)).limit(1))[0];
        if (conflict) throw new KilnError("SAFETY_DENIED", 403, "Owned attachment already belongs to another resource");
      }
      await tx.insert(resources).values({ ...input.resource, provenanceRequired: 1, createdAt: new Date(input.resource.createdAt), expiresAt: input.resource.expiresAt ? new Date(input.resource.expiresAt) : null });
      await tx.insert(idempotency).values({ key: input.idempotencyKey, payload: input.normalizedPayload, resourceId: input.resource.id });
      await tx.insert(provisioningPlans).values({ resourceId: input.plan.resourceId, templateResourceId: input.plan.templateResourceId, canonicalDigest: input.plan.canonicalDigest, plan: input.plan, createdAt: new Date(input.plan.createdAt) });
      await tx.insert(provisioningAttachments).values(input.plan.attachments.map((attachment) => ({ resourceId: input.plan.resourceId, attachmentId: attachment.id, nativeId: attachment.nativeId, attachment })));
      if (ownedIds.length) await tx.insert(ownedAttachmentIdentities).values(ownedIds.map((nativeId) => ({ nativeId, resourceId: input.plan.resourceId })));
      await tx.insert(operations).values({ ...input.operation, createdAt: new Date(input.operation.createdAt), submittedAt: null, reconciliationDeadline: input.operation.reconciliationDeadline ? new Date(input.operation.reconciliationDeadline) : null, completedAt: null });
      await tx.insert(events).values({ ...input.event, timestamp: new Date(input.event.timestamp) });
      return { resource: structuredClone(input.resource), operation: structuredClone(input.operation), replayed: false };
    });
  }
  async getProvisioningPlan(resourceId: string): Promise<ProvisioningPlan | null> {
    const row = (await this.db.select().from(provisioningPlans).where(eq(provisioningPlans.resourceId, resourceId)).limit(1))[0];
    if (!row) return null;
    const attachments = await this.db.select().from(provisioningAttachments).where(eq(provisioningAttachments.resourceId, resourceId));
    if (attachments.length !== row.plan.attachments.length || attachments.some((attachment) => attachment.attachmentId !== attachment.attachment.id || attachment.nativeId !== attachment.attachment.nativeId) || canonicalAttachmentGraph(attachments.map((attachment) => attachment.attachment)) !== canonicalAttachmentGraph(row.plan.attachments)) return null;
    const owned = row.plan.attachments.filter((attachment) => attachment.ownership === "OWNED_CHILD").map((attachment) => attachment.nativeId);
    const identities = owned.length ? await this.db.select().from(ownedAttachmentIdentities).where(inArray(ownedAttachmentIdentities.nativeId, owned)) : [];
    if (identities.length !== owned.length || identities.some((identity) => identity.resourceId !== resourceId)) return null;
    return structuredClone(row.plan);
  }
  async provenanceSummary(resourceId: string): Promise<SafeProvenanceSummary | null> {
    const plan = await this.getProvisioningPlan(resourceId);
    return plan ? { templateId: plan.templateResourceId, imageManifestDigest: plan.imageManifestDigest, planDigest: plan.canonicalDigest, cloneMode: plan.cloneMode, attachmentClasses: plan.attachments.map((attachment) => attachment.class) } : null;
  }
  async retireTemplate(resourceId: string, event: Omit<Event, "id">): Promise<void> {
    await this.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`template:${resourceId}`}))`);
      const template = (await tx.select().from(templateImports).where(eq(templateImports.resourceId, resourceId)).limit(1))[0];
      if (!template) throw new KilnError("NOT_FOUND", 404, "Template was not found");
      const unresolvedImport = (await tx.select({ id: operations.id }).from(operations).where(and(eq(operations.resourceId, resourceId), inArray(operations.status, ["INTENT", "SUBMITTED", "UNKNOWN"]))).limit(1))[0];
      if (unresolvedImport) throw new KilnError("CONFLICT", 409, "Template has an unresolved import operation");
      const live = (await tx.execute(sql`SELECT 1 FROM provisioning_plans p JOIN resources r ON r.id = p.resource_id LEFT JOIN operations o ON o.resource_id = r.id AND o.status IN ('INTENT', 'SUBMITTED', 'UNKNOWN') WHERE p.template_resource_id = ${resourceId} AND (r.state <> 'DESTROYED' OR o.id IS NOT NULL) LIMIT 1`)).rows[0];
      if (live) throw new KilnError("CONFLICT", 409, "Template has live or unresolved clone plans");
      await tx.update(templateImports).set({ state: "RETIRED" }).where(eq(templateImports.resourceId, resourceId));
      await tx.insert(events).values({ ...event, timestamp: new Date(event.timestamp) });
    });
  }
  async idempotentResource(key: string, payload: string): Promise<Resource | null> {
    const existing = (await this.db.select().from(idempotency).where(eq(idempotency.key, key)).limit(1))[0];
    if (!existing) return null;
    if (existing.payload !== payload)
      throw new KilnError("IDEMPOTENCY_CONFLICT", 409, "Idempotency key was used with a different request");
    const row = (await this.db.select().from(resources).where(eq(resources.id, existing.resourceId)).limit(1))[0];
    if (!row) throw new Error("Idempotency record references no resource");
    return toResource(row);
  }
  async createNetworkProbe(resource: Resource, probe: NetworkProbeRecord, key: string, payload: string, savedEvent: Omit<Event, "id">): Promise<{ resource: Resource; probe: NetworkProbeRecord; replayed: boolean }> {
    return this.db.transaction(async (tx) => {
      const existing = (await tx.select().from(idempotency).where(eq(idempotency.key, key)).limit(1))[0];
      if (existing) {
        if (existing.payload !== payload) throw new KilnError("IDEMPOTENCY_CONFLICT", 409, "Idempotency key was used with a different request");
        const row = (await tx.select().from(resources).where(eq(resources.id, existing.resourceId)).limit(1))[0];
        const job = (await tx.select().from(networkProbes).where(eq(networkProbes.resourceId, existing.resourceId)).limit(1))[0];
        if (!row || !job) throw new Error("Network probe idempotency record is incomplete");
        return { resource: toResource(row), probe: toNetworkProbe(job), replayed: true };
      }
      await tx.insert(resources).values(resourceValues(resource));
      const reservation = await tx.insert(idempotency).values({ key, payload, resourceId: resource.id }).onConflictDoNothing().returning();
      if (!reservation[0]) {
        await tx.delete(resources).where(eq(resources.id, resource.id));
        const winner = (await tx.select().from(idempotency).where(eq(idempotency.key, key)).limit(1))[0];
        if (!winner) throw new Error("Network probe idempotency reservation was lost without a winner");
        if (winner.payload !== payload) throw new KilnError("IDEMPOTENCY_CONFLICT", 409, "Idempotency key was used with a different request");
        const row = (await tx.select().from(resources).where(eq(resources.id, winner.resourceId)).limit(1))[0];
        const job = (await tx.select().from(networkProbes).where(eq(networkProbes.resourceId, winner.resourceId)).limit(1))[0];
        if (!row || !job) throw new Error("Network probe idempotency record is incomplete");
        return { resource: toResource(row), probe: toNetworkProbe(job), replayed: true };
      }
      await tx.insert(networkProbes).values({ ...probe, tokenHash: null, tokenExpiresAt: null, resultDigest: null, results: null, receivedAt: null, createdAt: new Date(probe.createdAt) });
      await tx.insert(events).values({ ...savedEvent, timestamp: new Date(savedEvent.timestamp) });
      return { resource, probe, replayed: false };
    });
  }
  async getNetworkProbe(resourceId: string): Promise<NetworkProbeRecord | null> {
    const row = (await this.db.select().from(networkProbes).where(eq(networkProbes.resourceId, resourceId)).limit(1))[0];
    return row ? toNetworkProbe(row) : null;
  }
  async listNetworkProbes(gatewayId?: string): Promise<NetworkProbeRecord[]> {
    return (await this.db.select().from(networkProbes).where(gatewayId ? eq(networkProbes.gatewayId, gatewayId) : undefined)).map(toNetworkProbe);
  }
  async issueNetworkProbeToken(resourceId: string, hash: string, expiresAt: string, savedEvent: Omit<Event, "id">): Promise<void> {
    await this.db.transaction(async (tx) => {
      const updated = await tx.update(networkProbes).set({ tokenHash: hash, tokenExpiresAt: new Date(expiresAt) }).where(eq(networkProbes.resourceId, resourceId)).returning({ resourceId: networkProbes.resourceId });
      if (!updated[0]) throw new KilnError("NOT_FOUND", 404, "Network probe not found");
      await tx.insert(events).values({ ...savedEvent, timestamp: new Date(savedEvent.timestamp) });
    });
  }
  async acceptNetworkProbeResult(input: { resourceId: string; planDigest: string; resultDigest: string; results: NetworkProbeResult[]; receivedAt: string; event: Omit<Event, "id"> }): Promise<{ probe: NetworkProbeRecord; replayed: boolean }> {
    return this.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`network-probe:${input.resourceId}`}))`);
      const current = (await tx.select().from(networkProbes).where(eq(networkProbes.resourceId, input.resourceId)).limit(1))[0];
      if (!current || current.planDigest !== input.planDigest) throw new KilnError("CONFLICT", 409, "Network probe plan changed");
      if (current.resultDigest) {
        if (current.resultDigest !== input.resultDigest) throw new KilnError("CONFLICT", 409, "Network probe already has a different result");
        return { probe: toNetworkProbe(current), replayed: true };
      }
      const updated = (await tx.update(networkProbes).set({ state: "COMPLETED", resultDigest: input.resultDigest, results: input.results, receivedAt: new Date(input.receivedAt) }).where(eq(networkProbes.resourceId, input.resourceId)).returning())[0]!;
      await tx.insert(events).values({ ...input.event, timestamp: new Date(input.event.timestamp) });
      return { probe: toNetworkProbe(updated), replayed: false };
    });
  }
  async timeoutNetworkProbe(resourceId: string, state: "TIMED_OUT" | "INVALIDATED" | "CANCELLED", savedEvent: Omit<Event, "id">): Promise<NetworkProbeRecord | null> {
    return this.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`network-probe:${resourceId}`}))`);
      const current = (await tx.select().from(networkProbes).where(eq(networkProbes.resourceId, resourceId)).limit(1))[0];
      if (!current) return null;
      if (current.state !== "PENDING") return toNetworkProbe(current);
      const updated = (await tx.update(networkProbes).set({ state }).where(eq(networkProbes.resourceId, resourceId)).returning())[0]!;
      await tx.insert(events).values({ ...savedEvent, timestamp: new Date(savedEvent.timestamp) });
      return toNetworkProbe(updated);
    });
  }
  async expiredNetworkProbes(now: string): Promise<NetworkProbeRecord[]> {
    const jobs = await this.db.select().from(networkProbes).where(inArray(networkProbes.state, ["PENDING", "COMPLETED", "TIMED_OUT", "CANCELLED", "INVALIDATED"]));
    const eligible = jobs.filter((row) => row.state === "COMPLETED" || row.state === "CANCELLED" || row.state === "INVALIDATED" || row.plan.expiresAt <= now);
    const ids = eligible.map((row) => row.resourceId);
    if (ids.length === 0) return [];
    const active = new Set((await this.db.select({ id: resources.id }).from(resources).where(and(inArray(resources.id, ids), notInArray(resources.state, ["DESTROYED", "QUARANTINED", "LOST"])))).map((row) => row.id));
    return eligible.filter((row) => active.has(row.resourceId)).map(toNetworkProbe);
  }
  async updateResource(resource: Resource): Promise<void> {
    await this.db
      .update(resources)
      .set(resourceValues(resource))
      .where(eq(resources.id, resource.id));
  }
  async appendEvent(event: Omit<Event, "id">): Promise<Event> {
    const row = (
      await this.db
        .insert(events)
        .values({ ...event, timestamp: new Date(event.timestamp) })
        .returning()
    )[0]!;
    return { ...row, timestamp: row.timestamp.toISOString() };
  }
  async commitTransition(
    resource: Resource,
    event: Omit<Event, "id">,
  ): Promise<Event> {
    return this.db.transaction(async (tx) => {
      await tx
        .update(resources)
        .set(resourceValues(resource))
        .where(eq(resources.id, resource.id));
      if (resource.expiresAt) {
        const now = new Date();
        await tx
          .insert(leases)
          .values({
            resourceId: resource.id,
            expiresAt: new Date(resource.expiresAt),
            createdAt: now,
            updatedAt: now,
          })
          .onConflictDoUpdate({
            target: leases.resourceId,
            set: { expiresAt: new Date(resource.expiresAt), updatedAt: now },
          });
      }
      const row = (
        await tx
          .insert(events)
          .values({ ...event, timestamp: new Date(event.timestamp) })
          .returning()
      )[0]!;
      return { ...row, timestamp: row.timestamp.toISOString() };
    });
  }
  async events(projectId: string, after: number): Promise<Event[]> {
    return (
      await this.db
        .select()
        .from(events)
        .where(and(eq(events.projectId, projectId), gt(events.id, after)))
        .orderBy(asc(events.id))
    ).map((e) => ({ ...e, timestamp: e.timestamp.toISOString() }));
  }
  async expired(now: string): Promise<Resource[]> {
    return (
      await this.db
        .select()
        .from(resources)
        .where(
          and(
            lte(resources.expiresAt, new Date(now)),
            inArray(resources.ownership, ["KILN_MANAGED", "IMPORTED"]),
            notInArray(resources.type, ["gateway"]),
            notInArray(resources.state, ["DESTROYED", "LOST", "QUARANTINED"]),
          ),
        )
    ).map(toResource);
  }
  async beginOperation(
    operation: { resourceId: string; kind: Operation["kind"]; snapshot?: OperationSnapshot; reconciliationDeadline?: string; event?: Omit<Event, "id"> },
  ): Promise<Operation> {
    const saved: Operation = {
      resourceId: operation.resourceId,
      kind: operation.kind,
      id: randomUUID(),
      status: "INTENT",
      snapshot: operation.snapshot ?? null,
      taskHandle: null,
      safeReason: null,
      createdAt: new Date().toISOString(),
      submittedAt: null,
      reconciliationDeadline: operation.reconciliationDeadline ?? null,
      completedAt: null,
    };
    await this.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`operation:${saved.resourceId}`}))`);
      const existing = (await tx.select({ id: operations.id }).from(operations).where(and(eq(operations.resourceId, saved.resourceId), inArray(operations.status, ["INTENT", "SUBMITTED", "UNKNOWN"]))).limit(1))[0];
      if (existing) throw new KilnError("OPERATION_UNRESOLVED", 409, "Resource has an unresolved provider operation");
      await tx.insert(operations).values({ ...saved, createdAt: new Date(saved.createdAt), submittedAt: null, reconciliationDeadline: saved.reconciliationDeadline ? new Date(saved.reconciliationDeadline) : null, completedAt: null });
      if (operation.event) await tx.insert(events).values({ ...operation.event, timestamp: new Date(operation.event.timestamp) });
    });
    return saved;
  }
  async listOperations(resourceId: string, limit?: number): Promise<Operation[]> {
    return (await this.db.select().from(operations).where(eq(operations.resourceId, resourceId)).orderBy(desc(operations.createdAt)).limit(limit ?? 2147483647)).map(toOperation);
  }
  async getOperation(id: string): Promise<Operation | null> { const row = (await this.db.select().from(operations).where(eq(operations.id, id)).limit(1))[0]; return row ? toOperation(row) : null; }
  async unresolvedOperation(resourceId: string): Promise<Operation | null> {
    const row = (await this.db.select().from(operations).where(and(eq(operations.resourceId, resourceId), inArray(operations.status, ["INTENT", "SUBMITTED", "UNKNOWN"]))).orderBy(desc(operations.createdAt)).limit(1))[0];
    return row ? toOperation(row) : null;
  }
  async submittedOperations(): Promise<Operation[]> {
    return (await this.db.select().from(operations).where(eq(operations.status, "SUBMITTED")).orderBy(asc(operations.createdAt))).map(toOperation);
  }
  async markOperationSubmitted(id: string, handle: ProviderTaskHandle, savedEvent: Omit<Event, "id">): Promise<void> {
    await this.db.transaction(async (tx) => {
      const updated = await tx.update(operations).set({ status: "SUBMITTED", taskHandle: handle, submittedAt: new Date(), safeReason: null }).where(and(eq(operations.id, id), eq(operations.status, "INTENT"))).returning({ id: operations.id });
      if (!updated[0]) throw new Error("Operation was not ready to submit");
      await tx.insert(events).values({ ...savedEvent, timestamp: new Date(savedEvent.timestamp) });
    });
  }
  async completeOperation(id: string): Promise<void> {
    const completed = await this.db
      .update(operations)
      .set({ status: "COMPLETED", completedAt: new Date() })
      .where(and(eq(operations.id, id), inArray(operations.status, ["INTENT", "SUBMITTED"])))
      .returning({ id: operations.id });
    if (!completed[0]) throw new Error("Operation was not ready to complete");
  }
  async completeOperationTransition(
    id: string,
    resource: Resource,
    event: Omit<Event, "id">,
  ): Promise<Event> {
    return this.db.transaction(async (tx) => {
      const completed = await tx
        .update(operations)
        .set({ status: "COMPLETED", completedAt: new Date() })
        .where(and(eq(operations.id, id), inArray(operations.status, ["INTENT", "SUBMITTED"])))
        .returning({ id: operations.id });
      if (!completed[0]) throw new Error("Operation was not ready to complete");
      await tx
        .update(resources)
        .set(resourceValues(resource))
        .where(eq(resources.id, resource.id));
      if (resource.expiresAt) {
        const now = new Date();
        await tx
          .insert(leases)
          .values({
            resourceId: resource.id,
            expiresAt: new Date(resource.expiresAt),
            createdAt: now,
            updatedAt: now,
          })
          .onConflictDoUpdate({
            target: leases.resourceId,
            set: { expiresAt: new Date(resource.expiresAt), updatedAt: now },
          });
      }
      const row = (
        await tx
          .insert(events)
          .values({ ...event, timestamp: new Date(event.timestamp) })
          .returning()
      )[0]!;
      return { ...row, timestamp: row.timestamp.toISOString() };
    });
  }
  async completeNetworkProbeOperationTransition(id: string, resource: Resource, savedEvent: Omit<Event, "id">): Promise<Event> {
    return this.db.transaction(async (tx) => {
      const completed = await tx.update(operations).set({ status: "COMPLETED", completedAt: new Date() }).where(and(eq(operations.id, id), inArray(operations.status, ["INTENT", "SUBMITTED"]))).returning({ id: operations.id });
      if (!completed[0]) throw new Error("Operation was not ready to complete");
      await tx.update(resources).set(resourceValues(resource)).where(eq(resources.id, resource.id));
      if (resource.expiresAt) {
        const now = new Date();
        await tx.insert(leases).values({ resourceId: resource.id, expiresAt: new Date(resource.expiresAt), createdAt: now, updatedAt: now }).onConflictDoUpdate({ target: leases.resourceId, set: { expiresAt: new Date(resource.expiresAt), updatedAt: now } });
      }
      await tx.update(networkProbes).set({ state: "CANCELLED" }).where(and(eq(networkProbes.resourceId, resource.id), eq(networkProbes.state, "PENDING")));
      const row = (await tx.insert(events).values({ ...savedEvent, timestamp: new Date(savedEvent.timestamp) }).returning())[0]!;
      return { ...row, timestamp: row.timestamp.toISOString() };
    });
  }
  async markOperationUnknown(id: string, reason: OperationSafeReason = "DISPATCH_UNKNOWN", savedEvent?: Omit<Event, "id">): Promise<void> {
    await this.db.transaction(async (tx) => {
      const updated = await tx.update(operations).set({ status: "UNKNOWN", safeReason: reason }).where(and(eq(operations.id, id), inArray(operations.status, ["INTENT", "SUBMITTED", "UNKNOWN"]))).returning({ id: operations.id });
      if (!updated[0]) return;
      if (savedEvent) await tx.insert(events).values({ ...savedEvent, timestamp: new Date(savedEvent.timestamp) });
    });
  }
  async completedOperation(
    resourceId: string,
    kind: Operation["kind"],
  ): Promise<Operation | null> {
    const row = (
      await this.db
        .select()
        .from(operations)
        .where(
          and(
            eq(operations.resourceId, resourceId),
            eq(operations.kind, kind),
            eq(operations.status, "COMPLETED"),
          ),
        )
        .limit(1)
    )[0];
    return row ? toOperation(row) : null;
  }
  async upsertLease(resourceId: string, expiresAt: string): Promise<void> {
    const now = new Date();
    await this.db
      .insert(leases)
      .values({
        resourceId,
        expiresAt: new Date(expiresAt),
        createdAt: now,
        updatedAt: now,
      })
      .onConflictDoUpdate({
        target: leases.resourceId,
        set: { expiresAt: new Date(expiresAt), updatedAt: now },
      });
  }
  async createGateway(resource: Resource, metadata: GatewayMetadata, key: string, payload: string): Promise<{ resource: Resource; replayed: boolean }> {
    return this.db.transaction(async (tx) => {
      const existing = (await tx.select().from(idempotency).where(eq(idempotency.key, key)).limit(1))[0];
      if (existing) {
        if (existing.payload !== payload) throw new KilnError("IDEMPOTENCY_CONFLICT", 409, "Idempotency key was used with a different request");
        const row = (await tx.select().from(resources).where(eq(resources.id, existing.resourceId)).limit(1))[0];
        if (!row) throw new Error("Idempotency record references no resource");
        return { resource: toResource(row), replayed: true };
      }
      const occupied = (await tx.select().from(gateways).where(eq(gateways.node, metadata.node)).limit(1))[0];
      if (occupied) throw new KilnError("CONFLICT", 409, "Gateway node already has a protected gateway");
      await tx.insert(resources).values(resourceValues({ ...resource, expiresAt: null }));
      const reservation = await tx.insert(idempotency).values({ key, payload, resourceId: resource.id }).onConflictDoNothing().returning();
      if (!reservation[0]) {
        await tx.delete(resources).where(eq(resources.id, resource.id));
        const winner = (await tx.select().from(idempotency).where(eq(idempotency.key, key)).limit(1))[0];
        if (!winner) throw new Error("Idempotency reservation was lost without a winner");
        if (winner.payload !== payload) throw new KilnError("IDEMPOTENCY_CONFLICT", 409, "Idempotency key was used with a different request");
        const row = (await tx.select().from(resources).where(eq(resources.id, winner.resourceId)).limit(1))[0];
        if (!row) throw new Error("Idempotency record references no resource");
        return { resource: toResource(row), replayed: true };
      }
      const createdGateway = await tx.insert(gateways).values({ ...metadata, createdAt: new Date(metadata.createdAt) }).onConflictDoNothing().returning();
      if (!createdGateway[0]) {
        await tx.delete(idempotency).where(eq(idempotency.key, key));
        await tx.delete(resources).where(eq(resources.id, resource.id));
        throw new KilnError("CONFLICT", 409, "Gateway node already has a protected gateway");
      }
      return { resource, replayed: false };
    });
  }
  async getGateway(resourceId: string): Promise<GatewayMetadata | null> {
    const row = (await this.db.select().from(gateways).where(eq(gateways.resourceId, resourceId)).limit(1))[0];
    return row ? { ...row, createdAt: row.createdAt.toISOString() } : null;
  }
  async listGateways(): Promise<Array<{ resource: Resource; metadata: GatewayMetadata; health: GatewayHealth | null }>> {
    const rows = await this.db.select().from(gateways);
    return (await Promise.all(rows.map(async (metadata) => {
      const row = (await this.db.select().from(resources).where(eq(resources.id, metadata.resourceId)).limit(1))[0];
      const health = (await this.db.select().from(gatewayHealth).where(eq(gatewayHealth.resourceId, metadata.resourceId)).limit(1))[0];
      return row ? { resource: toResource(row), metadata: { ...metadata, createdAt: metadata.createdAt.toISOString() }, health: health ? { ...health, generation: health.generation ?? null, expectedFingerprint: health.expectedFingerprint ?? null, status: health.status as GatewayHealth["status"], observedAt: health.observedAt.toISOString() } : null } : null;
    }))).flatMap((entry) => entry ? [entry] : []);
  }
  async saveGatewayScan(health: GatewayHealth, incidents: GatewayIncident[], eventsToSave: Array<Omit<Event, "id">>): Promise<void> {
    await this.db.transaction(async (tx) => {
      await tx.insert(gatewayHealth).values({ ...health, observedAt: new Date(health.observedAt) }).onConflictDoUpdate({ target: gatewayHealth.resourceId, set: { node: health.node, status: health.status, observedAt: new Date(health.observedAt), generation: health.generation, expectedFingerprint: health.expectedFingerprint, evidence: health.evidence } });
      for (const incident of incidents) await tx.insert(gatewayIncidents).values({ ...incident, firstSeenAt: new Date(incident.firstSeenAt), lastSeenAt: new Date(incident.lastSeenAt), resolvedAt: incident.resolvedAt ? new Date(incident.resolvedAt) : null }).onConflictDoUpdate({ target: gatewayIncidents.id, set: { status: incident.status, lastSeenAt: new Date(incident.lastSeenAt), resolvedAt: incident.resolvedAt ? new Date(incident.resolvedAt) : null } });
      if (eventsToSave.length) await tx.insert(events).values(eventsToSave.map((event) => ({ ...event, timestamp: new Date(event.timestamp) })));
    });
  }
  async listGatewayIncidents(node?: string): Promise<GatewayIncident[]> {
    const rows = await this.db.select().from(gatewayIncidents).where(node ? eq(gatewayIncidents.node, node) : undefined);
    return rows.map((row) => ({ ...row, severity: row.severity as GatewayIncident["severity"], status: row.status as GatewayIncident["status"], firstSeenAt: row.firstSeenAt.toISOString(), lastSeenAt: row.lastSeenAt.toISOString(), resolvedAt: row.resolvedAt?.toISOString() ?? null }));
  }
  async bindGatewayCaFingerprint(fingerprint: string): Promise<void> {
    await this.db.transaction(async (tx) => {
      const existing = (await tx.select().from(gatewayCa).limit(1))[0];
      if (existing && existing.fingerprint !== fingerprint)
        throw new Error("Configured gateway CA does not match the persisted gateway CA fingerprint");
      if (!existing) await tx.insert(gatewayCa).values({ singleton: 1, fingerprint });
    });
  }
  async issueGatewayEnrollmentToken(token: GatewayEnrollmentTokenRecord, savedEvent: Omit<Event, "id">): Promise<void> {
    await this.db.transaction(async (tx) => {
      await tx.insert(gatewayEnrollmentTokens).values({ ...token, expiresAt: new Date(token.expiresAt) }).onConflictDoUpdate({ target: gatewayEnrollmentTokens.resourceId, set: { installationId: token.installationId, generation: token.generation, tokenHash: token.tokenHash, expiresAt: new Date(token.expiresAt), publicKeyFingerprint: null, deviceId: null, certificateFingerprint: null } });
      await tx.insert(events).values({ ...savedEvent, timestamp: new Date(savedEvent.timestamp) });
    });
  }
  async getGatewayEnrollmentToken(resourceId: string): Promise<GatewayEnrollmentTokenRecord | null> {
    const row = (await this.db.select().from(gatewayEnrollmentTokens).where(eq(gatewayEnrollmentTokens.resourceId, resourceId)).limit(1))[0];
    return row ? { ...row, expiresAt: row.expiresAt.toISOString(), publicKeyFingerprint: row.publicKeyFingerprint ?? null, deviceId: row.deviceId ?? null, certificateFingerprint: row.certificateFingerprint ?? null } : null;
  }
  async getGatewayIdentity(resourceId: string): Promise<GatewayIdentity | null> {
    return identityFromDatabase(this.db, resourceId);
  }
  async getGatewayCertificate(fingerprint: string): Promise<GatewayIdentity["currentCertificate"] | null> {
    const row = (await this.db.select().from(gatewayCertificates).where(eq(gatewayCertificates.fingerprint, fingerprint)).limit(1))[0];
    return row ? toCertificate(row) : null;
  }
  async gatewayIdentityRequired(resourceId: string): Promise<boolean> {
    const [token, identity] = await Promise.all([
      this.db.select({ resourceId: gatewayEnrollmentTokens.resourceId }).from(gatewayEnrollmentTokens).where(eq(gatewayEnrollmentTokens.resourceId, resourceId)).limit(1),
      this.db.select({ resourceId: gatewayIdentities.resourceId }).from(gatewayIdentities).where(eq(gatewayIdentities.resourceId, resourceId)).limit(1),
    ]);
    return Boolean(token[0] || identity[0]);
  }
  async enrollGatewayIdentity(input: { tokenHash: string; publicKeyPem: string; publicKeyFingerprint: string; identity: GatewayIdentity; event: Omit<Event, "id">; now: string }): Promise<{ identity: GatewayIdentity; certificate: GatewayIdentity["currentCertificate"]; replayed: boolean }> {
    return this.db.transaction(async (tx) => {
      const token = (await tx.select().from(gatewayEnrollmentTokens).where(eq(gatewayEnrollmentTokens.resourceId, input.identity.resourceId)).limit(1))[0];
      if (!token || token.tokenHash !== input.tokenHash || token.expiresAt.getTime() < Date.parse(input.now) || token.installationId !== input.identity.installationId || token.generation !== input.identity.generation)
        throw new KilnError("UNAUTHENTICATED", 401, "Gateway enrollment token is invalid or expired");
      const existing = await identityFromDatabase(tx, input.identity.resourceId);
      if (existing && !existing.revokedAt) {
        if (token.publicKeyFingerprint !== input.publicKeyFingerprint || existing.publicKeyFingerprint !== input.publicKeyFingerprint || Date.parse(existing.currentCertificate.expiresAt) < Date.parse(input.now))
          throw new KilnError("UNAUTHENTICATED", 401, "Gateway enrollment token cannot be replayed");
        const certificate = (await tx.select().from(gatewayCertificates).where(eq(gatewayCertificates.fingerprint, token.certificateFingerprint!)).limit(1))[0];
        if (!certificate || certificate.deviceId !== existing.deviceId) throw new KilnError("UNAUTHENTICATED", 401, "Gateway enrollment token cannot be replayed");
        return { identity: existing, certificate: toCertificate(certificate), replayed: true };
      }
      const inserted = await tx.insert(gatewayIdentities).values({ deviceId: input.identity.deviceId, resourceId: input.identity.resourceId, installationId: input.identity.installationId, generation: input.identity.generation, publicKeyPem: input.publicKeyPem, publicKeyFingerprint: input.publicKeyFingerprint, revokedAt: null, createdAt: new Date(input.identity.createdAt), nextSequence: input.identity.nextSequence, lastSeenAt: null, lastServices: null, lastPolicy: null, lastReservation: null }).onConflictDoNothing().returning();
      if (!inserted[0]) {
        const winner = await identityFromDatabase(tx, input.identity.resourceId);
        if (!winner || winner.revokedAt || token.publicKeyFingerprint !== input.publicKeyFingerprint || winner.publicKeyFingerprint !== input.publicKeyFingerprint || Date.parse(winner.currentCertificate.expiresAt) < Date.parse(input.now))
          throw new KilnError("UNAUTHENTICATED", 401, "Gateway enrollment token cannot be replayed");
        const certificate = (await tx.select().from(gatewayCertificates).where(eq(gatewayCertificates.fingerprint, token.certificateFingerprint!)).limit(1))[0];
        if (!certificate || certificate.deviceId !== winner.deviceId) throw new KilnError("UNAUTHENTICATED", 401, "Gateway enrollment token cannot be replayed");
        return { identity: winner, certificate: toCertificate(certificate), replayed: true };
      }
      await tx.insert(gatewayCertificates).values({ ...input.identity.currentCertificate, deviceId: input.identity.deviceId, issuedAt: new Date(input.identity.currentCertificate.issuedAt), expiresAt: new Date(input.identity.currentCertificate.expiresAt), acceptedUntil: new Date(input.identity.currentCertificate.acceptedUntil), current: 1 });
      await tx.update(gatewayEnrollmentTokens).set({ publicKeyFingerprint: input.publicKeyFingerprint, deviceId: input.identity.deviceId, certificateFingerprint: input.identity.currentCertificate.fingerprint }).where(eq(gatewayEnrollmentTokens.resourceId, input.identity.resourceId));
      await tx.insert(events).values({ ...input.event, timestamp: new Date(input.event.timestamp) });
      return { identity: input.identity, certificate: input.identity.currentCertificate, replayed: false };
    });
  }
  async issueGatewayChallenge(input: GatewayChallenge, now: string): Promise<GatewayChallenge> {
    return this.db.transaction(async (tx) => {
      const existing = (await tx.select().from(gatewayChallenges).where(eq(gatewayChallenges.deviceId, input.deviceId)).limit(1))[0];
      if (existing && existing.expiresAt.getTime() >= Date.parse(now)) return { deviceId: existing.deviceId, challengeId: existing.challengeId, nonce: existing.nonce, expiresAt: existing.expiresAt.toISOString() };
      await tx.insert(gatewayChallenges).values({ ...input, expiresAt: new Date(input.expiresAt) }).onConflictDoUpdate({ target: gatewayChallenges.deviceId, set: { challengeId: input.challengeId, nonce: input.nonce, expiresAt: new Date(input.expiresAt) } });
      return input;
    });
  }
  async renewGatewayIdentity(input: { identity: GatewayIdentity; challengeId: string; nonce: string; event: Omit<Event, "id">; now: string }): Promise<GatewayIdentity> {
    return this.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`gateway-identity:${input.identity.deviceId}`}))`);
      const challenge = (await tx.select().from(gatewayChallenges).where(eq(gatewayChallenges.deviceId, input.identity.deviceId)).limit(1))[0];
      if (!challenge || challenge.challengeId !== input.challengeId || challenge.nonce !== input.nonce || challenge.expiresAt.getTime() < Date.parse(input.now))
        throw new KilnError("UNAUTHENTICATED", 401, "Gateway renewal challenge is invalid or expired");
      const current = await identityFromDatabase(tx, input.identity.resourceId);
      if (!current || current.deviceId !== input.identity.deviceId || current.revokedAt)
        throw new KilnError("UNAUTHENTICATED", 401, "Gateway identity is not authorized");
      await tx.delete(gatewayCertificates).where(and(eq(gatewayCertificates.deviceId, input.identity.deviceId), eq(gatewayCertificates.current, 0)));
      await tx.update(gatewayCertificates).set({ current: 0, acceptedUntil: new Date(input.identity.previousCertificate!.acceptedUntil) }).where(and(eq(gatewayCertificates.deviceId, input.identity.deviceId), eq(gatewayCertificates.current, 1)));
      await tx.insert(gatewayCertificates).values({ ...input.identity.currentCertificate, deviceId: input.identity.deviceId, issuedAt: new Date(input.identity.currentCertificate.issuedAt), expiresAt: new Date(input.identity.currentCertificate.expiresAt), acceptedUntil: new Date(input.identity.currentCertificate.acceptedUntil), current: 1 });
      await tx.delete(gatewayChallenges).where(eq(gatewayChallenges.deviceId, input.identity.deviceId));
      await tx.insert(events).values({ ...input.event, timestamp: new Date(input.event.timestamp) });
      return input.identity;
    });
  }
  async revokeGatewayIdentity(resourceId: string, revokedAt: string, savedEvent: Omit<Event, "id">): Promise<void> {
    await this.db.transaction(async (tx) => {
      const rows = await tx.select({ deviceId: gatewayIdentities.deviceId }).from(gatewayIdentities).where(eq(gatewayIdentities.resourceId, resourceId));
      if (rows[0]) await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`gateway-identity:${rows[0].deviceId}`}))`);
      await tx.update(gatewayIdentities).set({ revokedAt: new Date(revokedAt) }).where(eq(gatewayIdentities.resourceId, resourceId));
      await tx.update(gatewayEnrollmentTokens).set({ tokenHash: "", expiresAt: new Date(revokedAt), publicKeyFingerprint: null, deviceId: null, certificateFingerprint: null }).where(eq(gatewayEnrollmentTokens.resourceId, resourceId));
      await tx.delete(gatewayChallenges).where(inArray(gatewayChallenges.deviceId, rows.map((row) => row.deviceId)));
      await tx.insert(events).values({ ...savedEvent, timestamp: new Date(savedEvent.timestamp) });
    });
  }
  async recordGatewayHeartbeat(input: { deviceId: string; certificateFingerprint: string; sequence: number; services: GatewaySignal; policy: GatewaySignal; reservation: GatewaySignal; receivedAt: string; event: Omit<Event, "id"> }): Promise<GatewayIdentity> {
    return this.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${`gateway-identity:${input.deviceId}`}))`);
      const row = (await tx.select().from(gatewayIdentities).where(eq(gatewayIdentities.deviceId, input.deviceId)).limit(1))[0];
      if (!row || row.revokedAt || input.sequence < row.nextSequence) throw new KilnError("UNAUTHENTICATED", 401, "Gateway heartbeat is not authorized");
      const cert = (await tx.select().from(gatewayCertificates).where(eq(gatewayCertificates.fingerprint, input.certificateFingerprint)).limit(1))[0];
      if (!cert || cert.deviceId !== row.deviceId || cert.acceptedUntil.getTime() < Date.parse(input.receivedAt)) throw new KilnError("UNAUTHENTICATED", 401, "Gateway certificate is not authorized");
      await tx.update(gatewayIdentities).set({ nextSequence: input.sequence + 1, lastSeenAt: new Date(input.receivedAt), lastServices: input.services, lastPolicy: input.policy, lastReservation: input.reservation }).where(eq(gatewayIdentities.deviceId, input.deviceId));
      await tx.insert(events).values({ ...input.event, timestamp: new Date(input.event.timestamp) });
      const saved = await identityFromDatabase(tx, row.resourceId);
      if (!saved) throw new Error("Gateway identity disappeared during heartbeat");
      return saved;
    });
  }
  async withResourceLock<T>(id: string, task: () => Promise<T>): Promise<T> {
    const previous = this.locks.get(id) ?? Promise.resolve();
    let release!: () => void;
    const next = new Promise<void>((resolve) => {
      release = resolve;
    });
    this.locks.set(id, next);
    await previous;
    try {
      return await task();
    } finally {
      release();
      if (this.locks.get(id) === next) this.locks.delete(id);
    }
  }
  async acquireSingletonWriter(): Promise<void> {
    this.writerClient = await this.pool.connect();
    const result = await this.writerClient.query<{ locked: boolean }>(
      "SELECT pg_try_advisory_lock(hashtext('kiln-api-writer')) AS locked",
    );
    if (!result.rows[0]?.locked) {
      this.writerClient.release();
      this.writerClient = null;
      throw new Error(
        "Another Kiln API writer already holds the database lock",
      );
    }
  }
  async migrate(sql: string): Promise<void> {
    await this.pool.query(sql);
  }
  private async activeLinuxImportPlans(): Promise<
    Array<{ installationId: string; plan: LinuxImportRun["plan"] }>
  > {
    const relation = await this.pool.query<{ rel: string | null }>(
      "SELECT to_regclass('public.linux_import_runs') AS rel",
    );
    if (!relation.rows[0]?.rel) return [];
    return this.db
      .select({
        installationId: linuxImportRuns.installationId,
        plan: linuxImportRuns.plan,
      })
      .from(linuxImportRuns)
      .where(eq(linuxImportRuns.status, "ACTIVE"));
  }
  async recoverUnfinishedOperations(): Promise<void> {
    const pending = await this.db
      .select()
      .from(operations)
      .where(eq(operations.status, "INTENT"));
    for (const operation of pending) {
      await this.db.transaction(async (tx) => {
        const resource = (
          await tx
            .select()
            .from(resources)
            .where(eq(resources.id, operation.resourceId))
            .limit(1)
        )[0];
        const reason: OperationSafeReason = operation.snapshot ? "RECOVERED_INTENT" : "LEGACY_UNRESOLVED";
        await tx
          .update(operations)
          .set({ status: "UNKNOWN", safeReason: reason })
          .where(eq(operations.id, operation.id));
        if (resource) await tx.insert(events).values({
          installationId: resource.installationId,
          projectId: resource.projectId,
          resourceId: resource.id,
          type: "resource.operation_recovered_unknown",
          timestamp: new Date(),
          payload: { operationId: operation.id, reason },
        });
      });
    }
    const provisioning = await this.db
      .select()
      .from(resources)
      .where(eq(resources.state, "PROVISIONING"));
    const activeLinuxImports = await this.activeLinuxImportPlans();
    for (const resource of provisioning) {
      if (resource.createdBy === "qualification" && resource.providerId === "proxmox" && resource.provenanceRequired === 1) {
        const run = (await this.db.select().from(qualificationRuns).where(eq(qualificationRuns.installationId, resource.installationId)).limit(1))[0];
        if (run && [run.plan.templateResourceId, run.plan.probeResourceId].includes(resource.id)) continue;
      }
      if (linuxImportDefersRecovery(resource, activeLinuxImports)) continue;
      const createOperation = await this.db
        .select()
        .from(operations)
        .where(
          and(
            eq(operations.resourceId, resource.id),
            eq(operations.kind, "create"),
          ),
        )
        .limit(1);
      if (createOperation[0]) continue;
      await this.db.transaction(async (tx) => {
        await tx
          .update(resources)
          .set({ state: "ERROR" })
          .where(
            and(
              eq(resources.id, resource.id),
              eq(resources.state, "PROVISIONING"),
            ),
          );
        await tx.insert(events).values({
          installationId: resource.installationId,
          projectId: resource.projectId,
          resourceId: resource.id,
          type: "resource.provisioning_recovered",
          timestamp: new Date(),
          payload: { code: "MISSING_CREATE_OPERATION" },
        });
      });
    }
  }
  async close(): Promise<void> {
    if (this.writerClient) {
      await this.writerClient.query(
        "SELECT pg_advisory_unlock(hashtext('kiln-api-writer'))",
      );
      this.writerClient.release();
    }
    await this.pool.end();
  }
}
