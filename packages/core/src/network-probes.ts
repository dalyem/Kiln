import { createHash, randomBytes, randomUUID, X509Certificate } from "node:crypto";
import { isIP } from "node:net";
import {
  KilnError,
  type ComputeProvider,
  type Event,
  type NetworkProbeCheck,
  type NetworkProbePlan,
  type NetworkProbeProfile,
  type NetworkProbeRecord,
  type NetworkProbeResult,
  type NetworkProbeResultCode,
  type Resource,
  type Store,
  ProviderOperationExecutor,
  operationBindingMatches,
  validateOwnership,
} from "./index.js";

const profileId = /^[a-zA-Z0-9_-]{1,64}$/;
const resultCodes: Record<NetworkProbeCheck["kind"], ReadonlySet<NetworkProbeResultCode>> = {
  dns: new Set(["DNS_ANSWER", "DNS_EMPTY", "DNS_ERROR", "TIMEOUT"]),
  https: new Set(["HTTPS_EXPECTED", "HTTPS_UNEXPECTED", "HTTPS_REDIRECT", "HTTPS_ERROR", "TIMEOUT"]),
  tcp: new Set(["TCP_CONNECTED", "TCP_FAILED", "TIMEOUT"]),
};

export function validateNetworkProbeProfiles(value: unknown): NetworkProbeProfile[] {
  if (!Array.isArray(value)) throw new Error("KILN_PROBE_PROFILES_FILE must contain an array");
  const profiles = value.map(validateProfile);
  if (new Set(profiles.map((profile) => profile.id)).size !== profiles.length)
    throw new Error("Network probe profile IDs must be unique");
  return profiles;
}
export function validateNetworkProbeRuntime(profiles: NetworkProbeProfile[], gatewayTlsConfigured: boolean): void {
  if (profiles.length > 0 && !gatewayTlsConfigured)
    throw new Error("KILN_PROBE_PROFILES_FILE requires complete gateway TLS configuration");
}

function validateProfile(value: unknown): NetworkProbeProfile {
  if (!isRecord(value) || Object.keys(value).some((key) => !["id", "ttlSeconds", "checks"].includes(key)))
    throw new Error("Network probe profile has unknown or invalid fields");
  if (typeof value.id !== "string" || !profileId.test(value.id)) throw new Error("Network probe profile ID is invalid");
  if (typeof value.ttlSeconds !== "number" || !Number.isInteger(value.ttlSeconds) || value.ttlSeconds < 60 || value.ttlSeconds > 600)
    throw new Error("Network probe profile ttlSeconds must be between 60 and 600");
  if (!Array.isArray(value.checks) || value.checks.length < 1 || value.checks.length > 8)
    throw new Error("Network probe profile must contain one to eight checks");
  const checks = value.checks.map(validateCheck);
  if (new Set(checks.map((check) => check.id)).size !== checks.length)
    throw new Error("Network probe check IDs must be unique");
  if (checks.reduce((total, check) => total + check.timeoutMs, 0) > 30_000)
    throw new Error("Network probe check timeouts exceed 30000ms");
  return { id: value.id, ttlSeconds: value.ttlSeconds, checks };
}

function validateCheck(value: unknown): NetworkProbeCheck {
  if (!isRecord(value) || typeof value.kind !== "string" || typeof value.id !== "string" || !profileId.test(value.id) || !validTimeout(value.timeoutMs))
    throw new Error("Network probe check is invalid");
  if (value.kind === "dns") {
    requireKeys(value, ["id", "kind", "hostname", "resolverAddress", "resolverPort", "timeoutMs"]);
    if (!hostname(value.hostname) || typeof value.resolverAddress !== "string" || isIP(value.resolverAddress) === 0 || !validPort(value.resolverPort)) throw new Error("DNS probe check is invalid");
    return { id: value.id, kind: "dns", hostname: value.hostname, resolverAddress: value.resolverAddress, resolverPort: value.resolverPort, timeoutMs: value.timeoutMs };
  }
  if (value.kind === "https") {
    requireKeys(value, ["id", "kind", "url", "expectedStatus", "caPem", "timeoutMs"], ["caPem"]);
    const caPem = value.caPem;
    if (typeof value.url !== "string" || !safeHttpsUrl(value.url) || typeof value.expectedStatus !== "number" || !Number.isInteger(value.expectedStatus) || value.expectedStatus < 200 || value.expectedStatus > 299 || (caPem !== undefined && (typeof caPem !== "string" || !certPem(caPem)))) throw new Error("HTTPS probe check is invalid");
    return { id: value.id, kind: "https", url: value.url, expectedStatus: value.expectedStatus, ...(typeof caPem === "string" ? { caPem } : {}), timeoutMs: value.timeoutMs };
  }
  if (value.kind === "tcp") {
    requireKeys(value, ["id", "kind", "address", "port", "expect", "timeoutMs"]);
    if (typeof value.address !== "string" || isIP(value.address) === 0 || !validPort(value.port) || (value.expect !== "reachable" && value.expect !== "blocked")) throw new Error("TCP probe check is invalid");
    return { id: value.id, kind: "tcp", address: value.address, port: value.port, expect: value.expect, timeoutMs: value.timeoutMs };
  }
  throw new Error("Network probe check kind is invalid");
}

function isRecord(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value); }
function requireKeys(value: Record<string, unknown>, keys: string[], optional: string[] = []): void { if (Object.keys(value).some((key) => !keys.includes(key)) || keys.some((key) => !optional.includes(key) && !(key in value))) throw new Error("Network probe check has unknown or missing fields"); }
function validTimeout(value: unknown): value is number { return typeof value === "number" && Number.isInteger(value) && value >= 100 && value <= 5000; }
function validPort(value: unknown): value is number { return typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= 65535; }
function hostname(value: unknown): value is string {
  if (typeof value !== "string" || value.length < 1 || value.length > 253 || value.endsWith(".")) return false;
  return value.split(".").every((label) => label.length >= 1 && label.length <= 63 && !label.startsWith("-") && !label.endsWith("-") && /^[a-zA-Z0-9-]+$/.test(label));
}
function safeHttpsUrl(value: string): boolean { if (/[\x00-\x1f\x7f]/.test(value)) return false; try { const url = new URL(value); return url.protocol === "https:" && hostname(url.hostname) && !url.username && !url.password && !url.search && !url.hash && (url.port === "" || validPort(Number(url.port))); } catch { return false; } }
function certPem(value: string): boolean { if (value.length > 16_384 || !/^-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\r?\n?$/.test(value)) return false; try { new X509Certificate(value); return true; } catch { return false; } }
function digest(value: unknown): string { return createHash("sha256").update(JSON.stringify(value)).digest("hex"); }
function tokenHash(token: string): string { return createHash("sha256").update(token).digest("hex"); }
function event(resource: Resource, type: string, payload: Record<string, unknown>, now: Date): Omit<Event, "id"> { return { installationId: resource.installationId, projectId: resource.projectId, resourceId: resource.id, type, timestamp: now.toISOString(), payload }; }

export class NetworkProbeService {
  constructor(private readonly store: Store, private readonly provider: ComputeProvider, private readonly profiles: NetworkProbeProfile[], private readonly resources: { mutate(id: string, operation: "destroy", projectId: string, requireExpired?: boolean): Promise<Resource> }, private readonly clock = () => new Date()) {}

  async create(gatewayId: string, profileIdValue: string, idempotencyKey: string, createdBy: string): Promise<{ resource: Resource; probe: NetworkProbeRecord; replayed: boolean }> {
    if (this.provider.mode !== "fake") throw new KilnError("UNSUPPORTED", 501, "Network probe creation is only available with the fake provider");
    const profile = this.profiles.find((candidate) => candidate.id === profileIdValue);
    if (!profile) throw new KilnError("NOT_FOUND", 404, "Network probe profile is not configured");
    return this.store.withResourceLock(`probe-create:${idempotencyKey}`, async () => {
      const installationId = await this.store.installationId();
      const normalizedPayload = JSON.stringify({ installationId, gatewayId, profileId: profile.id });
      const stored = await this.store.idempotentResource(`${installationId}:probe:${idempotencyKey}`, normalizedPayload);
      if (stored) {
        const probe = await this.store.getNetworkProbe(stored.id);
        if (!probe) throw new Error("Network probe idempotency record has no probe job");
        return { resource: stored, probe, replayed: true };
      }
      const gateway = await this.requireGateway(gatewayId, installationId);
      const now = this.clock();
      const id = `probe_${randomUUID().replaceAll("-", "")}`;
      const expiresAt = new Date(now.getTime() + profile.ttlSeconds * 1000).toISOString();
      const resource: Resource = { id, installationId, projectId: "infrastructure", type: "network_probe", ownership: "KILN_MANAGED", state: "PROVISIONING", providerId: this.provider.id, providerResourceId: id, providerKind: "fake", node: gateway.metadata.node, pool: "kiln", createdBy, createdAt: now.toISOString(), expiresAt, profile: profile.id };
      const profileDigest = digest(profile);
      const plan: NetworkProbePlan = { schemaVersion: 1, probeId: id, installationId, gatewayId, gatewayGeneration: gateway.metadata.generation, gatewayConfigFingerprint: gateway.metadata.expectedFingerprint, profileId: profile.id, profileDigest, expiresAt, checks: profile.checks };
      const probe: NetworkProbeRecord = { resourceId: id, installationId, gatewayId, gatewayGeneration: gateway.metadata.generation, gatewayConfigFingerprint: gateway.metadata.expectedFingerprint, node: gateway.metadata.node, profileId: profile.id, profileDigest, plan, planDigest: digest(plan), state: "PENDING", tokenHash: null, tokenExpiresAt: null, resultDigest: null, results: null, receivedAt: null, createdAt: now.toISOString() };
      const created = await this.store.createNetworkProbe(resource, probe, `${installationId}:probe:${idempotencyKey}`, normalizedPayload, event(resource, "network_probe.create_intent", { gatewayId, profileId: profile.id }, now));
      if (created.replayed) return created;
      const executor = new ProviderOperationExecutor(this.store, this.provider, this.clock);
      let createdObservation: import("./index.js").OwnershipObservation | null = null;
      await executor.dispatch(
        resource,
        "create",
        "network_probe.create",
        async () => { createdObservation = await this.provider.create(structuredClone(resource)); },
        async (operation) => {
          const observed = createdObservation ?? await this.provider.inspect(resource.providerResourceId);
          if (!observed) throw new KilnError("SAFETY_DENIED", 403, "Provider network probe is missing after create");
          validateOwnership(resource, installationId, observed);
          if (!await operationBindingMatches(operation, resource, this.store, this.provider))
            throw new KilnError("SAFETY_DENIED", 403, "Provider operation binding changed before completion");
          resource.state = "READY";
          await this.store.completeOperationTransition(operation.id, resource, event(resource, "network_probe.created", { operationId: operation.id }, this.clock()));
        },
      );
      return { resource, probe, replayed: false };
    });
  }

  async issueToken(id: string): Promise<{ token: string; expiresAt: string }> {
    return this.store.withResourceLock(id, async () => {
      const probe = await this.requirePendingProbe(id);
      await this.validateBinding(probe);
      const now = this.clock();
      const token = randomBytes(32).toString("base64url");
      await this.store.issueNetworkProbeToken(id, tokenHash(token), probe.plan.expiresAt, event(await this.requireResource(id), "network_probe.token_issued", {}, now));
      return { token, expiresAt: probe.plan.expiresAt };
    });
  }

  async plan(id: string, bearer: string): Promise<{ plan: NetworkProbePlan; planDigest: string }> {
    return this.store.withResourceLock(id, async () => {
      const probe = await this.authorize(id, bearer);
      if (probe.state !== "PENDING") throw new KilnError("CONFLICT", 409, "Network probe is no longer live");
      await this.validateBinding(probe);
      return { plan: probe.plan, planDigest: probe.planDigest };
    });
  }

  async result(id: string, bearer: string, planDigest: string, results: NetworkProbeResult[]): Promise<{ accepted: true; probeId: string; resultDigest: string }> {
    return this.store.withResourceLock(id, async () => {
      const probe = await this.authorize(id, bearer);
      if (planDigest !== probe.planDigest) throw new KilnError("CONFLICT", 409, "Network probe plan digest does not match");
      validateResults(probe.plan.checks, results);
      const resultDigest = digest({ planDigest, results });
      if (probe.resultDigest === resultDigest && probe.tokenExpiresAt && probe.tokenExpiresAt >= this.clock().toISOString()) {
        await this.validateCompletedReplay(probe);
        return { accepted: true, probeId: id, resultDigest };
      }
      if (probe.resultDigest) throw new KilnError("CONFLICT", 409, "Network probe already has a different result");
      await this.validateBinding(probe);
      const resource = await this.requireResource(id);
      const saved = await this.store.acceptNetworkProbeResult({ resourceId: id, planDigest, resultDigest, results, receivedAt: this.clock().toISOString(), event: event(resource, "network_probe.result_received", { resultDigest }, this.clock()) });
      if (saved.probe.resultDigest !== resultDigest) throw new KilnError("CONFLICT", 409, "Network probe already has a different result");
      return { accepted: true, probeId: id, resultDigest };
    });
  }

  async expire(): Promise<void> {
    for (const probe of await this.store.expiredNetworkProbes(this.clock().toISOString())) {
      await this.store.withResourceLock(probe.resourceId, async () => {
        const current = await this.store.getNetworkProbe(probe.resourceId);
        if (!current) return;
        const resource = await this.store.getResource(current.resourceId);
        if (!resource) return;
        await this.store.timeoutNetworkProbe(current.resourceId, "TIMED_OUT", event(resource, "network_probe.timed_out", {}, this.clock()));
      });
      try { await this.resources.mutate(probe.resourceId, "destroy", "infrastructure", probe.state !== "COMPLETED" && probe.state !== "CANCELLED" && probe.state !== "INVALIDATED"); }
      catch (error) {
        if (error instanceof KilnError && error.code === "OPERATION_UNRESOLVED") continue;
        const resource = await this.store.getResource(probe.resourceId);
        if (resource) await this.store.appendEvent(event(resource, "network_probe.cleanup_failed", { code: error instanceof KilnError ? error.code : "PROVIDER_FAILURE" }, this.clock()));
      }
    }
  }

  private async authorize(id: string, bearer: string): Promise<NetworkProbeRecord> {
    const probe = await this.store.getNetworkProbe(id);
    if (!probe || (probe.state !== "PENDING" && probe.state !== "COMPLETED")) throw new KilnError("NOT_FOUND", 404, "Network probe not found");
    if (!probe.tokenHash || !probe.tokenExpiresAt || probe.tokenExpiresAt < this.clock().toISOString() || tokenHash(bearer) !== probe.tokenHash) throw new KilnError("UNAUTHENTICATED", 401, "Network probe token is invalid or expired");
    return probe;
  }
  private async requirePendingProbe(id: string): Promise<NetworkProbeRecord> { const probe = await this.store.getNetworkProbe(id); if (!probe) throw new KilnError("NOT_FOUND", 404, "Network probe not found"); if (probe.state !== "PENDING") throw new KilnError("CONFLICT", 409, "Network probe is no longer live"); if (probe.plan.expiresAt < this.clock().toISOString()) throw new KilnError("UNAUTHENTICATED", 401, "Network probe has expired"); return probe; }
  private async requireResource(id: string): Promise<Resource> { const resource = await this.store.getResource(id); if (!resource) throw new KilnError("NOT_FOUND", 404, "Network probe resource not found"); return resource; }
  private async requireGateway(id: string, installationId: string) { const entries = await this.store.listGateways(); const gateway = entries.find((entry) => entry.resource.id === id); if (!gateway || gateway.resource.installationId !== installationId || gateway.resource.ownership !== "KILN_MANAGED" || gateway.resource.state !== "READY") throw new KilnError("SAFETY_DENIED", 403, "Gateway is not eligible for a network probe"); const observed = await this.provider.inspect(gateway.resource.providerResourceId); if (!observed) throw new KilnError("SAFETY_DENIED", 403, "Gateway provider observation is missing"); validateOwnership(gateway.resource, installationId, observed); return gateway; }
  private async validateBinding(probe: NetworkProbeRecord): Promise<void> { const installationId = await this.store.installationId(); const profile = this.profiles.find((candidate) => candidate.id === probe.profileId); if (installationId !== probe.installationId || !profile || digest(profile) !== probe.profileDigest) throw new KilnError("SAFETY_DENIED", 403, "Network probe binding changed"); const resource = await this.requireResource(probe.resourceId); if (await this.store.unresolvedOperation(resource.id)) throw new KilnError("OPERATION_UNRESOLVED", 409, "Network probe has an unresolved provider operation"); if (resource.installationId !== installationId || resource.type !== "network_probe" || resource.ownership !== "KILN_MANAGED" || resource.node !== probe.node || resource.state !== "READY") throw new KilnError("SAFETY_DENIED", 403, "Network probe ownership or state changed"); const observed = await this.provider.inspect(resource.providerResourceId); if (!observed) throw new KilnError("SAFETY_DENIED", 403, "Network probe provider observation is missing"); validateOwnership(resource, installationId, observed); const gateway = await this.requireGateway(probe.gatewayId, installationId); if (gateway.metadata.generation !== probe.gatewayGeneration || gateway.metadata.expectedFingerprint !== probe.gatewayConfigFingerprint || gateway.metadata.node !== probe.node) throw new KilnError("SAFETY_DENIED", 403, "Gateway binding changed"); }
  private async validateCompletedReplay(probe: NetworkProbeRecord): Promise<void> { const installationId = await this.store.installationId(); const profile = this.profiles.find((candidate) => candidate.id === probe.profileId); if (installationId !== probe.installationId || !profile || digest(profile) !== probe.profileDigest) throw new KilnError("SAFETY_DENIED", 403, "Network probe profile changed"); const gateway = await this.requireGateway(probe.gatewayId, installationId); if (gateway.metadata.generation !== probe.gatewayGeneration || gateway.metadata.expectedFingerprint !== probe.gatewayConfigFingerprint || gateway.metadata.node !== probe.node) throw new KilnError("SAFETY_DENIED", 403, "Gateway binding changed"); }
}

function validateResults(checks: NetworkProbeCheck[], results: NetworkProbeResult[]): void {
  if (!Array.isArray(results) || results.length !== checks.length) throw new KilnError("INVALID_INPUT", 400, "Network probe results do not match the plan");
  const byId = new Map(results.map((result) => [result.id, result]));
  if (byId.size !== results.length) throw new KilnError("INVALID_INPUT", 400, "Network probe results contain duplicate IDs");
  for (const check of checks) {
    const result = byId.get(check.id);
    if (!result || !resultCodes[check.kind].has(result.code) || !Number.isInteger(result.durationMs) || result.durationMs < 0 || result.durationMs > 30_000) throw new KilnError("INVALID_INPUT", 400, "Network probe result is invalid");
  }
}
