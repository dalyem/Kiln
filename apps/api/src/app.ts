import Fastify from "fastify";
import { createHash } from "node:crypto";
import {
  eventQuerySchema,
  doctorQuerySchema,
  gatewayCreateSchema,
  gatewayChallengeSchema,
  gatewayEnrollmentSchema,
  gatewayHeartbeatSchema,
  gatewayRenewSchema,
  incidentsQuerySchema,
  leaseSchema,
  networkProbeCreateSchema,
  networkProbeResultSchema,
  resourceCreateSchema,
  imageImportSchema,
  qualificationCreateSchema,
  qualificationIdSchema,
  linuxImportCreateSchema,
  linuxImportIdSchema,
} from "@kiln/api-schema";
import { TokenAuthenticator, requireInfrastructure, requireScope, type Identity } from "@kiln/auth";
import {
  KilnError,
  ResourceService,
  GatewayMonitor,
  GatewayService,
  DoctorService,
  GatewayIdentityService,
  NetworkProbeService,
  ImageProvenanceService,
  type NetworkProbeProfile,
  type GatewayCertificateIssuer,
  validateOwnership,
  type ComputeProvider,
  type Resource,
  type Store,
  type TrustedImageKeys,
  type LifecycleQualificationService,
  type LinuxImageImportService,
  type LinuxImageStaging,
} from "@kiln/core";
import { MemoryStore } from "@kiln/database";
import { FakeComputeProvider } from "@kiln/providers";

declare module "fastify" {
  interface FastifyRequest {
    identity?: Identity;
  }
}
export interface AppOptions {
  token?: string;
  infrastructureToken?: string;
  store?: Store;
  provider?: ComputeProvider;
  clock?: () => Date;
  gatewayIssuer?: GatewayCertificateIssuer;
  networkProbeProfiles?: NetworkProbeProfile[];
  trustedImageKeys?: TrustedImageKeys;
  qualificationService?: LifecycleQualificationService;
  qualificationToken?: string;
  linuxImportService?: LinuxImageImportService;
  linuxImportToken?: string;
  linuxImageStaging?: LinuxImageStaging;
}
export function createApp(options: AppOptions = {}) {
  const app = Fastify({ logger: false });
  const store = options.store ?? new MemoryStore();
  const provider = options.provider ?? new FakeComputeProvider();
  const service = new ResourceService(store, provider, options.clock);
  const gateways = new GatewayService(store, provider, options.clock);
  const monitor = new GatewayMonitor(store, provider, options.clock);
  const doctor = new DoctorService(store, provider, options.clock, options.networkProbeProfiles ?? []);
  const gatewayIdentity = options.gatewayIssuer ? new GatewayIdentityService(store, provider, options.gatewayIssuer, { clock: options.clock }) : null;
  const probeService = new NetworkProbeService(store, provider, options.networkProbeProfiles ?? [], service, options.clock);
  const provenance = new ImageProvenanceService(store, provider, options.trustedImageKeys ?? {}, options.clock);
  const qualification = options.qualificationService ?? null;
  const linuxImport = options.linuxImportService ?? null;
  const requireQualification = (request: Fastify.FastifyRequest) => {
    requireInfrastructure(request.identity!);
    if (!options.qualificationToken || request.headers["x-kiln-qualification-token"] !== options.qualificationToken)
      throw new KilnError("FORBIDDEN", 403, "Qualification credential is required");
    if (!qualification) throw new KilnError("UNSUPPORTED", 501, "Lifecycle qualification is disabled");
    return qualification;
  };
  const requireLinuxImport = (request: Fastify.FastifyRequest) => {
    requireInfrastructure(request.identity!);
    if (!options.linuxImportToken || request.headers["x-kiln-linux-import-token"] !== options.linuxImportToken)
      throw new KilnError("FORBIDDEN", 403, "Linux image import credential is required");
    if (!linuxImport || !options.linuxImageStaging) throw new KilnError("UNSUPPORTED", 501, "Linux image import is disabled");
    return linuxImport;
  };
  app.addContentTypeParser("application/octet-stream", (_request, payload, done) => done(null, payload));
  const authenticator = new TokenAuthenticator(options.token, options.infrastructureToken);
  app.get("/healthz", async () => ({ ok: true }));
  app.get("/readyz", async (_request, reply) => {
    try {
      await store.installationId();
      return { ok: true };
    } catch {
      reply.code(503);
      return { ok: false };
    }
  });
  app.addHook("onRequest", async (request, reply) => {
    if (!request.url.startsWith("/v1")) return;
    try {
      request.identity = authenticator.authenticate(
        request.headers.authorization,
      );
    } catch (error) {
      return sendError(reply, error);
    }
  });
  app.get("/v1/status", async (request, reply) => {
    const identity = request.identity!;
    requireScope(identity, "read");
    return {
      installationId: await store.installationId(),
      providerMode: provider.mode,
      mutationEnabled: provider.mode === "fake",
      monitoring: { enabled: true, repairEnabled: false },
      persistence:
        store instanceof MemoryStore ? "ephemeral-memory" : "postgres",
    };
  });
  app.get("/v1/doctor", async (request) => {
    requireScope(request.identity!, "read");
    const query = doctorQuerySchema.parse(request.query);
    return doctor.inspect(query.node);
  });
  app.get("/v1/incidents", async (request) => {
    requireScope(request.identity!, "read");
    const query = incidentsQuerySchema.parse(request.query);
    const incidents = await store.listGatewayIncidents(query.node);
    return { incidents: query.status === "all" ? incidents : incidents.filter((incident) => incident.status === "OPEN") };
  });
  app.get("/v1/gateways", async (request) => {
    requireScope(request.identity!, "admin");
    return { gateways: await store.listGateways() };
  });
  app.post("/v1/gateways/:id/enrollment-token", async (request) => {
    requireInfrastructure(request.identity!);
    if (!gatewayIdentity) throw new KilnError("UNSUPPORTED", 501, "Gateway identity TLS is not configured");
    return gatewayIdentity.issueEnrollmentToken((request.params as { id: string }).id);
  });
  app.get("/v1/gateways/:id/identity", async (request) => {
    requireInfrastructure(request.identity!);
    if (!gatewayIdentity) throw new KilnError("UNSUPPORTED", 501, "Gateway identity TLS is not configured");
    const identity = await gatewayIdentity.identity((request.params as { id: string }).id);
    if (!identity) return { identity: null };
    return { identity: redactGatewayIdentity(identity) };
  });
  app.post("/v1/gateways/:id/revoke-identity", async (request) => {
    requireInfrastructure(request.identity!);
    if (!gatewayIdentity) throw new KilnError("UNSUPPORTED", 501, "Gateway identity TLS is not configured");
    await gatewayIdentity.revoke((request.params as { id: string }).id);
    return { ok: true };
  });
  app.post("/v1/gateways/:id/probes", async (request, reply) => {
    requireInfrastructure(request.identity!);
    const key = request.headers["idempotency-key"];
    if (typeof key !== "string" || !key) throw new KilnError("INVALID_INPUT", 400, "Idempotency-Key is required");
    const input = networkProbeCreateSchema.parse(request.body);
    const result = await probeService.create((request.params as { id: string }).id, input.profileId, key, request.identity!.subject);
    reply.code(result.replayed ? 200 : 201);
    return redactProbe(result.probe, result.resource);
  });
  app.post("/v1/network-probes/:id/token", async (request) => {
    requireInfrastructure(request.identity!);
    return probeService.issueToken((request.params as { id: string }).id);
  });
  app.get("/v1/network-probes/:id", async (request) => {
    requireInfrastructure(request.identity!);
    const id = (request.params as { id: string }).id;
    const probe = await store.getNetworkProbe(id);
    if (!probe) throw new KilnError("NOT_FOUND", 404, "Network probe not found");
    const resource = await store.getResource(id);
    if (!resource) throw new KilnError("NOT_FOUND", 404, "Network probe resource not found");
    return redactProbe(probe, resource);
  });
  app.post("/v1/gateways", async (request, reply) => {
    requireInfrastructure(request.identity!);
    const key = request.headers["idempotency-key"];
    if (typeof key !== "string" || !key) throw new KilnError("INVALID_INPUT", 400, "Idempotency-Key is required");
    const input = gatewayCreateSchema.parse(request.body);
    const result = await gateways.createFakeGateway(input.node, key, request.identity!.subject);
    reply.code(result.replayed ? 200 : 201);
    return result.resource;
  });
  app.post("/v1/monitor/scan", async (request) => {
    requireInfrastructure(request.identity!);
    await monitor.scan();
    return { ok: true };
  });
  app.post("/v1/images/import", async (request, reply) => {
    requireInfrastructure(request.identity!);
    const key = request.headers["idempotency-key"];
    if (typeof key !== "string" || !key) throw new KilnError("INVALID_INPUT", 400, "Idempotency-Key is required");
    const input = imageImportSchema.parse(request.body);
    const result = await provenance.importImage(input, key, request.identity!.subject, input.node);
    reply.code(result.replayed ? 200 : 201);
    return { templateId: result.template.resourceId, imageManifestDigest: result.template.imageManifestDigest, state: result.template.state };
  });
  app.post("/v1/templates/:id/retire", async (request) => {
    requireInfrastructure(request.identity!);
    await provenance.retireTemplate((request.params as { id: string }).id);
    return { ok: true };
  });
  app.post("/v1/qualifications", async (request, reply) => {
    const service = requireQualification(request);
    const key = request.headers["idempotency-key"];
    if (typeof key !== "string" || !key) throw new KilnError("INVALID_INPUT", 400, "Idempotency-Key is required");
    const result = await service.createRun(qualificationCreateSchema.parse(request.body), key);
    reply.code(result.replayed ? 200 : 201);
    return { id: result.run.id, status: result.run.status, planDigest: result.run.plan.canonicalDigest, replayed: result.replayed };
  });
  app.get("/v1/qualifications/:id", async (request) => {
    const service = requireQualification(request);
    const { id } = qualificationIdSchema.parse(request.params);
    const status = await service.status(id);
    if (!status) throw new KilnError("NOT_FOUND", 404, "Qualification run was not found");
    return { id: status.run.id, status: status.run.status, planDigest: status.run.plan.canonicalDigest, artifactDisposition: status.run.plan.artifactDisposition, poolDisposition: status.run.plan.poolDisposition, phases: status.phases, allocations: status.allocations };
  });
  app.post("/v1/qualifications/:id/advance", async (request) => {
    const service = requireQualification(request);
    const { id } = qualificationIdSchema.parse(request.params);
    const run = await service.advance(id);
    return { id: run.id, status: run.status, planDigest: run.plan.canonicalDigest };
  });
  app.post("/v1/linux-import-staging", async (request, reply) => {
    requireLinuxImport(request);
    const key = request.headers["idempotency-key"];
    const expectedSha256 = request.headers["x-kiln-artifact-sha256"];
    if (typeof key !== "string" || !key) throw new KilnError("INVALID_INPUT", 400, "Idempotency-Key is required");
    if (typeof expectedSha256 !== "string" || !/^[a-f0-9]{64}$/.test(expectedSha256)) throw new KilnError("INVALID_INPUT", 400, "X-Kiln-Artifact-SHA256 is required");
    const length = Number(request.headers["content-length"]);
    const installationId = await store.installationId();
    const idempotencyDigest = createHash("sha256").update(key).digest("hex");
    const audit = (type: string, payload: Record<string, unknown>) => store.appendEvent({ installationId, projectId: "infrastructure", resourceId: null, type, timestamp: new Date().toISOString(), payload });
    await audit("linux_import.staging_requested", { subject: request.identity!.subject, idempotencyDigest, declaredSize: Number.isFinite(length) ? length : null, sha256: expectedSha256 });
    let staged;
    try {
      staged = await options.linuxImageStaging!.stage(request.body as AsyncIterable<Uint8Array>, Number.isFinite(length) ? length : undefined, { idempotencyKey: key, expectedSha256 });
      await audit("linux_import.staging_completed", { subject: request.identity!.subject, stagingId: staged.id, size: staged.size, sha256: staged.sha256, idempotencyDigest });
    } catch (error) {
      await audit("linux_import.staging_failed", { subject: request.identity!.subject, idempotencyDigest, code: error instanceof KilnError ? error.code : "INTERNAL" }).catch(() => undefined);
      throw error;
    }
    reply.code(201);
    return { stagingId: staged.id, size: staged.size, sha256: staged.sha256 };
  });
  app.post("/v1/linux-imports", { bodyLimit: 2 * 1024 * 1024 }, async (request, reply) => {
    const service = requireLinuxImport(request);
    const key = request.headers["idempotency-key"];
    if (typeof key !== "string" || !key) throw new KilnError("INVALID_INPUT", 400, "Idempotency-Key is required");
    const result = await service.createRun(linuxImportCreateSchema.parse(request.body), key);
    reply.code(result.replayed ? 200 : 201);
    return { id: result.run.id, status: result.run.status, planDigest: result.run.plan.canonicalDigest, replayed: result.replayed };
  });
  app.get("/v1/linux-imports/:id", async (request) => {
    const service = requireLinuxImport(request);
    const { id } = linuxImportIdSchema.parse(request.params);
    const status = await service.statusDetail(id);
    if (!status) throw new KilnError("NOT_FOUND", 404, "Linux image import was not found");
    const run = status.run;
    return { id: run.id, status: run.status, createdAt: run.createdAt, completedAt: run.completedAt, planDigest: run.plan.canonicalDigest, stagingId: run.plan.stageId, templateResourceId: run.plan.templateResourceId, cloneResourceId: run.plan.cloneResourceId, phases: status.phases };
  });
  app.post("/v1/linux-imports/:id/advance", async (request) => {
    const service = requireLinuxImport(request);
    const { id } = linuxImportIdSchema.parse(request.params);
    const run = await service.advance(id);
    return { id: run.id, status: run.status, planDigest: run.plan.canonicalDigest };
  });
  app.post("/v1/doctor/repair", async (request) => {
    requireInfrastructure(request.identity!);
    throw new KilnError("UNSUPPORTED", 501, "Gateway repair is disabled in this release");
  });
  app.get("/v1/resources", async (request) => {
    requireScope(request.identity!, "read");
    return {
      resources: await store.listResources(request.identity!.projectId),
    };
  });
  app.get("/v1/resources/:id", async (request) => {
    requireScope(request.identity!, "read");
    return service.requireResource(
      (request.params as { id: string }).id,
      request.identity!.projectId,
    );
  });
  app.get("/v1/resources/:id/operations", async (request) => {
    requireScope(request.identity!, "read");
    return {
      operations: await service.operationHistory(
      (request.params as { id: string }).id,
      request.identity!.projectId,
      ),
    };
  });
  app.get("/v1/resources/:id/provenance", async (request) => {
    requireScope(request.identity!, "read");
    await service.requireResource((request.params as { id: string }).id, request.identity!.projectId);
    return { provenance: await store.provenanceSummary((request.params as { id: string }).id) };
  });
  app.post("/v1/resources", async (request, reply) => {
    requireScope(request.identity!, "operate");
    if (provider.mode !== "fake")
      throw new KilnError(
        "UNSUPPORTED",
        501,
        "Resource creation is only available with the fake provider in Phase 1",
      );
    const key = request.headers["idempotency-key"];
    if (typeof key !== "string" || !key)
      throw new KilnError("INVALID_INPUT", 400, "Idempotency-Key is required");
    const input = resourceCreateSchema.parse(request.body);
    if (input.projectId !== request.identity!.projectId)
      throw new KilnError("UNAUTHORIZED", 403, "Project access denied");
    const result = await service.create(input, key, request.identity!.subject);
    reply.code(result.replayed ? 200 : 201);
    return result.resource;
  });
  app.post("/v1/resources/:id/stop", async (request) => {
    requireScope(request.identity!, "operate");
    return service.mutate(
      (request.params as { id: string }).id,
      "stop",
      request.identity!.projectId,
    );
  });
  app.delete("/v1/resources/:id", async (request) => {
    requireScope(request.identity!, "operate");
    return service.mutate(
      (request.params as { id: string }).id,
      "destroy",
      request.identity!.projectId,
    );
  });
  app.post("/v1/resources/:id/lease", async (request) => {
    requireScope(request.identity!, "operate");
    const input = leaseSchema.parse(request.body);
    return service.extend(
      (request.params as { id: string }).id,
      request.identity!.projectId,
      input.ttlSeconds,
    );
  });
  app.get("/v1/events", async (request) => {
    requireScope(request.identity!, "read");
    const query = eventQuerySchema.parse(request.query);
    const events = await store.events(request.identity!.projectId, query.after);
    return { events, nextCursor: events.at(-1)?.id ?? query.after };
  });
  app.get("/v1/inventory", async (request) => {
    requireScope(request.identity!, "admin");
    const inventory = await provider.discover();
    const installationId = await store.installationId();
    const known = new Map(
      (await store.listResources(request.identity!.projectId)).map(
        (resource) => [resource.providerResourceId, resource],
      ),
    );
    const resources = inventory.resources.map((observation) => {
      const record = known.get(observation.providerResourceId);
      if (!record)
        return {
          ...observation,
          ownership: "EXTERNAL",
          diagnostic: observation.tags.includes("kiln-managed")
            ? "ORPHANED"
            : undefined,
        };
      try {
        validateOwnership(record, installationId, observation);
        return { ...observation, ownership: record.ownership };
      } catch {
        return {
          ...observation,
          ownership: "EXTERNAL",
          diagnostic: "OWNERSHIP_MISMATCH",
        };
      }
    });
    return { ...inventory, resources, coverage: "permission-limited" };
  });
  app.setErrorHandler((error, _request, reply) => sendError(reply, error));
  return { app, store, provider, service, monitor, doctor, gateways, gatewayIdentity, probeService };
}
export function createGatewayEnrollmentApp(identity: GatewayIdentityService, https: import("node:https").ServerOptions, probeService?: NetworkProbeService) {
  const app = Fastify({ logger: false, https });
  app.post("/v1/gateway/enroll", async (request) => enrollmentResponse(await identity.enroll(gatewayEnrollmentSchema.parse(request.body))));
  app.post("/v1/gateway/challenge", async (request) => {
    const challenge = await identity.challenge(gatewayChallengeSchema.parse(request.body).deviceId);
    return gatewayChallengeResponse(challenge);
  });
  app.post("/v1/gateway/renew", async (request) => enrollmentResponse(await identity.renew(gatewayRenewSchema.parse(request.body))));
  if (probeService) {
    app.get("/v1/probes/:id/plan", async (request) => {
      const token = bearer(request.headers.authorization);
      return probeService.plan((request.params as { id: string }).id, token);
    });
    app.post("/v1/probes/:id/result", async (request) => {
      const token = bearer(request.headers.authorization);
      const input = networkProbeResultSchema.parse(request.body);
      return probeService.result((request.params as { id: string }).id, token, input.planDigest, input.results);
    });
  }
  app.setErrorHandler((error, _request, reply) => sendError(reply, error));
  return app;
}
function bearer(value: string | undefined): string {
  if (!value?.startsWith("Bearer ") || value.length <= 7) throw new KilnError("UNAUTHENTICATED", 401, "Network probe bearer token is required");
  return value.slice(7);
}
function redactProbe(probe: import("@kiln/core").NetworkProbeRecord, resource: Resource) {
  return { resource: { id: resource.id, state: resource.state, expiresAt: resource.expiresAt, node: resource.node }, probe: { id: probe.resourceId, state: probe.state, gatewayId: probe.gatewayId, gatewayGeneration: probe.gatewayGeneration, gatewayConfigFingerprint: probe.gatewayConfigFingerprint, profileId: probe.profileId, profileDigest: probe.profileDigest, plan: probe.plan, planDigest: probe.planDigest, resultDigest: probe.resultDigest, results: probe.results, receivedAt: probe.receivedAt, createdAt: probe.createdAt, placement: "UNVERIFIED" as const } };
}
export function createGatewayHeartbeatApp(identity: GatewayIdentityService, https: import("node:https").ServerOptions) {
  const app = Fastify({ logger: false, https });
  app.post("/v1/gateway/heartbeat", async (request) => {
    const socket = request.raw.socket as import("node:tls").TLSSocket;
    if (!socket.authorized) throw new KilnError("UNAUTHENTICATED", 401, "Mutual TLS client authentication is required");
    const peer = socket.getPeerCertificate(true);
    if (!peer || !peer.raw) throw new KilnError("UNAUTHENTICATED", 401, "Mutual TLS client authentication is required");
    const input = gatewayHeartbeatSchema.parse(request.body);
    const saved = await identity.heartbeat({ ...input, certificateFingerprint: createHash("sha256").update(peer.raw).digest("hex") });
    return { accepted: true, nextSequence: saved.nextSequence };
  });
  app.setErrorHandler((error, _request, reply) => sendError(reply, error));
  return app;
}
function enrollmentResponse(identity: import("@kiln/core").GatewayIdentity & { enrollmentCertificate?: import("@kiln/core").GatewayCertificate }) {
  const certificate = identity.enrollmentCertificate ?? identity.currentCertificate;
  return { deviceId: identity.deviceId, certificatePem: certificate.certificatePem, certificateExpiresAt: certificate.expiresAt, nextSequence: identity.nextSequence };
}
export function gatewayChallengeResponse(challenge: import("@kiln/core").GatewayChallenge) {
  return { challengeId: challenge.challengeId, nonce: challenge.nonce, expiresAt: challenge.expiresAt };
}
function redactGatewayIdentity(identity: import("@kiln/core").GatewayIdentity) {
  return { deviceId: identity.deviceId, resourceId: identity.resourceId, generation: identity.generation, publicKeyFingerprint: identity.publicKeyFingerprint, revokedAt: identity.revokedAt, certificate: { fingerprint: identity.currentCertificate.fingerprint, expiresAt: identity.currentCertificate.expiresAt }, previousCertificate: identity.previousCertificate ? { fingerprint: identity.previousCertificate.fingerprint, expiresAt: identity.previousCertificate.expiresAt, acceptedUntil: identity.previousCertificate.acceptedUntil } : null, nextSequence: identity.nextSequence, lastSeenAt: identity.lastSeenAt, lastServices: identity.lastServices, lastPolicy: identity.lastPolicy, lastReservation: identity.lastReservation };
}
function sendError(
  reply: { code: (status: number) => { send: (body: unknown) => unknown } },
  error: unknown,
) {
  if (error instanceof KilnError)
    return reply
      .code(error.status)
      .send({ error: { code: error.code, message: error.message } });
  const issue = error as { code?: string; issues?: unknown };
  if (issue.code === "IDEMPOTENCY_CONFLICT")
    return reply.code(409).send({
      error: {
        code: "IDEMPOTENCY_CONFLICT",
        message: "Idempotency key was used with a different request",
      },
    });
  if (issue.issues)
    return reply.code(400).send({
      error: { code: "INVALID_INPUT", message: "Request validation failed" },
    });
  const fastifyError = error as { statusCode?: number };
  if ([400, 413, 415].includes(fastifyError.statusCode ?? 0))
    return reply.code(fastifyError.statusCode!).send({
      error: { code: "INVALID_INPUT", message: "Request validation failed" },
    });
  return reply
    .code(500)
    .send({ error: { code: "INTERNAL", message: "Internal server error" } });
}
