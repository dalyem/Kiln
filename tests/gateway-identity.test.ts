import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  GatewayIdentityService,
  publicKeyFingerprint,
  type GatewayCertificateIssuer,
} from "@kiln/core";
import { MemoryStore } from "@kiln/database";
import { FakeComputeProvider } from "@kiln/providers";
import { GatewayMonitor, GatewayService, ResourceService } from "@kiln/core";
import { gatewayChallengeResponse } from "../apps/api/src/app.js";

const privateKeys = new Map<string, ReturnType<typeof generateKeyPairSync>["privateKey"]>();

describe("gateway device identity", () => {
  it("returns only the documented renewal challenge fields", () => {
    expect(gatewayChallengeResponse({ deviceId: "gwd_test", challengeId: "chl_test", nonce: "nonce", expiresAt: "2026-01-01T00:00:00.000Z" })).toEqual({ challengeId: "chl_test", nonce: "nonce", expiresAt: "2026-01-01T00:00:00.000Z" });
  });
  it("holds admission as soon as an enrollment token exists and does not restore fake readiness", async () => {
    const store = new MemoryStore();
    const provider = new FakeComputeProvider();
    const gateway = await new GatewayService(store, provider).createFakeGateway("fake-node", "hold", "infra");
    await new GatewayMonitor(store, provider).scan();
    await new GatewayIdentityService(store, provider, issuer()).issueEnrollmentToken(gateway.resource.id);
    await expect(new ResourceService(store, provider).create({ type: "execution", projectId: "default", ttlSeconds: 60 }, "held", "agent")).rejects.toMatchObject({ code: "NETWORK_NOT_READY" });
    await new GatewayMonitor(store, provider).scan();
    expect((await store.listGateways())[0]?.health).toMatchObject({ status: "NOT_READY", evidence: { canary: "UNKNOWN" } });
  });
  it("does not persist a token when its audit event fails", async () => {
    class FailingAuditStore extends MemoryStore { fail = false; override async appendEvent(event: Parameters<MemoryStore["appendEvent"]>[0]) { if (this.fail) throw new Error("audit unavailable"); return super.appendEvent(event); } }
    const store = new FailingAuditStore(); const provider = new FakeComputeProvider();
    const gateway = await new GatewayService(store, provider).createFakeGateway("fake-node", "audit", "infra");
    store.fail = true;
    await expect(new GatewayIdentityService(store, provider, issuer()).issueEnrollmentToken(gateway.resource.id)).rejects.toThrow("audit unavailable");
    expect(await store.getGatewayEnrollmentToken(gateway.resource.id)).toBeNull();
  });
  it("keeps a revoked pending token as an admission hold while denying its use", async () => {
    const store = new MemoryStore(); const provider = new FakeComputeProvider();
    const gateway = await new GatewayService(store, provider).createFakeGateway("fake-node", "pending-revoke", "infra");
    const service = new GatewayIdentityService(store, provider, issuer());
    await new GatewayMonitor(store, provider).scan();
    const token = await service.issueEnrollmentToken(gateway.resource.id);
    await service.revoke(gateway.resource.id);
    expect(await store.getGatewayEnrollmentToken(gateway.resource.id)).not.toBeNull();
    const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" }); const publicKeyPem = pair.publicKey.export({ type: "spki", format: "pem" }).toString(); const proof = ["kiln-gateway-enroll-v1", token.installationId, token.resourceId, token.generation, token.token, publicKeyFingerprint(publicKeyPem)].join("\n");
    await expect(service.enroll({ ...token, publicKeyPem, signature: sign("sha256", Buffer.from(proof), pair.privateKey).toString("base64") })).rejects.toMatchObject({ code: "UNAUTHENTICATED" });
    await new GatewayMonitor(store, provider).scan();
    await expect(new ResourceService(store, provider).create({ type: "execution", projectId: "default", ttlSeconds: 60 }, "revoke-hold", "agent")).rejects.toMatchObject({ code: "NETWORK_NOT_READY" });
  });
  it("allows only an exact same-key enrollment replay and records a monotonic heartbeat", async () => {
    let now = new Date("2026-01-01T00:00:00.000Z");
    const store = new MemoryStore();
    const provider = new FakeComputeProvider();
    const gateway = await new GatewayService(store, provider, () => now).createFakeGateway("fake-node", "identity", "infra");
    const service = new GatewayIdentityService(store, provider, issuer(), { clock: () => now });
    await service.initialize();
    const enrollment = await service.issueEnrollmentToken(gateway.resource.id);
    const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const publicKeyPem = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
    const proof = ["kiln-gateway-enroll-v1", enrollment.installationId, enrollment.resourceId, enrollment.generation, enrollment.token, publicKeyFingerprint(publicKeyPem)].join("\n");
    const request = { ...enrollment, publicKeyPem, signature: sign("sha256", Buffer.from(proof), pair.privateKey).toString("base64") };
    const first = await service.enroll(request);
    const replay = await service.enroll(request);
    expect(replay.currentCertificate.fingerprint).toBe(first.currentCertificate.fingerprint);
    const other = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const otherPublicKey = other.publicKey.export({ type: "spki", format: "pem" }).toString();
    const otherProof = ["kiln-gateway-enroll-v1", enrollment.installationId, enrollment.resourceId, enrollment.generation, enrollment.token, publicKeyFingerprint(otherPublicKey)].join("\n");
    await expect(service.enroll({ ...enrollment, publicKeyPem: otherPublicKey, signature: sign("sha256", Buffer.from(otherProof), other.privateKey).toString("base64") })).rejects.toMatchObject({ code: "UNAUTHENTICATED" });
    const heartbeat = await service.heartbeat({ deviceId: first.deviceId, certificateFingerprint: first.currentCertificate.fingerprint, sequence: 3, services: "PASS", policy: "UNKNOWN", reservation: "UNKNOWN" });
    expect(heartbeat.nextSequence).toBe(4);
    await expect(service.heartbeat({ deviceId: first.deviceId, certificateFingerprint: first.currentCertificate.fingerprint, sequence: 3, services: "PASS", policy: "UNKNOWN", reservation: "UNKNOWN" })).rejects.toMatchObject({ code: "UNAUTHENTICATED" });
  });
  it("rejects an invalid token before asking the certificate issuer to sign", async () => {
    let issued = 0;
    const trackingIssuer: GatewayCertificateIssuer = { fingerprint: "issuer", async issue(input) { issued += 1; const at = input.now.toISOString(); return { fingerprint: "never", certificatePem: "never", issuedAt: at, expiresAt: at, acceptedUntil: at }; } };
    const store = new MemoryStore(); const provider = new FakeComputeProvider();
    const gateway = await new GatewayService(store, provider).createFakeGateway("fake-node", "invalid-token", "infra");
    const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" }); const publicKeyPem = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
    const generation = (await store.getGateway(gateway.resource.id))!.generation; const installationId = await store.installationId();
    const proof = ["kiln-gateway-enroll-v1", installationId, gateway.resource.id, generation, "bad", publicKeyFingerprint(publicKeyPem)].join("\n");
    await expect(new GatewayIdentityService(store, provider, trackingIssuer).enroll({ installationId, resourceId: gateway.resource.id, generation, token: "bad", publicKeyPem, signature: sign("sha256", Buffer.from(proof), pair.privateKey).toString("base64") })).rejects.toMatchObject({ code: "UNAUTHENTICATED" });
    expect(issued).toBe(0);
  });
  it("replays a consumed token without issuing another certificate", async () => {
    let issued = 0;
    const trackingIssuer: GatewayCertificateIssuer = { fingerprint: "issuer", async issue(input) { issued += 1; const at = input.now.toISOString(); return { fingerprint: `cert-${issued}`, certificatePem: "cert", issuedAt: at, expiresAt: new Date(input.now.getTime() + 60_000).toISOString(), acceptedUntil: new Date(input.now.getTime() + 60_000).toISOString() }; } };
    const store = new MemoryStore(); const provider = new FakeComputeProvider(); const gateway = await new GatewayService(store, provider).createFakeGateway("fake-node", "replay-signer", "infra");
    const service = new GatewayIdentityService(store, provider, trackingIssuer); const token = await service.issueEnrollmentToken(gateway.resource.id);
    const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" }); const publicKeyPem = pair.publicKey.export({ type: "spki", format: "pem" }).toString(); const proof = ["kiln-gateway-enroll-v1", token.installationId, token.resourceId, token.generation, token.token, publicKeyFingerprint(publicKeyPem)].join("\n"); const request = { ...token, publicKeyPem, signature: sign("sha256", Buffer.from(proof), pair.privateKey).toString("base64") };
    await service.enroll(request); await service.enroll(request);
    expect(issued).toBe(1);
  });
  it("permits the previous certificate only during renewal grace and rejects revocation", async () => {
    let now = new Date("2026-01-01T00:00:00.000Z");
    const store = new MemoryStore();
    const provider = new FakeComputeProvider();
    const gateway = await new GatewayService(store, provider, () => now).createFakeGateway("fake-node", "renew", "infra");
    const service = new GatewayIdentityService(store, provider, issuer(), { clock: () => now, timing: { previousCertificateGraceMs: 1_000, renewalAfterMs: 0 } });
    await service.initialize();
    const token = await service.issueEnrollmentToken(gateway.resource.id);
    const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const publicKeyPem = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
    const enrollmentProof = ["kiln-gateway-enroll-v1", token.installationId, token.resourceId, token.generation, token.token, publicKeyFingerprint(publicKeyPem)].join("\n");
    const enrolled = await service.enroll({ ...token, publicKeyPem, signature: sign("sha256", Buffer.from(enrollmentProof), pair.privateKey).toString("base64") });
    const challenge = await service.challenge(enrolled.deviceId);
    const renewalProof = ["kiln-gateway-renew-v1", enrolled.installationId, enrolled.resourceId, enrolled.generation, enrolled.deviceId, challenge.challengeId, challenge.nonce].join("\n");
    const renewed = await service.renew({ deviceId: enrolled.deviceId, challengeId: challenge.challengeId, nonce: challenge.nonce, signature: sign("sha256", Buffer.from(renewalProof), pair.privateKey).toString("base64") });
    const enrollmentReplay = await service.enroll({ ...token, publicKeyPem, signature: sign("sha256", Buffer.from(enrollmentProof), pair.privateKey).toString("base64") });
    expect(enrollmentReplay.enrollmentCertificate.fingerprint).toBe(enrolled.currentCertificate.fingerprint);
    expect(enrollmentReplay.currentCertificate.fingerprint).toBe(renewed.currentCertificate.fingerprint);
    await service.heartbeat({ deviceId: enrolled.deviceId, certificateFingerprint: enrolled.currentCertificate.fingerprint, sequence: 1, services: "PASS", policy: "UNKNOWN", reservation: "UNKNOWN" });
    now = new Date(now.getTime() + 1_001);
    await expect(service.heartbeat({ deviceId: enrolled.deviceId, certificateFingerprint: enrolled.currentCertificate.fingerprint, sequence: 2, services: "PASS", policy: "UNKNOWN", reservation: "UNKNOWN" })).rejects.toMatchObject({ code: "UNAUTHENTICATED" });
    await service.revoke(gateway.resource.id);
    await expect(service.heartbeat({ deviceId: renewed.deviceId, certificateFingerprint: renewed.currentCertificate.fingerprint, sequence: 2, services: "PASS", policy: "UNKNOWN", reservation: "UNKNOWN" })).rejects.toMatchObject({ code: "UNAUTHENTICATED" });
    await expect(service.enroll({ ...token, publicKeyPem, signature: sign("sha256", Buffer.from(enrollmentProof), pair.privateKey).toString("base64") })).rejects.toMatchObject({ code: "UNAUTHENTICATED" });
    const recovery = await service.issueEnrollmentToken(gateway.resource.id);
    const replacement = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const replacementKey = replacement.publicKey.export({ type: "spki", format: "pem" }).toString();
    const replacementProof = ["kiln-gateway-enroll-v1", recovery.installationId, recovery.resourceId, recovery.generation, recovery.token, publicKeyFingerprint(replacementKey)].join("\n");
    const recovered = await service.enroll({ ...recovery, publicKeyPem: replacementKey, signature: sign("sha256", Buffer.from(replacementProof), replacement.privateKey).toString("base64") });
    expect(recovered.deviceId).not.toBe(enrolled.deviceId);
  });
  it("denies device authority on quarantined ownership while still allowing revocation", async () => {
    const store = new MemoryStore();
    const provider = new FakeComputeProvider();
    const created = await new GatewayService(store, provider).createFakeGateway("fake-node", "quarantine", "infra");
    const service = new GatewayIdentityService(store, provider, issuer(), { timing: { renewalAfterMs: 0 } });
    const enrolled = await enroll(service, created.resource.id);
    provider.fixtures.get(created.resource.id)!.tags = ["kiln"];
    await new GatewayMonitor(store, provider).scan();
    await expect(service.heartbeat({ deviceId: enrolled.deviceId, certificateFingerprint: enrolled.currentCertificate.fingerprint, sequence: 1, services: "PASS", policy: "UNKNOWN", reservation: "UNKNOWN" })).rejects.toMatchObject({ code: "SAFETY_DENIED" });
    await expect(service.issueEnrollmentToken(created.resource.id)).rejects.toMatchObject({ code: "SAFETY_DENIED" });
    await service.revoke(created.resource.id);
    expect((await service.identity(created.resource.id))?.revokedAt).toBeTruthy();
    expect((await store.listGateways())[0]?.health?.status).toBe("QUARANTINED");
  });
  it("renews an expired leaf with a fresh one-time challenge and rejects its replay", async () => {
    let now = new Date("2026-01-01T00:00:00.000Z");
    const store = new MemoryStore();
    const provider = new FakeComputeProvider();
    const created = await new GatewayService(store, provider, () => now).createFakeGateway("fake-node", "expired", "infra");
    const service = new GatewayIdentityService(store, provider, issuer(), { clock: () => now, timing: { certificateMs: 1_000, renewalAfterMs: 0 } });
    const enrolled = await enroll(service, created.resource.id);
    now = new Date(now.getTime() + 1_001);
    const challenge = await service.challenge(enrolled.deviceId);
    const proof = ["kiln-gateway-renew-v1", enrolled.installationId, enrolled.resourceId, enrolled.generation, enrolled.deviceId, challenge.challengeId, challenge.nonce].join("\n");
    const pair = keyFor(enrolled.publicKeyPem);
    const request = { deviceId: enrolled.deviceId, challengeId: challenge.challengeId, nonce: challenge.nonce, signature: sign("sha256", Buffer.from(proof), pair).toString("base64") };
    await service.renew(request);
    await expect(service.renew(request)).rejects.toMatchObject({ code: "UNAUTHENTICATED" });
  });
});

function issuer(): GatewayCertificateIssuer {
  let sequence = 0;
  return {
    fingerprint: createHash("sha256").update("gateway-test-ca").digest("hex"),
    async issue(input) {
      sequence += 1;
      const issuedAt = input.now.toISOString();
      const expiresAt = new Date(input.now.getTime() + input.lifetimeMs).toISOString();
      return { fingerprint: `cert-${sequence}`, certificatePem: `test-${sequence}`, issuedAt, expiresAt, acceptedUntil: expiresAt };
    },
  };
}
async function enroll(service: GatewayIdentityService, resourceId: string) {
  const token = await service.issueEnrollmentToken(resourceId);
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKeyPem = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
  privateKeys.set(publicKeyPem, pair.privateKey);
  const proof = ["kiln-gateway-enroll-v1", token.installationId, token.resourceId, token.generation, token.token, publicKeyFingerprint(publicKeyPem)].join("\n");
  return service.enroll({ ...token, publicKeyPem, signature: sign("sha256", Buffer.from(proof), pair.privateKey).toString("base64") });
}
function keyFor(publicKeyPem: string) {
  const key = privateKeys.get(publicKeyPem);
  if (!key) throw new Error("Missing test private key");
  return key;
}
