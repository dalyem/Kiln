import "reflect-metadata";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  randomUUID,
  verify,
  webcrypto,
  X509Certificate as NodeX509Certificate,
} from "node:crypto";
import {
  BasicConstraintsExtension,
  ExtendedKeyUsage,
  ExtendedKeyUsageExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  SubjectAlternativeNameExtension,
  X509Certificate,
  X509CertificateGenerator,
  cryptoProvider,
} from "@peculiar/x509";
import {
  KilnError,
  type ComputeProvider,
  type Event,
  type GatewayCertificate,
  type GatewayChallenge,
  type GatewayEnrollmentTokenRecord,
  type GatewayHealth,
  type GatewayIdentity,
  type GatewaySignal,
  type Resource,
  type Store,
  validateOwnership,
} from "./index.js";

cryptoProvider.set(webcrypto as unknown as Crypto);

export const gatewayTiming = {
  enrollmentTokenMs: 10 * 60_000,
  certificateMs: 24 * 60 * 60_000,
  renewalAfterMs: 12 * 60 * 60_000,
  challengeMs: 60_000,
  previousCertificateGraceMs: 10 * 60_000,
  heartbeatStaleMs: 30_000,
} as const;
export const maxGatewayHeartbeatSequence = 2_147_483_646;
type GatewayTiming = { [Key in keyof typeof gatewayTiming]: number };

export interface GatewayCertificateIssuer {
  readonly fingerprint: string;
  issue(input: {
    installationId: string;
    resourceId: string;
    generation: string;
    deviceId: string;
    publicKeyPem: string;
    now: Date;
    lifetimeMs: number;
  }): Promise<GatewayCertificate>;
}

export class X509GatewayCertificateIssuer implements GatewayCertificateIssuer {
  readonly fingerprint: string;
  private readonly issuer: X509Certificate;
  private readonly signingKey: CryptoKey;
  private constructor(issuerPem: string, signingKey: CryptoKey) {
    this.issuer = new X509Certificate(issuerPem);
    this.signingKey = signingKey;
    this.fingerprint = certificateFingerprint(issuerPem);
  }
  static async load(issuerPem: string, privateKeyPem: string): Promise<X509GatewayCertificateIssuer> {
    const issuer = new NodeX509Certificate(issuerPem);
    if (!issuer.ca) throw new Error("Gateway issuer certificate is not a CA certificate");
    const now = Date.now();
    if (Date.parse(issuer.validFrom) > now || Date.parse(issuer.validTo) < now)
      throw new Error("Gateway issuer certificate is not currently valid");
    const parsedIssuer = new X509Certificate(issuerPem);
    const usages = parsedIssuer.getExtension(KeyUsagesExtension)?.usages;
    if (!usages || (usages & KeyUsageFlags.keyCertSign) === 0)
      throw new Error("Gateway issuer certificate cannot sign certificates");
    const privateKey = createPrivateKey(privateKeyPem);
    const publicKey = createPublicKey(privateKey);
    if (publicKey.export({ type: "spki", format: "der" }).toString("hex") !== issuer.publicKey.export({ type: "spki", format: "der" }).toString("hex"))
      throw new Error("Gateway issuer private key does not match its certificate");
    const signingKey = await webcrypto.subtle.importKey(
      "jwk",
      privateKey.export({ format: "jwk" }),
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign"],
    );
    return new X509GatewayCertificateIssuer(issuerPem, signingKey);
  }
  async issue(input: {
    installationId: string;
    resourceId: string;
    generation: string;
    deviceId: string;
    publicKeyPem: string;
    now: Date;
    lifetimeMs: number;
  }): Promise<GatewayCertificate> {
    const publicKey = canonicalGatewayPublicKey(input.publicKeyPem);
    const subtlePublicKey = await webcrypto.subtle.importKey(
      "jwk",
      publicKey.export({ format: "jwk" }),
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"],
    );
    const issuedAt = wholeSecond(input.now);
    const expiresAt = wholeSecond(new Date(issuedAt.getTime() + input.lifetimeMs));
    if (Date.parse(this.issuer.notAfter.toISOString()) < expiresAt.getTime())
      throw new Error("Gateway issuer certificate expires before the configured gateway certificate lifetime; rotate the issuer before enrolling gateways");
    const uri = gatewayUri(input);
    const certificate = await X509CertificateGenerator.create({
      serialNumber: positiveSerial(),
      subject: `CN=kiln-gateway-${input.deviceId}`,
      issuer: this.issuer.subjectName,
      publicKey: subtlePublicKey,
      signingKey: this.signingKey,
      notBefore: issuedAt,
      notAfter: expiresAt,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      extensions: [
        new BasicConstraintsExtension(false, undefined, true),
        new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
        new ExtendedKeyUsageExtension([ExtendedKeyUsage.clientAuth], true),
        new SubjectAlternativeNameExtension([{ type: "url", value: uri }], false),
      ],
    });
    const certificatePem = certificate.toString("pem");
    return {
      fingerprint: certificateFingerprint(certificatePem),
      certificatePem,
      issuedAt: issuedAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
      acceptedUntil: expiresAt.toISOString(),
    };
  }
}

export interface GatewayIdentityServiceOptions {
  clock?: () => Date;
  timing?: Partial<GatewayTiming>;
}

export class GatewayIdentityService {
  private readonly clock: () => Date;
  private readonly timing: GatewayTiming;
  constructor(
    private readonly store: Store,
    private readonly provider: ComputeProvider,
    private readonly issuer: GatewayCertificateIssuer,
    options: GatewayIdentityServiceOptions = {},
  ) {
    this.clock = options.clock ?? (() => new Date());
    this.timing = { ...gatewayTiming, ...options.timing };
  }
  async initialize(): Promise<void> {
    await this.store.bindGatewayCaFingerprint(this.issuer.fingerprint);
  }
  async issueEnrollmentToken(resourceId: string): Promise<{ installationId: string; resourceId: string; generation: string; token: string; expiresAt: string }> {
    return this.store.withResourceLock(`gateway-admission:${resourceId}`, async () => {
      const { resource, generation } = await this.requireOwnedGateway(resourceId);
      const existing = await this.store.getGatewayIdentity(resourceId);
      if (existing && !existing.revokedAt)
        throw new KilnError("CONFLICT", 409, "Gateway identity is already enrolled; revoke it before issuing a replacement token");
      const token = randomBytes(32).toString("base64url");
      const expiresAt = new Date(this.clock().getTime() + this.timing.enrollmentTokenMs).toISOString();
      const record: GatewayEnrollmentTokenRecord = {
        resourceId,
        installationId: resource.installationId,
        generation,
        tokenHash: hashSecret(token),
        expiresAt,
        publicKeyFingerprint: null,
        deviceId: null,
        certificateFingerprint: null,
      };
      await this.store.issueGatewayEnrollmentToken(record, event(resource, "gateway.identity_token_issued", { expiresAt }, this.clock));
      await this.invalidateGatewayAdmission(resource.id);
      return { installationId: resource.installationId, resourceId, generation, token, expiresAt };
    });
  }
  async identity(resourceId: string): Promise<GatewayIdentity | null> {
    return this.store.getGatewayIdentity(resourceId);
  }
  async enroll(input: {
    installationId: string;
    resourceId: string;
    generation: string;
    token: string;
    publicKeyPem: string;
    signature: string;
  }): Promise<GatewayIdentity & { enrollmentCertificate: GatewayCertificate }> {
    validateIdentifier(input.installationId, "installationId");
    validateIdentifier(input.resourceId, "resourceId");
    validateIdentifier(input.generation, "generation");
    const publicKey = canonicalGatewayPublicKey(input.publicKeyPem);
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const keyFingerprint = publicKeyFingerprint(publicKeyPem);
    const proof = ["kiln-gateway-enroll-v1", input.installationId, input.resourceId, input.generation, input.token, keyFingerprint].join("\n");
    verifyGatewaySignature(publicKeyPem, proof, input.signature);
    return this.store.withResourceLock(`gateway-admission:${input.resourceId}`, async () => {
      const { resource } = await this.requireOwnedGateway(input.resourceId, input.installationId, input.generation);
      const now = this.clock();
      const token = await this.store.getGatewayEnrollmentToken(input.resourceId);
      if (!token || token.tokenHash !== hashSecret(input.token) || token.installationId !== resource.installationId || token.generation !== input.generation || Date.parse(token.expiresAt) < now.getTime())
        throw new KilnError("UNAUTHENTICATED", 401, "Gateway enrollment token is invalid or expired");
      const existing = await this.store.getGatewayIdentity(input.resourceId);
      if (existing && !existing.revokedAt && token.publicKeyFingerprint === keyFingerprint && existing.publicKeyFingerprint === keyFingerprint) {
        const certificate = token.certificateFingerprint ? await this.store.getGatewayCertificate(token.certificateFingerprint) : null;
        if (!certificate) throw new KilnError("UNAUTHENTICATED", 401, "Gateway enrollment token cannot be replayed");
        return { ...existing, enrollmentCertificate: certificate };
      }
      const deviceId = `gwd_${randomUUID().replaceAll("-", "")}`;
      const currentCertificate = await this.issuer.issue({ ...input, deviceId, publicKeyPem, now, lifetimeMs: this.timing.certificateMs });
      const identity: GatewayIdentity = {
        deviceId,
        resourceId: resource.id,
        installationId: resource.installationId,
        generation: input.generation,
        publicKeyPem,
        publicKeyFingerprint: keyFingerprint,
        revokedAt: null,
        createdAt: now.toISOString(),
        currentCertificate,
        previousCertificate: null,
        nextSequence: 1,
        lastSeenAt: null,
        lastServices: null,
        lastPolicy: null,
        lastReservation: null,
      };
      const result = await this.store.enrollGatewayIdentity({ tokenHash: hashSecret(input.token), publicKeyPem, publicKeyFingerprint: keyFingerprint, identity, event: event(resource, "gateway.identity_enrolled", { deviceId, certificateFingerprint: currentCertificate.fingerprint }, this.clock), now: now.toISOString() });
      return { ...result.identity, enrollmentCertificate: result.certificate };
    });
  }
  async challenge(deviceId: string): Promise<GatewayChallenge> {
    validateIdentifier(deviceId, "deviceId");
    const identity = await this.requireAuthorizedIdentity(deviceId);
    return this.store.withResourceLock(`gateway-admission:${identity.resourceId}`, async () => {
      await this.requireAuthorizedIdentity(deviceId);
      const now = this.clock();
      return this.store.issueGatewayChallenge({ deviceId, challengeId: `chl_${randomUUID().replaceAll("-", "")}`, nonce: randomBytes(32).toString("base64url"), expiresAt: new Date(now.getTime() + this.timing.challengeMs).toISOString() }, now.toISOString());
    });
  }
  async renew(input: { deviceId: string; challengeId: string; nonce: string; signature: string }): Promise<GatewayIdentity> {
    validateIdentifier(input.deviceId, "deviceId");
    validateIdentifier(input.challengeId, "challengeId");
    const identity = await this.requireAuthorizedIdentity(input.deviceId);
    if (this.clock().getTime() < Date.parse(identity.currentCertificate.issuedAt) + this.timing.renewalAfterMs && this.clock().getTime() < Date.parse(identity.currentCertificate.expiresAt))
      throw new KilnError("CONFLICT", 409, "Gateway certificate is not eligible for renewal yet");
    const proof = ["kiln-gateway-renew-v1", identity.installationId, identity.resourceId, identity.generation, identity.deviceId, input.challengeId, input.nonce].join("\n");
    verifyGatewaySignature(identity.publicKeyPem, proof, input.signature);
    return this.store.withResourceLock(`gateway-admission:${identity.resourceId}`, async () => {
      const current = await this.requireAuthorizedIdentity(input.deviceId);
      const now = this.clock();
      const nextCertificate = await this.issuer.issue({ ...current, now, lifetimeMs: this.timing.certificateMs });
      const old = current.currentCertificate;
      old.acceptedUntil = new Date(Math.min(Date.parse(old.expiresAt), now.getTime() + this.timing.previousCertificateGraceMs)).toISOString();
      const next: GatewayIdentity = { ...current, currentCertificate: nextCertificate, previousCertificate: old };
      const resource = (await this.store.getResource(current.resourceId))!;
      return this.store.renewGatewayIdentity({ identity: next, challengeId: input.challengeId, nonce: input.nonce, event: event(resource, "gateway.identity_renewed", { deviceId: current.deviceId, certificateFingerprint: nextCertificate.fingerprint }, this.clock), now: now.toISOString() });
    });
  }
  async revoke(resourceId: string): Promise<void> {
    return this.store.withResourceLock(`gateway-admission:${resourceId}`, async () => {
      const resource = await this.requireStoredGateway(resourceId);
      await this.store.revokeGatewayIdentity(resourceId, this.clock().toISOString(), event(resource, "gateway.identity_revoked", {}, this.clock));
      await this.invalidateGatewayAdmission(resource.id);
    });
  }
  async heartbeat(input: { deviceId: string; certificateFingerprint: string; sequence: number; services: GatewaySignal; policy: GatewaySignal; reservation: GatewaySignal }): Promise<GatewayIdentity> {
    validateIdentifier(input.deviceId, "deviceId");
    if (!Number.isSafeInteger(input.sequence) || input.sequence < 1 || input.sequence > maxGatewayHeartbeatSequence) throw new KilnError("INVALID_INPUT", 400, "Heartbeat sequence is outside the supported range");
    for (const value of [input.services, input.policy, input.reservation]) if (!["PASS", "FAIL", "UNKNOWN"].includes(value)) throw new KilnError("INVALID_INPUT", 400, "Gateway signal is invalid");
    const identity = await this.requireAuthorizedIdentity(input.deviceId);
    return this.store.withResourceLock(`gateway-admission:${identity.resourceId}`, async () => {
      await this.requireOwnedGateway(identity.resourceId, identity.installationId, identity.generation);
      const resource = (await this.store.getResource(identity.resourceId))!;
      return this.store.recordGatewayHeartbeat({ ...input, receivedAt: this.clock().toISOString(), event: event(resource, "gateway.heartbeat", { deviceId: input.deviceId, sequence: input.sequence, services: input.services, policy: input.policy, reservation: input.reservation }, this.clock) });
    });
  }
  private async requireAuthorizedIdentity(deviceId: string): Promise<GatewayIdentity> {
    const all = await this.store.listGateways();
    const found = all.map((gateway) => gateway.resource.id).map(async (id) => this.store.getGatewayIdentity(id));
    const identity = (await Promise.all(found)).find((candidate) => candidate?.deviceId === deviceId) ?? null;
    if (!identity || identity.revokedAt) throw new KilnError("UNAUTHENTICATED", 401, "Gateway identity is not authorized");
    await this.requireOwnedGateway(identity.resourceId, identity.installationId, identity.generation);
    return identity;
  }
  private async requireOwnedGateway(resourceId: string, installationId?: string, generation?: string): Promise<{ resource: Resource; generation: string }> {
    const resource = await this.store.getResource(resourceId);
    const metadata = await this.store.getGateway(resourceId);
    const currentInstallation = await this.store.installationId();
    const health = (await this.store.listGateways()).find((gateway) => gateway.resource.id === resourceId)?.health;
    if (!resource || !metadata || resource.type !== "gateway" || resource.ownership !== "KILN_MANAGED" || resource.state !== "READY" || health?.status === "QUARANTINED" || resource.installationId !== currentInstallation || (installationId && installationId !== currentInstallation) || (generation && metadata.generation !== generation))
      throw new KilnError("SAFETY_DENIED", 403, "Gateway is not eligible for device authority");
    const observed = await this.provider.inspect(resource.providerResourceId);
    try {
      if (!observed) throw new Error("missing provider resource");
      validateOwnership(resource, currentInstallation, observed);
    } catch {
      await this.store.appendEvent(event(resource, "gateway.identity_provider_ownership_denied", {}, this.clock));
      throw new KilnError("SAFETY_DENIED", 403, "Gateway provider ownership validation failed");
    }
    return { resource, generation: metadata.generation };
  }
  private async requireStoredGateway(resourceId: string): Promise<Resource> {
    const resource = await this.store.getResource(resourceId);
    const installationId = await this.store.installationId();
    if (!resource || resource.type !== "gateway" || resource.ownership !== "KILN_MANAGED" || resource.installationId !== installationId)
      throw new KilnError("SAFETY_DENIED", 403, "Gateway is not eligible for identity revocation");
    return resource;
  }
  private async invalidateGatewayAdmission(resourceId: string): Promise<void> {
    const gateway = (await this.store.listGateways()).find((candidate) => candidate.resource.id === resourceId);
    if (!gateway?.health) return;
    const health: GatewayHealth = {
      ...gateway.health,
      status: gateway.health.status === "QUARANTINED" ? "QUARANTINED" : "NOT_READY",
      observedAt: this.clock().toISOString(),
      evidence: { ...gateway.health.evidence, heartbeat: "UNKNOWN", services: "UNKNOWN", policy: "UNKNOWN", reservation: "UNKNOWN", canary: "UNKNOWN" },
    };
    await this.store.saveGatewayScan(health, await this.store.listGatewayIncidents(gateway.metadata.node), []);
  }
}

function event(resource: Resource, type: string, payload: Record<string, unknown>, clock: () => Date): Omit<Event, "id"> {
  return { installationId: resource.installationId, projectId: "infrastructure", resourceId: resource.id, type, timestamp: clock().toISOString(), payload };
}
function wholeSecond(value: Date): Date { return new Date(Math.floor(value.getTime() / 1000) * 1000); }
function positiveSerial(): string {
  const serial = randomBytes(20);
  serial[0] = serial[0]! & 0x7f;
  if (serial.every((byte) => byte === 0)) serial[19] = 1;
  return serial.toString("hex");
}
function hashSecret(value: string): string { return createHash("sha256").update(value).digest("hex"); }
export function publicKeyFingerprint(value: string): string { return createHash("sha256").update(canonicalGatewayPublicKey(value).export({ type: "spki", format: "der" })).digest("hex"); }
export function certificateFingerprint(value: string): string { return createHash("sha256").update(new NodeX509Certificate(value).raw).digest("hex"); }
export function gatewayUri(input: { installationId: string; resourceId: string; generation: string; deviceId: string }): string { return `spiffe://kiln.dev/gateway/${input.installationId}/${input.resourceId}/${input.generation}/${input.deviceId}`; }
export function canonicalGatewayPublicKey(value: string) {
  if (typeof value !== "string" || value.length > 8_192) throw new KilnError("INVALID_INPUT", 400, "Gateway public key is invalid");
  let key: ReturnType<typeof createPublicKey>;
  try { key = createPublicKey(value); } catch { throw new KilnError("INVALID_INPUT", 400, "Gateway public key is invalid"); }
  if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") throw new KilnError("INVALID_INPUT", 400, "Gateway key must be ECDSA P-256");
  return key;
}
function verifyGatewaySignature(publicKeyPem: string, proof: string, signature: string): void {
  let encoded: Buffer;
  try { encoded = Buffer.from(signature, "base64"); } catch { throw new KilnError("UNAUTHENTICATED", 401, "Gateway signature is invalid"); }
  if (!encoded.length || !verify("sha256", Buffer.from(proof, "utf8"), canonicalGatewayPublicKey(publicKeyPem), encoded)) throw new KilnError("UNAUTHENTICATED", 401, "Gateway signature is invalid");
}
function validateIdentifier(value: string, name: string): void {
  if (typeof value !== "string" || value.length < 1 || value.length > 256 || /[\x00-\x1f\x7f\r\n]/.test(value)) throw new KilnError("INVALID_INPUT", 400, `${name} is invalid`);
}
