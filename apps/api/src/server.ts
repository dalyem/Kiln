import { createGatewayEnrollmentApp, createGatewayHeartbeatApp, createApp } from "./app.js";
import { DrizzleStore, MemoryStore, gatewayHealthAttestationMigration, gatewayIdentityMigration, gatewayMonitoringMigration, imageProvenanceMigration, initialMigration, linuxImageImportMigration, networkProbeMigration, providerOperationMigration, proxmoxQualificationMigration } from "@kiln/database";
import { FakeComputeProvider } from "@kiln/providers";
import { ProxmoxLinuxImportProvider, ProxmoxProvider, ProxmoxQualificationProvider, parseProxmoxToken } from "@kiln/proxmox";
import { LifecycleQualificationService, LinuxImageImportService, LinuxImageStaging, type LinuxImportProfile, type QualificationProfile, X509GatewayCertificateIssuer, type TrustedImageKeys, validateNetworkProbeProfiles, validateNetworkProbeRuntime, validateTrustedImageKeys } from "@kiln/core";
import { lstat, readFile } from "node:fs/promises";
import { dirname } from "node:path";
const token = process.env.KILN_API_TOKEN;
if (!token)
  throw new Error("KILN_API_TOKEN is required before the API can listen");
const store =
  process.env.KILN_STORE === "memory"
    ? new MemoryStore()
    : process.env.KILN_DATABASE_URL
      ? new DrizzleStore(process.env.KILN_DATABASE_URL)
      : undefined;
if (!store)
  throw new Error(
    "KILN_DATABASE_URL is required unless KILN_STORE=memory is explicit",
  );
if (store instanceof DrizzleStore) {
  await store.acquireSingletonWriter();
  await store.migrate(await initialMigration());
  await store.migrate(await gatewayMonitoringMigration());
  await store.migrate(await gatewayHealthAttestationMigration());
  await store.migrate(await gatewayIdentityMigration());
  await store.migrate(await networkProbeMigration());
  await store.migrate(await providerOperationMigration());
  await store.migrate(await imageProvenanceMigration());
  await store.migrate(await proxmoxQualificationMigration());
  await store.migrate(await linuxImageImportMigration());
}
await store.initializeInstallation(process.env.KILN_INSTALLATION_ID);
if (store instanceof DrizzleStore) await store.recoverUnfinishedOperations();
const providerMode = process.env.KILN_PROVIDER ?? "fake";
const provider =
  providerMode === "fake"
    ? new FakeComputeProvider()
    : providerMode === "proxmox-read-only"
      ? new ProxmoxProvider(
          parseProxmoxToken(
            required("KILN_PROXMOX_URL"),
            required("KILN_PROXMOX_TOKEN"),
          ),
        )
      : (() => {
          throw new Error("KILN_PROVIDER must be fake or proxmox-read-only");
        })();
const infrastructureToken = process.env.KILN_INFRASTRUCTURE_TOKEN;
if (infrastructureToken && infrastructureToken === token)
  throw new Error("KILN_INFRASTRUCTURE_TOKEN must differ from KILN_API_TOKEN");
const gatewayRuntime = await loadGatewayRuntime();
const probeProfiles = await loadProbeProfiles();
const trustedImageKeys = await loadTrustedImageKeys();
const qualificationProfile = await loadQualificationProfile();
const linuxImportProfile = await loadLinuxImportProfile();
if (qualificationProfile && !(store instanceof DrizzleStore)) throw new Error("Proxmox qualification requires PostgreSQL");
if (qualificationProfile && !infrastructureToken) throw new Error("KILN_INFRASTRUCTURE_TOKEN is required for qualification");
const qualificationToken = qualificationProfile ? required("KILN_QUALIFICATION_TOKEN") : undefined;
if (qualificationProfile && providerMode !== "proxmox-read-only") throw new Error("KILN_PROXMOX_QUALIFICATION_FILE requires KILN_PROVIDER=proxmox-read-only");
if (qualificationToken && (qualificationToken === token || qualificationToken === infrastructureToken)) throw new Error("KILN_QUALIFICATION_TOKEN must differ from routine and infrastructure credentials");
const qualification = qualificationProfile
  ? new LifecycleQualificationService(
      store as import("@kiln/core").Store & import("@kiln/core").QualificationStore,
      new ProxmoxQualificationProvider(parseProxmoxToken(required("KILN_PROXMOX_URL"), required("KILN_PROXMOX_TOKEN"))),
      trustedImageKeys,
      qualificationProfile,
    )
  : null;
if (linuxImportProfile && (!(store instanceof DrizzleStore) || providerMode !== "proxmox-read-only" || !infrastructureToken)) throw new Error("Linux image import requires PostgreSQL, infrastructure credentials and proxmox-read-only mode");
const linuxImportToken = linuxImportProfile ? required("KILN_LINUX_IMPORT_TOKEN") : undefined;
if (linuxImportToken && (linuxImportToken === token || linuxImportToken === infrastructureToken || linuxImportToken === qualificationToken)) throw new Error("KILN_LINUX_IMPORT_TOKEN must differ from all other credentials");
const linuxStaging = linuxImportProfile ? new LinuxImageStaging(required("KILN_LINUX_IMAGE_STAGING_DIR")) : null;
const linuxImport = linuxImportProfile ? new LinuxImageImportService(store as import("@kiln/core").Store & import("@kiln/core").LinuxImportStore & import("@kiln/core").QualificationStore, new ProxmoxLinuxImportProvider(parseProxmoxToken(required("KILN_PROXMOX_URL"), required("KILN_PROXMOX_TOKEN"))), trustedImageKeys, linuxImportProfile, linuxStaging!) : null;
await qualification?.recoverInstallation();
await linuxImport?.recoverInstallation();
validateNetworkProbeRuntime(probeProfiles, Boolean(gatewayRuntime));
const { app, service, gateways, monitor, gatewayIdentity, probeService } = createApp({ token, infrastructureToken, store, provider, gatewayIssuer: gatewayRuntime?.issuer, networkProbeProfiles: probeProfiles, trustedImageKeys, qualificationService: qualification ?? undefined, qualificationToken, linuxImportService: linuxImport ?? undefined, linuxImportToken, linuxImageStaging: linuxStaging ?? undefined });
if (gatewayIdentity) await gatewayIdentity.initialize();
let scanning = false;
const leaseTimer = setInterval(() => {
  if (scanning) return;
  scanning = true;
  void service
    .expire()
    .catch(() => console.error("kiln lease scan failed"))
    .finally(() => {
      scanning = false;
    });
}, 30_000);
leaseTimer.unref();
let probing = false;
const probeTimer = setInterval(() => {
  if (probing) return;
  probing = true;
  void probeService.expire().catch(() => console.error("kiln network probe cleanup failed")).finally(() => { probing = false; });
}, 10_000);
probeTimer.unref();
let reconciling = false;
const operationTimer = setInterval(() => {
  if (reconciling) return;
  reconciling = true;
  void Promise.all([service.reconcileOperations(), gateways.reconcileOperations()]).catch(() => console.error("kiln operation reconciliation failed")).finally(() => { reconciling = false; });
}, 10_000);
operationTimer.unref();
let monitoring = false;
const monitorTimer = setInterval(() => {
  if (monitoring) return;
  monitoring = true;
  void monitor.scan().catch(() => console.error("kiln gateway monitor failed")).finally(() => { monitoring = false; });
}, 10_000);
monitorTimer.unref();
await monitor.scan();
await app.listen({
  host: process.env.KILN_HOST ?? "127.0.0.1",
  port: Number(process.env.KILN_PORT ?? 4000),
});
const enrollmentApp = gatewayIdentity && gatewayRuntime ? createGatewayEnrollmentApp(gatewayIdentity, { key: gatewayRuntime.serverKey, cert: gatewayRuntime.serverCertificate, minVersion: "TLSv1.3" }, probeService) : null;
const heartbeatApp = gatewayIdentity && gatewayRuntime ? createGatewayHeartbeatApp(gatewayIdentity, { key: gatewayRuntime.serverKey, cert: gatewayRuntime.serverCertificate, ca: gatewayRuntime.gatewayCa, requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3" }) : null;
if (enrollmentApp && heartbeatApp && gatewayRuntime) {
  await enrollmentApp.listen({ host: process.env.KILN_GATEWAY_ENROLL_HOST ?? "127.0.0.1", port: port("KILN_GATEWAY_ENROLL_PORT", 4443) });
  await heartbeatApp.listen({ host: process.env.KILN_GATEWAY_HEARTBEAT_HOST ?? "127.0.0.1", port: port("KILN_GATEWAY_HEARTBEAT_PORT", 4444) });
}
function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required for the selected provider`);
  return value;
}
async function loadTrustedImageKeys(): Promise<TrustedImageKeys> {
  const file = process.env.KILN_IMAGE_TRUSTED_KEYS_FILE;
  if (!file) return {};
  const parsed: unknown = JSON.parse(await readFile(file, "utf8"));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("KILN_IMAGE_TRUSTED_KEYS_FILE must contain an object");
  validateTrustedImageKeys(parsed);
  return parsed as TrustedImageKeys;
}
async function loadQualificationProfile(): Promise<QualificationProfile | null> {
  const file = process.env.KILN_PROXMOX_QUALIFICATION_FILE;
  if (!file) return null;
  const parsed: unknown = JSON.parse(await readFile(file, "utf8"));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("KILN_PROXMOX_QUALIFICATION_FILE must contain an object");
  const value = parsed as Record<string, unknown>;
  const keys = ["enabled", "node", "pool", "stageStorage", "targetStorage", "pveVersion", "templateVmid", "probeVmid", "tokenIdentity", "storageConfigDigest"];
  if (Object.keys(value).length !== keys.length || keys.some((key) => !(key in value)) || value.enabled !== true || value.pveVersion !== "9.2.2" || !keys.slice(1).every((key) => typeof value[key] === "string") || !/^[1-9][0-9]{2,8}$/.test(value.templateVmid as string) || !/^[1-9][0-9]{2,8}$/.test(value.probeVmid as string) || value.templateVmid === value.probeVmid || !/^[a-f0-9]{40}$/.test(value.storageConfigDigest as string)) throw new Error("KILN_PROXMOX_QUALIFICATION_FILE is invalid");
  const credentials = parseProxmoxToken(required("KILN_PROXMOX_URL"), required("KILN_PROXMOX_TOKEN"));
  if (value.tokenIdentity !== credentials.tokenId) throw new Error("Qualification token identity must match KILN_PROXMOX_TOKEN");
  return { node: value.node as string, pool: value.pool as string, stageStorage: value.stageStorage as string, targetStorage: value.targetStorage as string, pveVersion: "9.2.2", storageConfigDigest: value.storageConfigDigest as string, templateVmid: value.templateVmid as string, probeVmid: value.probeVmid as string, tokenIdentity: value.tokenIdentity as string };
}
async function loadLinuxImportProfile(): Promise<LinuxImportProfile | null> {
  const file = process.env.KILN_PROXMOX_LINUX_IMPORT_FILE;
  if (!file) return null;
  const parsed: unknown = JSON.parse(await readFile(file, "utf8"));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("KILN_PROXMOX_LINUX_IMPORT_FILE must contain an object");
  const value = parsed as Record<string, unknown>;
  const keys = ["enabled", "node", "pool", "stageStorage", "targetStorage", "pveVersion", "tokenIdentity", "storageConfigDigest", "templateVmid", "cloneVmid", "templateName", "cloneName", "sourcePoolRunId", "sourcePoolAllocationId", "sourcePoolNonce", "sourcePoolComment"];
  if (Object.keys(value).length !== keys.length || keys.some((key) => !(key in value)) || value.enabled !== true || value.pveVersion !== "9.2.2" || !keys.slice(1).every((key) => typeof value[key] === "string") || !/^[1-9][0-9]{2,8}$/.test(value.templateVmid as string) || !/^[1-9][0-9]{2,8}$/.test(value.cloneVmid as string) || value.templateVmid === value.cloneVmid || !/^[a-f0-9]{40}$/.test(value.storageConfigDigest as string) || !/^qual_[a-f0-9]{32}$/.test(value.sourcePoolRunId as string) || !/^alloc_pool_qual_[a-f0-9]{32}$/.test(value.sourcePoolAllocationId as string)) throw new Error("KILN_PROXMOX_LINUX_IMPORT_FILE is invalid");
  const credentials = parseProxmoxToken(required("KILN_PROXMOX_URL"), required("KILN_PROXMOX_TOKEN"));
  if (credentials.tokenId !== value.tokenIdentity) throw new Error("Linux image import token identity must match KILN_PROXMOX_TOKEN");
  return Object.fromEntries(keys.slice(1).map((key) => [key, value[key]])) as unknown as LinuxImportProfile;
}
async function shutdown(): Promise<void> {
  clearInterval(leaseTimer);
  clearInterval(monitorTimer);
  clearInterval(probeTimer);
  clearInterval(operationTimer);
  await app.close();
  await enrollmentApp?.close();
  await heartbeatApp?.close();
  if (store instanceof DrizzleStore) await store.close();
}
process.once("SIGINT", () => {
  void shutdown();
});

function port(name: string, fallback: number): number {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(value) || value < 1 || value > 65_535) throw new Error(`${name} must be a TCP port`);
  return value;
}
async function loadGatewayRuntime(): Promise<{ issuer: X509GatewayCertificateIssuer; gatewayCa: string; serverCertificate: string; serverKey: string } | null> {
  const names = ["KILN_TLS_CERT_FILE", "KILN_TLS_KEY_FILE", "KILN_GATEWAY_CA_CERT_FILE", "KILN_GATEWAY_CA_KEY_FILE"] as const;
  const configured = names.filter((name) => Boolean(process.env[name]));
  if (configured.length === 0) return null;
  if (configured.length !== names.length) throw new Error(`Gateway TLS requires ${names.join(", ")}`);
  const [serverCertificate, serverKey, gatewayCa, gatewayCaKey] = await Promise.all([
    pemFile(process.env.KILN_TLS_CERT_FILE!, "KILN_TLS_CERT_FILE"),
    privatePemFile(process.env.KILN_TLS_KEY_FILE!, "KILN_TLS_KEY_FILE"),
    pemFile(process.env.KILN_GATEWAY_CA_CERT_FILE!, "KILN_GATEWAY_CA_CERT_FILE"),
    privatePemFile(process.env.KILN_GATEWAY_CA_KEY_FILE!, "KILN_GATEWAY_CA_KEY_FILE"),
  ]);
  const issuer = await X509GatewayCertificateIssuer.load(gatewayCa, gatewayCaKey);
  return { issuer, gatewayCa, serverCertificate, serverKey };
}
async function loadProbeProfiles() {
  const file = process.env.KILN_PROBE_PROFILES_FILE;
  if (!file) return [];
  const stat = await lstat(file);
  if (stat.isSymbolicLink() || !stat.isFile()) throw new Error("KILN_PROBE_PROFILES_FILE must name a regular file, not a symlink");
  let parsed: unknown;
  try { parsed = JSON.parse(await readFile(file, "utf8")); }
  catch { throw new Error("KILN_PROBE_PROFILES_FILE must contain valid JSON"); }
  return validateNetworkProbeProfiles(parsed);
}
async function privatePemFile(path: string, name: string): Promise<string> {
  const stat = await lstat(path);
  if (stat.isSymbolicLink() || !stat.isFile()) throw new Error(`${name} must name a regular file, not a symlink`);
  if ((stat.mode & 0o077) !== 0) throw new Error(`${name} must not be group- or world-readable`);
  const directory = await lstat(dirname(path));
  if (directory.isSymbolicLink() || !directory.isDirectory() || (directory.mode & 0o077) !== 0)
    throw new Error(`${name} must be stored in a non-symlink private directory`);
  return readFile(path, "utf8");
}
async function pemFile(path: string, name: string): Promise<string> {
  const stat = await lstat(path);
  if (stat.isSymbolicLink() || !stat.isFile()) throw new Error(`${name} must name a regular file, not a symlink`);
  return readFile(path, "utf8");
}
process.once("SIGTERM", () => {
  void shutdown();
});
