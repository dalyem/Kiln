import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { createSocket } from "node:dgram";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer as createHttpsServer, request as httpsRequest } from "node:https";
import { createServer as createTcpServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { createApp, createGatewayEnrollmentApp } from "../apps/api/src/app.js";
import {
  DrizzleStore,
  gatewayHealthAttestationMigration,
  gatewayIdentityMigration,
  gatewayMonitoringMigration,
  initialMigration,
  networkProbeMigration,
  providerOperationMigration,
  imageProvenanceMigration,
} from "@kiln/database";
import {
  GatewayIdentityService,
  type NetworkProbeProfile,
  X509GatewayCertificateIssuer,
} from "@kiln/core";
import { FakeComputeProvider } from "@kiln/providers";
import { Pool } from "pg";

const databaseUrl = process.env.KILN_TEST_DATABASE_URL;
const run = promisify(execFile);

describe.skipIf(!databaseUrl)("network probe cross-runtime integration", () => {
  it("persists Go probe evidence through a Core restart without clearing network admission holds", async () => {
    const directory = await mkdtemp(join(tmpdir(), "kiln-network-probe-runtime-"));
    const binary = join(directory, "kilnd");
    const managementPort = await unusedPort();
    const probePort = await unusedPort();
    let isolated: Awaited<ReturnType<typeof createIsolatedDatabase>> | null = null;
    let core: Awaited<ReturnType<typeof startCore>> | null = null;
    let expectedServer: Server | null = null;
    let redirectServer: Server | null = null;
    let reachableServer: Server | null = null;
    let dns = createSocket("udp4");
    try {
      isolated = await createIsolatedDatabase(databaseUrl!);
      await createTestPKI(directory);
      await run("go", ["build", "-o", binary, "./cmd/kilnd"], {
        cwd: process.cwd(),
      });

      const expectedPort = await unusedPort();
      const redirectPort = await unusedPort();
      const reachablePort = await unusedPort();
      const blockedPort = await unusedPort();
      const certificate = await readFile(join(directory, "server.crt"), "utf8");
      const key = await readFile(join(directory, "server.key"), "utf8");
      expectedServer = createHttpsServer({ cert: certificate, key, minVersion: "TLSv1.3" }, (_request, response) => {
        response.writeHead(204).end();
      });
      redirectServer = createHttpsServer({ cert: certificate, key, minVersion: "TLSv1.3" }, (_request, response) => {
        response.writeHead(302, { location: `https://127.0.0.1:${expectedPort}/expected` }).end();
      });
      reachableServer = createTcpServer((socket) => socket.end());
      await listen(expectedServer, expectedPort);
      await listen(redirectServer, redirectPort);
      await listen(reachableServer, reachablePort);
      await bindDns(dns);
      dns.on("message", (request, remote) => {
        const answer = dnsAnswer(request);
        if (answer) dns.send(answer, remote.port, remote.address);
      });
      const dnsPort = (dns.address() as { port: number }).port;
      const profile: NetworkProbeProfile = {
        id: "local_runtime",
        ttlSeconds: 60,
        checks: [
          { id: "dns_a", kind: "dns", hostname: "probe.test", resolverAddress: "127.0.0.1", resolverPort: dnsPort, timeoutMs: 500 },
          { id: "https_expected", kind: "https", url: `https://127.0.0.1:${expectedPort}/expected`, expectedStatus: 204, caPem: certificate, timeoutMs: 500 },
          { id: "https_redirect", kind: "https", url: `https://127.0.0.1:${redirectPort}/redirect`, expectedStatus: 204, caPem: certificate, timeoutMs: 500 },
          { id: "tcp_reachable", kind: "tcp", address: "127.0.0.1", port: reachablePort, expect: "reachable", timeoutMs: 500 },
          { id: "tcp_blocked", kind: "tcp", address: "127.0.0.1", port: blockedPort, expect: "blocked", timeoutMs: 500 },
        ],
      };
      const node = `probe_${randomUUID().replaceAll("-", "")}`;
      const provider = new FakeComputeProvider({
        nodes: [{ id: node, online: true, cpuFree: 8, memoryFree: 16, storage: [], networks: [], images: [] }],
        storage: [],
        resources: [],
      });
      let now = new Date();
      const clock = () => now;
      core = await startCore({
        directory,
        databaseUrl: isolated.url,
        managementPort,
        probePort,
        provider,
        profile,
        clock,
      });

      const normal = "ordinary-client-token";
      const infrastructure = "infrastructure-client-token";
      expect((await managementRequest(managementPort, normal, "POST", "/v1/gateways", { node }, "gateway-normal")).status).toBe(403);
      const gatewayCreated = await managementRequest(managementPort, infrastructure, "POST", "/v1/gateways", { node }, "gateway-create");
      expect(gatewayCreated.status).toBe(201);
      const gatewayId = (gatewayCreated.body as { id: string }).id;
      expect(gatewayId).toMatch(/^gw_/);

      // This makes the existing admission hold explicit. The probe must not clear it.
      expect((await managementRequest(managementPort, infrastructure, "POST", `/v1/gateways/${gatewayId}/enrollment-token`)).status).toBe(200);
      expect((await managementRequest(managementPort, infrastructure, "POST", "/v1/monitor/scan")).status).toBe(200);
      expect((await managementRequest(managementPort, normal, "POST", "/v1/resources", { type: "execution", projectId: "default", ttlSeconds: 60 }, "held-before-probe")).status).toBe(409);

      expect((await managementRequest(managementPort, normal, "POST", `/v1/gateways/${gatewayId}/probes`, { profileId: profile.id }, "probe-normal")).status).toBe(403);
      const created = await managementRequest(managementPort, infrastructure, "POST", `/v1/gateways/${gatewayId}/probes`, { profileId: profile.id }, "probe-create");
      expect(created.status).toBe(201);
      const probeId = (created.body as { resource: { id: string } }).resource.id;
      const deniedToken = await managementRequest(managementPort, normal, "POST", `/v1/network-probes/${probeId}/token`);
      expect(deniedToken.status).toBe(403);
      const issuedToken = await managementRequest(managementPort, infrastructure, "POST", `/v1/network-probes/${probeId}/token`);
      expect(issuedToken.status).toBe(200);
      const token = (issuedToken.body as { token: string }).token;
      const tokenHash = createHash("sha256").update(token).digest("hex");
      const tokenFile = join(directory, "probe-token");
      const configFile = join(directory, "probe.json");
      await writeFile(tokenFile, `${token}\n`, { mode: 0o600 });
      await writeFile(configFile, JSON.stringify({ coreUrl: `https://127.0.0.1:${probePort}`, serverCaFile: join(directory, "server.crt"), probeId, tokenFile }), { mode: 0o600 });
      const plan = await probePlanRequest(probePort, certificate, probeId, token);
      expect(plan.status).toBe(200);
      expect(plan.body).toMatchObject({ plan: { schemaVersion: 1, probeId, gatewayConfigFingerprint: expect.any(String) }, planDigest: expect.stringMatching(/^[a-f0-9]{64}$/) });
      const output = await runProbe(binary, configFile, [token, tokenHash]);
      expect(output).not.toContain(token);
      expect(output).not.toContain(tokenHash);

      const completed = await managementRequest(managementPort, infrastructure, "GET", `/v1/network-probes/${probeId}`);
      expect(completed.status).toBe(200);
      expect(JSON.stringify(completed.body)).not.toContain(token);
      expect(JSON.stringify(completed.body)).not.toContain(tokenHash);
      const completedProbe = (completed.body as { resource: { state: string }; probe: { state: string; placement: string; planDigest: string; resultDigest: string; results: Array<{ id: string; code: string; durationMs: number }> } }).probe;
      expect(completedProbe.state).toBe("COMPLETED");
      expect(completedProbe.placement).toBe("UNVERIFIED");
      expect(completedProbe.resultDigest).toMatch(/^[a-f0-9]{64}$/);
      expect(Object.fromEntries(completedProbe.results.map((result) => [result.id, result.code]))).toEqual({
        dns_a: "DNS_ANSWER",
        https_expected: "HTTPS_EXPECTED",
        https_redirect: "HTTPS_REDIRECT",
        tcp_reachable: "TCP_CONNECTED",
        tcp_blocked: "TCP_FAILED",
      });
      expect(completedProbe.results.every((result) => Number.isInteger(result.durationMs) && result.durationMs >= 0)).toBe(true);
      expect((await managementRequest(managementPort, infrastructure, "POST", "/v1/monitor/scan")).status).toBe(200);
      expect((await managementRequest(managementPort, normal, "POST", "/v1/resources", { type: "execution", projectId: "default", ttlSeconds: 60 }, "held-after-probe")).status).toBe(409);
      const doctor = await managementRequest(managementPort, normal, "GET", "/v1/doctor?network=true");
      expect(doctor.status).toBe(200);
      expect((doctor.body as { nodes: Array<{ diagnostics: Array<{ probeId: string; placement: string; resultSummary: unknown }> }> }).nodes[0]?.diagnostics).toContainEqual({
        probeId,
        state: "COMPLETED",
        placement: "UNVERIFIED",
        receivedAt: expect.any(String),
        resultSummary: { pass: 3, fail: 1, unknown: 1 },
      });

      const replayBody = { planDigest: completedProbe.planDigest, results: completedProbe.results };
      await core.close();
      core = await startCore({ directory, databaseUrl: isolated.url, managementPort, probePort, provider, profile, clock });
      const afterRestart = await managementRequest(managementPort, infrastructure, "GET", `/v1/network-probes/${probeId}`);
      expect(afterRestart.status).toBe(200);
      expect((afterRestart.body as { probe: { resultDigest: string; results: unknown } }).probe).toMatchObject({ resultDigest: completedProbe.resultDigest, results: completedProbe.results });

      await core.probeService.expire();
      expect(provider.fixtures.has(probeId)).toBe(false);
      const replay = await probeRequest(probePort, certificate, probeId, token, replayBody);
      expect(replay.status).toBe(200);
      expect(replay.body).toEqual({ accepted: true, probeId, resultDigest: completedProbe.resultDigest });

      const second = await managementRequest(managementPort, infrastructure, "POST", `/v1/gateways/${gatewayId}/probes`, { profileId: profile.id }, "probe-mismatch");
      expect(second.status).toBe(201);
      const secondProbeId = (second.body as { resource: { id: string } }).resource.id;
      const secondToken = await managementRequest(managementPort, infrastructure, "POST", `/v1/network-probes/${secondProbeId}/token`);
      const secondTokenFile = join(directory, "probe-token-second");
      const secondConfigFile = join(directory, "probe-second.json");
      await writeFile(secondTokenFile, `${(secondToken.body as { token: string }).token}\n`, { mode: 0o600 });
      await writeFile(secondConfigFile, JSON.stringify({ coreUrl: `https://127.0.0.1:${probePort}`, serverCaFile: join(directory, "server.crt"), probeId: secondProbeId, tokenFile: secondTokenFile }), { mode: 0o600 });
      await runProbe(binary, secondConfigFile, [(secondToken.body as { token: string }).token]);
      const fixture = provider.fixtures.get(secondProbeId);
      expect(fixture).toBeDefined();
      provider.fixtures.set(secondProbeId, { ...fixture!, tags: fixture!.tags.filter((tag) => tag !== "kiln-managed") });
      await core.probeService.expire();
      expect(provider.fixtures.has(secondProbeId)).toBe(true);
      const unsafeCleanup = await managementRequest(managementPort, infrastructure, "GET", `/v1/network-probes/${secondProbeId}`);
      expect((unsafeCleanup.body as { resource: { state: string } }).resource.state).toBe("QUARANTINED");
    } finally {
      await core?.close();
      await closeServer(expectedServer);
      await closeServer(redirectServer);
      await closeServer(reachableServer);
      try {
        dns.close();
      } catch {
        // The socket may not have bound when setup failed.
      }
      await isolated?.destroy();
      await rm(directory, { recursive: true, force: true });
    }
  }, 90_000);
});

async function startCore(input: {
  directory: string;
  databaseUrl: string;
  managementPort: number;
  probePort: number;
  provider: FakeComputeProvider;
  profile: NetworkProbeProfile;
  clock: () => Date;
}) {
  const store = new DrizzleStore(input.databaseUrl);
  let management: ReturnType<typeof createApp>["app"] | null = null;
  let probe: Awaited<ReturnType<typeof createGatewayEnrollmentApp>> | null = null;
  try {
    await store.acquireSingletonWriter();
    await store.migrate(await initialMigration());
    await store.migrate(await gatewayMonitoringMigration());
    await store.migrate(await gatewayHealthAttestationMigration());
    await store.migrate(await gatewayIdentityMigration());
    await store.migrate(await networkProbeMigration());
    await store.migrate(await providerOperationMigration());
    await store.migrate(await imageProvenanceMigration());
    await store.initializeInstallation();
    const issuer = await X509GatewayCertificateIssuer.load(
      await readFile(join(input.directory, "gateway-ca.crt"), "utf8"),
      await readFile(join(input.directory, "gateway-ca.key"), "utf8"),
    );
    const identity = new GatewayIdentityService(store, input.provider, issuer, { clock: input.clock });
    await identity.initialize();
    const app = createApp({
      token: "ordinary-client-token",
      infrastructureToken: "infrastructure-client-token",
      store,
      provider: input.provider,
      clock: input.clock,
      gatewayIssuer: issuer,
      networkProbeProfiles: [input.profile],
    });
    management = app.app;
    await management.listen({ host: "127.0.0.1", port: input.managementPort });
    const key = await readFile(join(input.directory, "server.key"), "utf8");
    const cert = await readFile(join(input.directory, "server.crt"), "utf8");
    probe = createGatewayEnrollmentApp(identity, { key, cert, minVersion: "TLSv1.3" }, app.probeService);
    await probe.listen({ host: "127.0.0.1", port: input.probePort });
    return {
      probeService: app.probeService,
      async close(): Promise<void> {
        await management?.close();
        await probe?.close();
        await store.close();
      },
    };
  } catch (error) {
    await management?.close();
    await probe?.close();
    await store.close();
    throw error;
  }
}

async function managementRequest(port: number, token: string, method: string, path: string, body?: unknown, idempotencyKey?: string): Promise<{ status: number; body: unknown }> {
  const response = await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...(idempotencyKey ? { "idempotency-key": idempotencyKey } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
}

async function probeRequest(port: number, ca: string, probeId: string, token: string, body: unknown): Promise<{ status: number; body: unknown }> {
  return new Promise((resolve, reject) => {
    const request = httpsRequest({ host: "127.0.0.1", port, path: `/v1/probes/${probeId}/result`, method: "POST", ca, minVersion: "TLSv1.3", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" } }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.once("end", () => {
        try {
          resolve({ status: response.statusCode ?? 0, body: JSON.parse(Buffer.concat(chunks).toString("utf8")) });
        } catch (error) {
          reject(error);
        }
      });
    });
    request.once("error", reject);
    request.end(JSON.stringify(body));
  });
}

async function probePlanRequest(port: number, ca: string, probeId: string, token: string): Promise<{ status: number; body: unknown }> {
  return new Promise((resolve, reject) => {
    const request = httpsRequest({ host: "127.0.0.1", port, path: `/v1/probes/${probeId}/plan`, method: "GET", ca, minVersion: "TLSv1.3", headers: { authorization: `Bearer ${token}` } }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.once("end", () => {
        try {
          resolve({ status: response.statusCode ?? 0, body: JSON.parse(Buffer.concat(chunks).toString("utf8")) });
        } catch (error) {
          reject(error);
        }
      });
    });
    request.once("error", reject);
    request.end();
  });
}

async function runProbe(binary: string, configFile: string, redactions: string[]): Promise<string> {
  try {
    const result = await run(binary, ["probe", "--config", configFile], { timeout: 20_000, maxBuffer: 1 << 20 });
    return `${result.stdout}${result.stderr}`;
  } catch (error) {
    const output = error instanceof Error && "stdout" in error && "stderr" in error
      ? `${String(error.stdout)}${String(error.stderr)}`
      : "";
    const safeOutput = redactions.reduce((value, secret) => value.replaceAll(secret, "[redacted]"), output).slice(0, 1 << 16);
    throw new Error(`kilnd probe did not complete successfully${safeOutput ? `: ${safeOutput}` : ""}`);
  }
}

async function listen(server: Server, port: number): Promise<void> {
  await new Promise<void>((resolve, reject) => server.listen(port, "127.0.0.1", resolve).once("error", reject));
}

async function closeServer(server: Server | null): Promise<void> {
  if (!server?.listening) return;
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

async function bindDns(socket: ReturnType<typeof createSocket>): Promise<void> {
  await new Promise<void>((resolve, reject) => socket.bind(0, "127.0.0.1", resolve).once("error", reject));
}

function dnsAnswer(request: Buffer): Buffer | null {
  if (request.length < 17) return null;
  let end = 12;
  while (end < request.length) {
    const label = request[end]!;
    if (label === 0) {
      end += 5;
      break;
    }
    if (label > 63 || end + label >= request.length) return null;
    end += label + 1;
  }
  if (end > request.length) return null;
  const response = Buffer.from(request.subarray(0, end));
  response.writeUInt16BE(0x8180, 2);
  response.writeUInt16BE(1, 6);
  return Buffer.concat([response, Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 1])]);
}

async function unusedPort(): Promise<number> {
  const server = createTcpServer();
  await new Promise<void>((resolve, reject) => server.listen(0, "127.0.0.1", resolve).once("error", reject));
  const address = server.address();
  await closeServer(server);
  if (!address || typeof address === "string") throw new Error("could not allocate a test port");
  return address.port;
}

async function createTestPKI(directory: string): Promise<void> {
  await run("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", join(directory, "server.key"), "-out", join(directory, "server.crt"), "-subj", "/CN=kiln-probe-core", "-addext", "subjectAltName=IP:127.0.0.1", "-days", "1"]);
  await run("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", join(directory, "gateway-ca.key"), "-out", join(directory, "gateway-ca.crt"), "-subj", "/CN=kiln-probe-gateway-ca", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,digitalSignature", "-days", "1"]);
}

async function createIsolatedDatabase(baseURL: string): Promise<{ url: string; destroy: () => Promise<void> }> {
  const database = `kiln_network_probe_runtime_${randomUUID().replaceAll("-", "")}`;
  const admin = new Pool({ connectionString: baseURL });
  await admin.query(`CREATE DATABASE ${database}`);
  await admin.end();
  const isolated = new URL(baseURL);
  isolated.pathname = `/${database}`;
  return {
    url: isolated.toString(),
    async destroy(): Promise<void> {
      const cleanup = new Pool({ connectionString: baseURL });
      try {
        await cleanup.query(`DROP DATABASE IF EXISTS ${database}`);
      } finally {
        await cleanup.end();
      }
    },
  };
}
