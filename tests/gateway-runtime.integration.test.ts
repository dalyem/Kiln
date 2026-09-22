import { execFile, spawn, type ChildProcess } from "node:child_process";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { once } from "node:events";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createServer } from "node:net";
import { Agent as HttpsAgent, request as httpsRequest } from "node:https";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import {
  createGatewayEnrollmentApp,
  createGatewayHeartbeatApp,
} from "../apps/api/src/app.js";
import {
  DrizzleStore,
  gatewayHealthAttestationMigration,
  gatewayIdentityMigration,
  gatewayMonitoringMigration,
  initialMigration,
  providerOperationMigration,
  imageProvenanceMigration,
} from "@kiln/database";
import {
  GatewayIdentityService,
  GatewayService,
  X509GatewayCertificateIssuer,
} from "@kiln/core";
import { FakeComputeProvider } from "@kiln/providers";
import { Pool } from "pg";

const databaseUrl = process.env.KILN_TEST_DATABASE_URL;
const run = promisify(execFile);

describe.skipIf(!databaseUrl)(
  "gateway runtime cross-language integration",
  () => {
    it("enrolls and heartbeats over TLS, recovers through a Core restart and expired local lease, then stops after revocation", async () => {
      const directory = await mkdtemp(join(tmpdir(), "kiln-gateway-runtime-"));
      let isolated: Awaited<ReturnType<typeof createIsolatedDatabase>> | null =
        null;
      const enrollmentPort = await unusedPort();
      const heartbeatPort = await unusedPort();
      const binary = join(directory, "kilnd");
      let store: DrizzleStore | null = null;
      let enrollmentApp: Awaited<
        ReturnType<typeof createGatewayEnrollmentApp>
      > | null = null;
      let heartbeatApp: Awaited<
        ReturnType<typeof createGatewayHeartbeatApp>
      > | null = null;
      let daemon: ChildProcess | null = null;
      try {
        isolated = await createIsolatedDatabase(databaseUrl!);
        await createTestPKI(directory);
        const shortIssuer = await X509GatewayCertificateIssuer.load(
          await readFile(join(directory, "gateway-ca.crt"), "utf8"),
          await readFile(join(directory, "gateway-ca.key"), "utf8"),
        );
        const proofKey = generateKeyPairSync("ec", {
          namedCurve: "prime256v1",
        });
        await expect(
          shortIssuer.issue({
            installationId: "issuer_test",
            resourceId: "gateway_test",
            generation: "generation_test",
            deviceId: "device_test",
            publicKeyPem: proofKey.publicKey
              .export({ type: "spki", format: "pem" })
              .toString(),
            now: new Date(),
            lifetimeMs: 2 * 24 * 60 * 60_000,
          }),
        ).rejects.toThrow(/rotate the issuer/i);
        await run("go", ["build", "-o", binary, "./cmd/kilnd"], {
          cwd: process.cwd(),
        });
        const node = `runtime_${randomUUID().replaceAll("-", "")}`;
        const provider = new FakeComputeProvider({
          nodes: [
            {
              id: node,
              online: true,
              cpuFree: 8,
              memoryFree: 16,
              storage: [],
              networks: [],
              images: [],
            },
          ],
          storage: [],
          resources: [],
        });
        const first = await startCore({
          directory,
          databaseUrl: isolated.url,
          provider,
          node,
          enrollmentPort,
          heartbeatPort,
        });
        store = first.store;
        enrollmentApp = first.enrollmentApp;
        heartbeatApp = first.heartbeatApp;

        const stateDir = join(directory, "state");
        const tokenFile = join(directory, "bootstrap-token");
        const configFile = join(directory, "gateway.json");
        await writeFile(tokenFile, first.enrollment.token, { mode: 0o600 });
        await writeFile(
          configFile,
          JSON.stringify({
            enrollmentUrl: `https://127.0.0.1:${enrollmentPort}`,
            heartbeatUrl: `https://127.0.0.1:${heartbeatPort}`,
            serverCaFile: join(directory, "server.crt"),
            clientCaFile: join(directory, "gateway-ca.crt"),
            installationId: first.enrollment.installationId,
            resourceId: first.gatewayId,
            generation: first.enrollment.generation,
            bootstrapTokenFile: tokenFile,
            stateDir,
          }),
          { mode: 0o600 },
        );
        daemon = startGateway(binary, configFile);
        const enrolled = await waitForIdentity(
          first.identity,
          first.gatewayId,
          (identity) => identity.lastSeenAt !== null,
        );
        expect(enrolled.deviceId).toMatch(/^gwd_/);

        // Stop the daemon before its first five-second renewal check. Its initial
        // certificate is intentionally short-lived for this opt-in regression.
        await stop(daemon);
        daemon = null;
        await enrollmentApp.close();
        enrollmentApp = null;
        await heartbeatApp.close();
        heartbeatApp = null;
        await store.close();
        store = null;
        const restarted = await startCore({
          directory,
          databaseUrl: isolated.url,
          provider,
          node,
          enrollmentPort,
          heartbeatPort,
          gatewayId: first.gatewayId,
        });
        store = restarted.store;
        enrollmentApp = restarted.enrollmentApp;
        heartbeatApp = restarted.heartbeatApp;

        // Expire the actual short-lived X.509 leaf. Do not alter daemon state.
        await delay(12_500);
        const beforeRenewal = (await restarted.identity.identity(
          first.gatewayId,
        ))!.currentCertificate.fingerprint;
        daemon = startGateway(binary, configFile);
        const afterRenewal = await waitForIdentity(
          restarted.identity,
          first.gatewayId,
          (identity) =>
            identity.currentCertificate.fingerprint !== beforeRenewal &&
            identity.nextSequence > enrolled.nextSequence,
        );
        expect(afterRenewal.deviceId).toBe(enrolled.deviceId);

        await stop(daemon);
        daemon = null;
        const state = JSON.parse(
          await readFile(join(stateDir, "gateway-state.json"), "utf8"),
        ) as { certificatePem: string; deviceId: string; nextSequence: number };
        const agent = new HttpsAgent({
          keepAlive: true,
          maxSockets: 1,
          ca: await readFile(join(directory, "server.crt"), "utf8"),
          cert: state.certificatePem,
          key: await readFile(join(stateDir, "gateway-key.pem"), "utf8"),
          minVersion: "TLSv1.3",
        });
        try {
          expect(
            await heartbeatStatus({
              port: heartbeatPort,
              agent,
              deviceId: state.deviceId,
              sequence: state.nextSequence,
            }),
          ).toBe(200);
          expect(
            (await restarted.identity.identity(first.gatewayId))?.nextSequence,
          ).toBe(state.nextSequence + 1);

          await restarted.identity.revoke(first.gatewayId);
          expect(
            await heartbeatStatus({
              port: heartbeatPort,
              agent,
              deviceId: state.deviceId,
              sequence: state.nextSequence + 1,
            }),
          ).toBe(401);
          expect(
            (await restarted.identity.identity(first.gatewayId))?.nextSequence,
          ).toBe(state.nextSequence + 1);
        } finally {
          agent.destroy();
        }
        expect(
          (await restarted.identity.identity(first.gatewayId))?.revokedAt,
        ).not.toBeNull();
      } finally {
        if (daemon) await stop(daemon);
        await enrollmentApp?.close();
        await heartbeatApp?.close();
        await store?.close();
        await isolated?.destroy();
        await rm(directory, { recursive: true, force: true });
      }
    }, 90_000);
  },
);

async function startCore(input: {
  directory: string;
  databaseUrl: string;
  provider: FakeComputeProvider;
  node: string;
  enrollmentPort: number;
  heartbeatPort: number;
  gatewayId?: string;
}) {
  const store = new DrizzleStore(input.databaseUrl);
  let enrollmentApp: Awaited<
    ReturnType<typeof createGatewayEnrollmentApp>
  > | null = null;
  let heartbeatApp: Awaited<
    ReturnType<typeof createGatewayHeartbeatApp>
  > | null = null;
  try {
    await store.acquireSingletonWriter();
    await store.migrate(await initialMigration());
    await store.migrate(await gatewayMonitoringMigration());
    await store.migrate(await gatewayHealthAttestationMigration());
    await store.migrate(await gatewayIdentityMigration());
    await store.migrate(await providerOperationMigration());
    await store.migrate(await imageProvenanceMigration());
    await store.initializeInstallation();
    const issuer = await X509GatewayCertificateIssuer.load(
      await readFile(join(input.directory, "gateway-ca.crt"), "utf8"),
      await readFile(join(input.directory, "gateway-ca.key"), "utf8"),
    );
    const identity = new GatewayIdentityService(store, input.provider, issuer, {
      timing: { certificateMs: 12_000, renewalAfterMs: 0 },
    });
    await identity.initialize();
    let gatewayId = input.gatewayId;
    let enrollment: Awaited<ReturnType<typeof identity.issueEnrollmentToken>>;
    if (!gatewayId) {
      const gateway = await new GatewayService(
        store,
        input.provider,
      ).createFakeGateway(
        input.node,
        `runtime_${Date.now()}`,
        "runtime-integration",
      );
      gatewayId = gateway.resource.id;
      enrollment = await identity.issueEnrollmentToken(gatewayId);
    } else {
      // The database retains the identity and token across a Core restart. The
      // restarted daemon uses its device key and challenge flow, not this token.
      const previous = (await identity.identity(gatewayId))!;
      enrollment = {
        installationId: previous.installationId,
        resourceId: gatewayId,
        generation: previous.generation,
        token: "unused-after-enrollment",
        expiresAt: new Date().toISOString(),
      };
    }
    const key = await readFile(join(input.directory, "server.key"), "utf8");
    const cert = await readFile(join(input.directory, "server.crt"), "utf8");
    const ca = await readFile(join(input.directory, "gateway-ca.crt"), "utf8");
    enrollmentApp = createGatewayEnrollmentApp(identity, {
      key,
      cert,
      minVersion: "TLSv1.3",
    });
    heartbeatApp = createGatewayHeartbeatApp(identity, {
      key,
      cert,
      ca,
      requestCert: true,
      rejectUnauthorized: true,
      minVersion: "TLSv1.3",
    });
    await enrollmentApp.listen({
      host: "127.0.0.1",
      port: input.enrollmentPort,
    });
    await heartbeatApp.listen({ host: "127.0.0.1", port: input.heartbeatPort });
    return {
      store,
      identity,
      enrollmentApp,
      heartbeatApp,
      gatewayId,
      enrollment,
    };
  } catch (error) {
    await enrollmentApp?.close();
    await heartbeatApp?.close();
    await store.close();
    throw error;
  }
}

function startGateway(binary: string, config: string): ChildProcess {
  return spawn(binary, ["gateway", "--config", config], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "pipe"],
  });
}

async function waitForIdentity(
  identity: GatewayIdentityService,
  gatewayId: string,
  predicate: (
    value: NonNullable<Awaited<ReturnType<GatewayIdentityService["identity"]>>>,
  ) => boolean,
) {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    const value = await identity.identity(gatewayId);
    if (value && predicate(value)) return value;
    await delay(100);
  }
  throw new Error("gateway identity did not reach the expected state");
}

async function heartbeatStatus(input: {
  port: number;
  agent: HttpsAgent;
  deviceId: string;
  sequence: number;
}): Promise<number> {
  return new Promise((resolve, reject) => {
    const request = httpsRequest(
      {
        host: "127.0.0.1",
        port: input.port,
        path: "/v1/gateway/heartbeat",
        method: "POST",
        agent: input.agent,
        headers: { "content-type": "application/json" },
      },
      (response) => {
        response.resume();
        response.once("end", () => resolve(response.statusCode ?? 0));
      },
    );
    request.once("error", reject);
    request.end(
      JSON.stringify({
        deviceId: input.deviceId,
        sequence: input.sequence,
        services: "UNKNOWN",
        policy: "UNKNOWN",
        reservation: "UNKNOWN",
      }),
    );
  });
}

async function stop(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null) return;
  child.kill("SIGTERM");
  const stopped = await Promise.race([
    once(child, "exit").then(() => true),
    delay(5_000).then(() => false),
  ]);
  if (!stopped) {
    child.kill("SIGKILL");
    await once(child, "exit");
  }
}

async function unusedPort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) =>
    server.listen(0, "127.0.0.1", resolve).once("error", reject),
  );
  const address = server.address();
  server.close();
  if (!address || typeof address === "string")
    throw new Error("could not allocate a test port");
  return address.port;
}

async function createTestPKI(directory: string): Promise<void> {
  await run("openssl", [
    "req",
    "-x509",
    "-newkey",
    "ec",
    "-pkeyopt",
    "ec_paramgen_curve:P-256",
    "-nodes",
    "-keyout",
    join(directory, "server.key"),
    "-out",
    join(directory, "server.crt"),
    "-subj",
    "/CN=kiln-runtime-server",
    "-addext",
    "subjectAltName=IP:127.0.0.1",
    "-days",
    "1",
  ]);
  await run("openssl", [
    "req",
    "-x509",
    "-newkey",
    "ec",
    "-pkeyopt",
    "ec_paramgen_curve:P-256",
    "-nodes",
    "-keyout",
    join(directory, "gateway-ca.key"),
    "-out",
    join(directory, "gateway-ca.crt"),
    "-subj",
    "/CN=kiln-runtime-gateway-ca",
    "-addext",
    "basicConstraints=critical,CA:TRUE",
    "-addext",
    "keyUsage=critical,keyCertSign,digitalSignature",
    "-days",
    "1",
  ]);
}

async function createIsolatedDatabase(
  baseURL: string,
): Promise<{ url: string; destroy: () => Promise<void> }> {
  const database = `kiln_gateway_runtime_${randomUUID().replaceAll("-", "")}`;
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

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
