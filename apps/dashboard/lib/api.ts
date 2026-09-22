import "server-only";

export type DashboardStatus = {
  installationId: string;
  providerMode: string;
  mutationEnabled: boolean;
  persistence: string;
  monitoring?: { enabled: boolean; repairEnabled: false };
};

export type DashboardResource = {
  id: string;
  type: string;
  ownership: string;
  state: string;
  node: string | null;
  expiresAt: string | null;
};

export type DashboardCheck = {
  id: string;
  status: "PASS" | "WARN" | "FAIL" | "UNKNOWN";
  code: string;
  message: string;
};

export type DashboardDoctor = {
  schemaVersion: 1;
  checkedAt: string;
  installationId: string;
  providerMode: string;
  persistence: string;
  overall: "HEALTHY" | "DEGRADED" | "UNKNOWN";
  checks: DashboardCheck[];
  nodes: Array<{
    node: string;
    gatewayId: string | null;
    status: "READY" | "NOT_READY" | "QUARANTINED" | "UNCONFIGURED";
    checks: DashboardCheck[];
  }>;
  incidents: DashboardIncident[];
  repairEnabled: false;
  limitations: string[];
};

export type DashboardIncident = {
  id: string;
  node: string;
  gatewayId: string | null;
  code: string;
  severity: "warning" | "critical";
  status: "OPEN" | "RESOLVED";
  firstSeenAt: string;
  lastSeenAt: string;
  resolvedAt: string | null;
  message: string;
  guidance: string[];
};

export type DashboardGateway = {
  resource: DashboardResource;
  metadata: { resourceId: string; node: string; generation: string; createdAt: string };
  health: { resourceId: string; node: string; status: string; observedAt: string } | null;
};

type ApiFailure = { message: string };

function config(): { baseUrl: URL; token: string } | ApiFailure {
  const baseUrl = process.env.KILN_URL;
  const token = process.env.KILN_TOKEN;
  if (!baseUrl || !token) {
    return { message: "Dashboard API credentials are not configured. Set KILN_URL and KILN_TOKEN on the dashboard server." };
  }
  try {
    const parsed = new URL(baseUrl);
    if (
      (parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
      parsed.username || parsed.password || parsed.search || parsed.hash ||
      !["", "/"].includes(parsed.pathname)
    ) {
      return { message: "Dashboard API URL must be an HTTP(S) origin without credentials, path, query, or fragment." };
    }
    return { baseUrl: parsed, token };
  } catch {
    return { message: "Dashboard API URL is invalid." };
  }
}

export async function getDashboardData(): Promise<{
  status?: DashboardStatus;
  resources?: DashboardResource[];
  doctor?: DashboardDoctor;
  gateways?: DashboardGateway[];
  incidents?: DashboardIncident[];
  monitoringError?: string;
  error?: string;
}> {
  const settings = config();
  if ("message" in settings) {
    return { error: settings.message };
  }
  try {
    const [status, resources, doctor, gateways, incidents] = await Promise.allSettled([
      request<DashboardStatus>(settings, "/v1/status"),
      request<{ resources: DashboardResource[] }>(settings, "/v1/resources"),
      request<DashboardDoctor>(settings, "/v1/doctor?network=true"),
      request<{ gateways: DashboardGateway[] }>(settings, "/v1/gateways"),
      request<{ incidents: DashboardIncident[] }>(settings, "/v1/incidents?status=open"),
    ]);
    if (status.status === "rejected") return { error: safeError(status.reason) };
    if (resources.status === "rejected") return { error: safeError(resources.reason) };
    const monitoringFailed = [doctor, gateways, incidents].some((result) => result.status === "rejected");
    return {
      status: status.value,
      resources: resources.value.resources,
      doctor: doctor.status === "fulfilled" ? doctor.value : undefined,
      gateways: gateways.status === "fulfilled" ? gateways.value.gateways : undefined,
      incidents: incidents.status === "fulfilled" ? incidents.value.incidents : undefined,
      monitoringError: monitoringFailed ? "Some monitoring data could not be read from the control plane." : undefined,
    };
  } catch (error) {
    return { error: safeError(error) };
  }
}

async function request<T>(settings: { baseUrl: URL; token: string }, path: string): Promise<T> {
  const response = await fetch(new URL(path, settings.baseUrl), {
    headers: { Accept: "application/json", Authorization: `Bearer ${settings.token}` },
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) {
    throw new Error(`Kiln API returned HTTP ${response.status}`);
  }
  return response.json() as Promise<T>;
}

function safeError(error: unknown): string {
  if (error instanceof Error && /^Kiln API returned HTTP \d{3}$/.test(error.message)) {
    return error.message;
  }
  return "Kiln API could not be reached.";
}
