export type Ownership = "KILN_MANAGED" | "EXTERNAL" | "IMPORTED";

export type Resource = {
  id: string;
  installationId: string;
  projectId: string;
  type: string;
  ownership: Ownership;
  state: string;
  providerId: string;
  providerResourceId: string;
  providerKind: string;
  node: string | null;
  pool: string | null;
  createdBy: string;
  createdAt: string;
  expiresAt: string | null;
  profile: string | null;
};

export type Status = {
  installationId: string;
  providerMode: string;
  mutationEnabled: boolean;
  persistence: string;
  monitoring?: { enabled: boolean; repairEnabled: false };
};

export type DoctorOverall = "HEALTHY" | "DEGRADED" | "UNKNOWN";
export type DoctorCheckStatus = "PASS" | "WARN" | "FAIL" | "UNKNOWN";
export type DoctorNodeStatus = "READY" | "NOT_READY" | "QUARANTINED" | "UNCONFIGURED";

export type DoctorCheck = {
  id: string;
  status: DoctorCheckStatus;
  code: string;
  message: string;
};

export type DoctorNode = {
  node: string;
  gatewayId: string | null;
  status: DoctorNodeStatus;
  checks: DoctorCheck[];
};

export type DoctorIncident = {
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

export type DoctorReport = {
  schemaVersion: 1;
  checkedAt: string;
  installationId: string;
  providerMode: string;
  persistence: string;
  overall: DoctorOverall;
  checks: DoctorCheck[];
  nodes: DoctorNode[];
  incidents: DoctorIncident[];
  repairEnabled: false;
  limitations: string[];
};

export type DoctorOptions = {
  network?: boolean;
  node?: string;
};

export class KilnApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
  ) {
    super(`Kiln API request failed (${code})`);
  }
}

export class KilnClient {
  private readonly baseUrl: URL;

  constructor(
    options: { baseUrl: string; token: string; fetch?: typeof fetch; timeoutMilliseconds?: number },
  ) {
    if (!options.token) {
      throw new Error("KilnClient requires a token");
    }
    this.baseUrl = new URL(options.baseUrl);
    if (
      !["http:", "https:"].includes(this.baseUrl.protocol) ||
      this.baseUrl.username || this.baseUrl.password || this.baseUrl.search || this.baseUrl.hash ||
      !["", "/"].includes(this.baseUrl.pathname)
    ) {
      throw new Error("KilnClient baseUrl must be an HTTP(S) origin without credentials, path, query, or fragment");
    }
    if (!Number.isFinite(options.timeoutMilliseconds ?? 15_000) || (options.timeoutMilliseconds ?? 15_000) < 1) {
      throw new Error("KilnClient timeoutMilliseconds must be a positive number");
    }
    this.token = options.token;
    this.fetcher = options.fetch ?? fetch;
    this.timeoutMilliseconds = options.timeoutMilliseconds ?? 15_000;
  }

  private readonly token: string;
  private readonly fetcher: typeof fetch;
  private readonly timeoutMilliseconds: number;

  status(): Promise<Status> {
    return this.request("/v1/status");
  }

  resources(): Promise<{ resources: Resource[] }> {
    return this.request("/v1/resources");
  }

  resource(id: string): Promise<Resource> {
    return this.request(`/v1/resources/${encodeURIComponent(id)}`);
  }

  inventory(): Promise<unknown> {
    return this.request("/v1/inventory");
  }

  doctor(options: DoctorOptions = {}): Promise<DoctorReport> {
    const query = new URLSearchParams();
    if (options.network) query.set("network", "true");
    if (options.node) query.set("node", options.node);
    const suffix = query.size > 0 ? `?${query}` : "";
    return this.request(`/v1/doctor${suffix}`);
  }

  incidents(options: { status?: "open" | "all"; node?: string } = {}): Promise<{ incidents: DoctorIncident[] }> {
    const query = new URLSearchParams();
    if (options.status) query.set("status", options.status);
    if (options.node) query.set("node", options.node);
    const suffix = query.size > 0 ? `?${query}` : "";
    return this.request(`/v1/incidents${suffix}`);
  }

  createDevelopment(input: { ttlSeconds: number; projectId?: string; profile?: string; idempotencyKey: string }): Promise<Resource> {
    const { idempotencyKey, ...body } = input;
    return this.request("/v1/resources", {
      method: "POST",
      body: JSON.stringify({ type: "development", projectId: "default", ...body }),
      headers: { "Idempotency-Key": idempotencyKey },
    });
  }

  stopResource(id: string): Promise<Resource> {
    return this.request(`/v1/resources/${encodeURIComponent(id)}/stop`, { method: "POST", body: "{}" });
  }

  destroyResource(id: string): Promise<Resource> {
    return this.request(`/v1/resources/${encodeURIComponent(id)}`, { method: "DELETE" });
  }

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await this.fetcher(new URL(path, this.baseUrl), {
      ...init,
      redirect: "error",
      signal: AbortSignal.timeout(this.timeoutMilliseconds),
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${this.token}`,
        ...(init?.body ? { "Content-Type": "application/json" } : {}),
        ...init?.headers,
      },
    });
    const body: unknown = await response.json().catch(() => undefined);
    if (!response.ok) {
      throw new KilnApiError(response.status, apiErrorCode(body));
    }
    return body as T;
  }
}

function apiErrorCode(body: unknown): string {
  if (body && typeof body === "object" && "error" in body && body.error && typeof body.error === "object" && "code" in body.error && typeof body.error.code === "string" && knownErrorCodes.has(body.error.code)) {
    return body.error.code;
  }
  return "request_failed";
}

const knownErrorCodes = new Set([
  "CONFLICT", "IDEMPOTENCY_CONFLICT", "INTERNAL", "INVALID_INPUT", "NOT_FOUND", "PROVIDER_FAILURE",
  "SAFETY_DENIED", "UNAUTHENTICATED", "UNAUTHORIZED", "UNSUPPORTED",
]);
