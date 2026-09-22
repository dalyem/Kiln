export type KilnApiError = {
  status: number;
  code: string;
};

export class KilnClient {
  private readonly baseUrl: URL;

  constructor(
    private readonly token: string,
    baseUrl = process.env.KILN_URL,
    private readonly fetcher: typeof fetch = fetch,
  ) {
    if (!token) {
      throw new Error("KILN_TOKEN is required to start the MCP server");
    }
    if (!baseUrl) {
      throw new Error("KILN_URL is required to start the MCP server");
    }
    try {
      this.baseUrl = new URL(baseUrl);
    } catch {
      throw new Error("KILN_URL must be an absolute HTTP(S) URL");
    }
    if (
      !["http:", "https:"].includes(this.baseUrl.protocol) ||
      this.baseUrl.username || this.baseUrl.password || this.baseUrl.search || this.baseUrl.hash ||
      !["", "/"].includes(this.baseUrl.pathname)
    ) {
      throw new Error("KILN_URL must be an HTTP(S) origin without credentials, path, query, or fragment");
    }
  }

  async status(): Promise<unknown> {
    return this.request("/v1/status");
  }

  async resources(): Promise<unknown> {
    return this.request("/v1/resources");
  }

  async resource(resourceId: string): Promise<unknown> {
    return this.request(`/v1/resources/${encodeURIComponent(resourceId)}`);
  }

  async doctor(options: { network?: boolean; node?: string } = {}): Promise<unknown> {
    const query = new URLSearchParams();
    if (options.network) query.set("network", "true");
    if (options.node) query.set("node", options.node);
    const suffix = query.size > 0 ? `?${query}` : "";
    return this.request(`/v1/doctor${suffix}`);
  }

  async incidents(options: { status?: "open" | "all"; node?: string } = {}): Promise<unknown> {
    const query = new URLSearchParams();
    if (options.status) query.set("status", options.status);
    if (options.node) query.set("node", options.node);
    const suffix = query.size > 0 ? `?${query}` : "";
    return this.request(`/v1/incidents${suffix}`);
  }

  async stopResource(resourceId: string): Promise<unknown> {
    return this.request(`/v1/resources/${encodeURIComponent(resourceId)}/stop`, {
      method: "POST",
      body: "{}",
    });
  }

  async destroyResource(resourceId: string): Promise<unknown> {
    return this.request(`/v1/resources/${encodeURIComponent(resourceId)}`, {
      method: "DELETE",
    });
  }

  private async request(path: string, init?: RequestInit): Promise<unknown> {
    const url = new URL(path, this.baseUrl);
    const response = await this.fetcher(url, {
      ...init,
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${this.token}`,
        ...(init?.body ? { "Content-Type": "application/json" } : {}),
        ...init?.headers,
      },
    });
    const body = await readJson(response);
    if (!response.ok) {
      const code = errorCode(body);
      throw { status: response.status, code } satisfies KilnApiError;
    }
    return body;
  }
}

async function readJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return undefined;
  }
}

function errorCode(body: unknown): string {
  if (
    body &&
    typeof body === "object" &&
    "error" in body &&
    body.error &&
    typeof body.error === "object" &&
    "code" in body.error &&
    typeof body.error.code === "string" &&
    knownErrorCodes.has(body.error.code)
  ) {
    return body.error.code;
  }
  return "request_failed";
}

const knownErrorCodes = new Set([
  "CONFLICT", "IDEMPOTENCY_CONFLICT", "INTERNAL", "INVALID_INPUT", "NOT_FOUND", "PROVIDER_FAILURE",
  "SAFETY_DENIED", "UNAUTHENTICATED", "UNAUTHORIZED", "UNSUPPORTED",
]);
