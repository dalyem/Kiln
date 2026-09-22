import { describe, expect, it } from "vitest";
import { KilnClient as McpKilnClient } from "../apps/mcp/src/kiln-client.js";
import { KilnClient as SdkKilnClient } from "../packages/sdk-js/src/index.js";

const doctorResponse = {
  schemaVersion: 1,
  checkedAt: "2026-01-01T00:00:00.000Z",
  installationId: "installation_test",
  providerMode: "fake",
  persistence: "memory",
  overall: "UNKNOWN" as const,
  checks: [],
  nodes: [],
  incidents: [],
  repairEnabled: false as const,
  limitations: ["No gateway has reported health evidence."],
};

describe("doctor adapters", () => {
  it("SDK sends only the encoded doctor query through the Kiln API", async () => {
    const requested: URL[] = [];
    const client = new SdkKilnClient({
      baseUrl: "https://kiln.example.test",
      token: "token",
      fetch: async (input) => {
        requested.push(new URL(input.toString()));
        return Response.json(doctorResponse);
      },
    });

    await expect(client.doctor({ network: true, node: "node-a" })).resolves.toMatchObject({ overall: "UNKNOWN" });
    expect(requested).toHaveLength(1);
    expect(requested[0]?.pathname).toBe("/v1/doctor");
    expect(requested[0]?.searchParams.get("network")).toBe("true");
    expect(requested[0]?.searchParams.get("node")).toBe("node-a");
  });

  it("MCP client reads doctor evidence through the same Kiln endpoint", async () => {
    const requested: URL[] = [];
    const client = new McpKilnClient(
      "token",
      "https://kiln.example.test",
      async (input) => {
        requested.push(new URL(input.toString()));
        return Response.json(doctorResponse);
      },
    );

    await expect(client.doctor({ network: true, node: "node-a" })).resolves.toEqual(doctorResponse);
    expect(requested[0]?.pathname).toBe("/v1/doctor");
    expect(requested[0]?.search).toBe("?network=true&node=node-a");
  });

  it("does not expose a repair method to SDK or MCP clients", () => {
    const sdk = new SdkKilnClient({ baseUrl: "https://kiln.example.test", token: "token" });
    const mcp = new McpKilnClient("token", "https://kiln.example.test");

    expect("repair" in sdk).toBe(false);
    expect("repair" in mcp).toBe(false);
  });
});
