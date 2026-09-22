import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { KilnClient, type KilnApiError } from "./kiln-client.js";

const resourceId = z.string().min(1).max(128).regex(/^[A-Za-z0-9_-]+$/);
const nodeName = z.string().min(1).max(128).regex(/^[A-Za-z0-9][A-Za-z0-9._-]*$/);

function result(data: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
  };
}

function failure(error: unknown) {
  const apiError = error as Partial<KilnApiError>;
  const status = typeof apiError.status === "number" ? apiError.status : 0;
  const code = typeof apiError.code === "string" ? apiError.code : "request_failed";
  console.error(`Kiln MCP request failed: status=${status} code=${code}`);
  return {
    content: [{ type: "text" as const, text: `Kiln API request failed (${code}).` }],
    isError: true,
  };
}

export function createServer(client = new KilnClient(process.env.KILN_TOKEN ?? "")) {
  const server = new McpServer({ name: "kiln", version: "0.1.0" });

  server.registerTool(
    "kiln_status",
    { description: "Read Kiln control-plane status. This does not create compute." },
    async () => {
      try {
        return result(await client.status());
      } catch (error) {
        return failure(error);
      }
    },
  );
  server.registerTool(
    "kiln_doctor",
    {
      description: "Read Kiln gateway readiness, monitoring evidence, incidents, and recovery guidance. This does not start, stop, create, repair, or configure infrastructure.",
      inputSchema: {
        network: z.boolean().optional(),
        node: nodeName.optional(),
      },
    },
    async ({ network, node }) => {
      try {
        return result(await client.doctor({ network, node }));
      } catch (error) {
        return failure(error);
      }
    },
  );
  server.registerTool(
    "kiln_resources_list",
    { description: "List Kiln-owned resources visible to this credential. This does not inspect external Proxmox resources." },
    async () => {
      try {
        return result(await client.resources());
      } catch (error) {
        return failure(error);
      }
    },
  );
  server.registerTool(
    "kiln_resource_get",
    { description: "Read one Kiln resource by its Kiln resource ID.", inputSchema: { resourceId } },
    async ({ resourceId: id }) => {
      try {
        return result(await client.resource(id));
      } catch (error) {
        return failure(error);
      }
    },
  );
  server.registerTool(
    "kiln_resource_stop",
    { description: "Request that Kiln stop a managed resource. Kiln will enforce ownership checks before any provider action.", inputSchema: { resourceId } },
    async ({ resourceId: id }) => {
      try {
        return result(await client.stopResource(id));
      } catch (error) {
        return failure(error);
      }
    },
  );
  server.registerTool(
    "kiln_resource_destroy",
    { description: "Request Kiln to destroy a managed resource. Kiln will deny this when ownership validation fails.", inputSchema: { resourceId } },
    async ({ resourceId: id }) => {
      try {
        return result(await client.destroyResource(id));
      } catch (error) {
        return failure(error);
      }
    },
  );
  return server;
}

async function main() {
  const server = createServer();
  await server.connect(new StdioServerTransport());
}

main().catch((error: unknown) => {
  console.error("Kiln MCP failed to start:", error instanceof Error ? error.message : "configuration error");
  process.exitCode = 1;
});
