import { describe, expect, it } from "vitest";
import { ProxmoxProvider, parseProxmoxToken } from "@kiln/proxmox";
import type { Resource } from "@kiln/core";
const resource: Resource = {
  id: "dev_x",
  installationId: "i",
  projectId: "default",
  type: "development",
  ownership: "KILN_MANAGED",
  state: "READY",
  providerId: "proxmox",
  providerResourceId: "100",
  providerKind: "qemu",
  node: null,
  pool: "kiln",
  createdBy: "test",
  createdAt: new Date().toISOString(),
  expiresAt: null,
  profile: null,
};
describe("Proxmox Phase 1 adapter", () => {
  it("requires HTTPS and the PVE service-token format", () => {
    expect(() =>
      parseProxmoxToken(
        "http://pve.local:8006",
        "PVEAPIToken=user@pam!kiln=secret",
      ),
    ).toThrow("HTTPS");
    expect(() =>
      parseProxmoxToken("https://pve.local:8006", "bad-token"),
    ).toThrow("token format");
  });
  it("refuses every mutation before making a provider request", async () => {
    const provider = new ProxmoxProvider(
      parseProxmoxToken(
        "https://pve.local:8006",
        "PVEAPIToken=kiln@pam!api=secret",
      ),
      async () => {
        throw new Error("network call should not occur");
      },
    );
    await expect(
      Promise.all([
        provider.create(resource),
        provider.start(resource),
        provider.stop(resource),
        provider.destroy(resource),
      ]),
    ).rejects.toMatchObject({ code: "UNSUPPORTED", status: 501 });
  });
  it("discovers qemu and lxc inventory from read-only endpoints without returning config secrets", async () => {
    const calls: string[] = [];
    const provider = new ProxmoxProvider(
      parseProxmoxToken(
        "https://pve.local:8006",
        "PVEAPIToken=kiln@pam!api=secret",
      ),
      async (input) => {
        const path = new URL(input.toString()).pathname;
        calls.push(path);
        const data = path.endsWith("/nodes")
          ? [
              {
                node: "pve1",
                status: "online",
                maxcpu: 8,
                cpu: 0.25,
                maxmem: 100,
                mem: 25,
              },
            ]
          : path.endsWith("/storage")
            ? [{ storage: "local", shared: 0 }]
            : path.endsWith("/resources")
              ? [
                  { type: "qemu", vmid: 100, node: "pve1", pool: "kiln" },
                  { type: "lxc", vmid: 101, node: "pve1", pool: "kiln" },
                ]
              : path.endsWith("qemu/100/config")
                ? {
                    tags: "kiln;kiln-managed;kiln-resource-development",
                    token: "secret",
                  }
                : {
                    tags: "kiln;kiln-managed;kiln-resource-unknown",
                    password: "secret",
                  };
        return new Response(JSON.stringify({ data }));
      },
    );
    const inventory = await provider.discover();
    expect(calls.some((path) => path.endsWith("qemu/100/config"))).toBe(true);
    expect(inventory.resources).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          providerResourceId: "100",
          providerKind: "qemu",
          kind: "development",
        }),
        expect.objectContaining({
          providerResourceId: "101",
          providerKind: "lxc",
          kind: null,
        }),
      ]),
    );
    expect(JSON.stringify(inventory)).not.toContain("secret");
  });
  it("rejects an HTTP 200 response without the Proxmox data envelope", async () => {
    const provider = new ProxmoxProvider(
      parseProxmoxToken(
        "https://pve.local:8006",
        "PVEAPIToken=kiln@pam!api=secret",
      ),
      async () => new Response("{}", { status: 200 }),
    );
    await expect(provider.discover()).rejects.toMatchObject({
      code: "PROVIDER_FAILURE",
      status: 502,
    });
  });
});
