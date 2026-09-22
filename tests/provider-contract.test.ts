import { describe, expect, it } from "vitest";
import type { ComputeProvider, Resource } from "@kiln/core";
import { FakeComputeProvider } from "@kiln/providers";
const resource: Resource = {
  id: "dev_contract",
  installationId: "installation",
  projectId: "default",
  type: "development",
  ownership: "KILN_MANAGED",
  state: "READY",
  providerId: "fake",
  providerResourceId: "dev_contract",
  providerKind: "fake",
  node: null,
  pool: "kiln",
  createdBy: "test",
  createdAt: new Date().toISOString(),
  expiresAt: null,
  profile: null,
};
function computeProviderContract(name: string, make: () => ComputeProvider) {
  describe(name, () => {
    it("returns a missing observation distinctly from a resource", async () => {
      expect(await make().inspect("absent")).toBeNull();
    });
    it("reports capacity metrics without changing a workload", async () => {
      const provider = make();
      await expect(provider.metrics()).resolves.toEqual(expect.any(Array));
    });
  });
}
computeProviderContract("FakeComputeProvider", () => new FakeComputeProvider());
describe("FakeComputeProvider mutation contract", () => {
  it("creates, stops, and destroys a correctly owned record", async () => {
    const provider = new FakeComputeProvider();
    await provider.create(resource);
    await provider.stop(resource);
    await provider.destroy(resource);
    expect(await provider.inspect(resource.providerResourceId)).toBeNull();
  });
});
