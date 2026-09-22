import { describe, expect, it } from "vitest";
import {
  canonicalQualifiedQemuConfig,
  qualifyQemuConfig,
  type QualifiedQemuInput,
} from "../packages/proxmox/src/qualified-config.js";

function input(
  overrides: Partial<QualifiedQemuInput> = {},
): QualifiedQemuInput {
  return {
    config: {
      bios: "seabios",
      scsihw: "virtio-scsi-single",
      boot: "order=scsi0",
      serial0: "socket",
      memory: "128",
      cores: 1,
      cpu: "kvm64",
      scsi0: "local-lvm:vm-101-disk-0,size=4M",
      tags: "kiln;kiln-managed;kiln-installation-inst1;kiln-resource-network_probe;kiln-resource-id-r1;kiln-qualification-nonce-nonce1",
      digest: "a".repeat(40),
      meta: "creation-qemu=11.0.0,ctime=1",
      smbios1: "uuid=12345678-1234-1234-1234-123456789abc",
      vmgenid: "12345678-1234-1234-1234-123456789abc",
    },
    evidence: {
      vmid: "101",
      pending: [
        ["bios", "seabios"],
        ["scsihw", "virtio-scsi-single"],
        ["boot", "order=scsi0"],
        ["serial0", "socket"],
        ["memory", "128"],
        ["cores", 1],
        ["cpu", "kvm64"],
        ["scsi0", "local-lvm:vm-101-disk-0,size=4M"],
        [
          "tags",
          "kiln;kiln-managed;kiln-installation-inst1;kiln-resource-network_probe;kiln-resource-id-r1;kiln-qualification-nonce-nonce1",
        ],
        ["digest", "a".repeat(40)],
        ["meta", "creation-qemu=11.0.0,ctime=1"],
        ["smbios1", "uuid=12345678-1234-1234-1234-123456789abc"],
        ["vmgenid", "12345678-1234-1234-1234-123456789abc"],
      ].map(([key, value]) => ({ key, value })),
      snapshots: [
        {
          name: "current",
          description: "You are here!",
          digest: "a".repeat(40),
          running: 0,
        },
      ],
      firewallOptions: { digest: "b".repeat(40) },
      firewallRules: [],
      firewallAliases: [],
      firewallIpsets: [],
      haResources: [],
    },
    expected: {
      vmid: "101",
      storage: "local-lvm",
      volume: "vm-101-disk-0",
      template: false,
      name: null,
      ownership: {
        installationId: "inst1",
        resourceId: "r1",
        nonce: "nonce1",
        tags: [
          "kiln",
          "kiln-managed",
          "kiln-installation-inst1",
          "kiln-resource-network_probe",
          "kiln-resource-id-r1",
          "kiln-qualification-nonce-nonce1",
        ],
      },
    },
    ...overrides,
  };
}

describe("qualified QEMU configuration", () => {
  it("accepts the one-disk BIOS profile with no network device", () => {
    expect(qualifyQemuConfig(input())).toMatchObject({
      vmid: "101",
      bootVolume: "local-lvm:vm-101-disk-0",
      template: false,
    });
  });

  it.each([
    ["a NIC", { net0: "virtio=BC:24:11:00:00:01,bridge=vmbr0" }],
    ["an extra disk", { scsi1: "local-lvm:vm-101-disk-1,size=4M" }],
    ["a larger boot disk", { scsi0: "local-lvm:vm-101-disk-0,size=8M" }],
    ["a changed serial device", { serial0: "none" }],
    ["an unsupported CPU", { cpu: "host" }],
    [
      "extra SMBIOS fields",
      {
        smbios1:
          "uuid=12345678-1234-1234-1234-123456789abc,manufacturer=foreign",
      },
    ],
    ["a changed ownership tag", { tags: "kiln;kiln-managed" }],
  ])("rejects %s", (_name, fields) => {
    expect(() =>
      qualifyQemuConfig(
        input({
          config: { ...(input().config as Record<string, unknown>), ...fields },
        }),
      ),
    ).toThrow();
  });

  it.each([
    [
      "a pending edit",
      { pending: [{ key: "scsi0", value: "old", pending: "new" }] },
    ],
    [
      "a deleted pending field",
      { pending: [{ key: "scsi0", value: "old", delete: 1 }] },
    ],
    [
      "a pending current-value mismatch",
      { pending: [{ key: "scsi0", value: "foreign" }] },
    ],
    [
      "a pending unexpected device",
      { pending: [{ key: "net0", value: "virtio=BC:24:11:00:00:01" }] },
    ],
    [
      "a second snapshot",
      { snapshots: [{ name: "current" }, { name: "before" }] },
    ],
    ["a firewall rule", { firewallRules: [{ type: "in" }] }],
    ["a firewall alias", { firewallAliases: [{ name: "host" }] }],
    ["an HA entry", { haResources: [{ sid: "vm:101" }] }],
  ])("rejects %s", (_name, evidence) => {
    expect(() =>
      qualifyQemuConfig(
        input({ evidence: { ...input().evidence, ...evidence } }),
      ),
    ).toThrow();
  });

  it("requires the base disk name after template conversion", () => {
    const templateConfig = {
      ...(input().config as Record<string, unknown>),
      template: 1,
      scsi0: "local-lvm:base-101-disk-0,size=4M",
    };
    const template = input({
      config: templateConfig,
      evidence: {
        ...input().evidence,
        pending: Object.entries(templateConfig).map(([key, value]) => ({
          key,
          value,
        })),
      },
      expected: {
        ...input().expected,
        template: true,
        volume: "base-101-disk-0",
      },
    });
    expect(() => qualifyQemuConfig(template)).not.toThrow();
    expect(() =>
      qualifyQemuConfig(
        input({ config: template.config, expected: input().expected }),
      ),
    ).toThrow();
  });

  it("binds its digest to generated clone identity values", () => {
    const first = canonicalQualifiedQemuConfig(qualifyQemuConfig(input()));
    const changedConfig = {
      ...(input().config as Record<string, unknown>),
      smbios1: "uuid=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    };
    const changed = canonicalQualifiedQemuConfig(
      qualifyQemuConfig(
        input({
          config: changedConfig,
          evidence: {
            ...input().evidence,
            pending: Object.entries(changedConfig).map(([key, value]) => ({
              key,
              value,
            })),
          },
        }),
      ),
    );
    expect(changed).not.toBe(first);
  });
});
