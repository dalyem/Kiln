import { createHash } from "node:crypto";

export interface LinuxQualifiedQemuEvidence {
  vmid: string;
  pending: unknown;
  snapshots: unknown;
  firewallOptions: unknown;
  firewallRules: unknown;
  firewallAliases: unknown;
  firewallIpsets: unknown;
  haResources: unknown;
  status: unknown;
}

export interface LinuxQualifiedQemuExpected {
  vmid: string;
  storage: string;
  volume: string;
  template: boolean;
  name: string | null;
  tags: string[];
  status: "running" | "stopped";
}

export interface LinuxQualifiedQemuGraph {
  vmid: string;
  configDigest: string;
  bootVolume: string;
  template: boolean;
  generatedCtime: string;
  generatedUuid: string;
  vmgenid: string;
}

export class LinuxQualifiedQemuConfigError extends Error {
  constructor(message: string) {
    super(message);
  }
}

const VMID = /^[1-9][0-9]{2,8}$/;
const NATIVE = /^[A-Za-z0-9._:-]+$/;
const DIGEST = /^[a-f0-9]{40}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CONFIG_KEYS = new Set([
  "bios",
  "boot",
  "cores",
  "cpu",
  "digest",
  "memory",
  "meta",
  "name",
  "scsi0",
  "scsihw",
  "serial0",
  "smbios1",
  "tags",
  "template",
  "vmgenid",
]);

function deny(message: string): never {
  throw new LinuxQualifiedQemuConfigError(message);
}

function record(value: unknown, message: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    deny(message);
  return value as Record<string, unknown>;
}

function string(value: unknown, message: string): string {
  if (typeof value !== "string" || value.length === 0) deny(message);
  return value;
}

function exactTags(value: unknown, expected: string[]): void {
  if (!expected.length || expected.some((tag) => !NATIVE.test(tag)))
    deny("Linux QEMU ownership tags are invalid");
  const actual = string(value, "Linux QEMU ownership tags are invalid").split(
    ";",
  );
  const sortedExpected = [...expected].sort();
  if (
    actual.length !== sortedExpected.length ||
    new Set(actual).size !== actual.length ||
    actual.some((tag) => !NATIVE.test(tag)) ||
    [...actual].sort().some((tag, index) => tag !== sortedExpected[index])
  )
    deny("Linux QEMU ownership tags do not match the saved plan");
}

function validatePending(
  value: unknown,
  config: Record<string, unknown>,
): void {
  if (!Array.isArray(value) || value.length !== Object.keys(config).length)
    deny("Linux QEMU pending evidence is incomplete");
  const seen = new Set<string>();
  for (const item of value) {
    const row = record(item, "Linux QEMU pending evidence is incomplete");
    if (
      typeof row.key !== "string" ||
      !Object.hasOwn(row, "value") ||
      Object.hasOwn(row, "pending") ||
      Object.hasOwn(row, "delete") ||
      seen.has(row.key) ||
      !Object.hasOwn(config, row.key) ||
      row.value !== config[row.key]
    )
      deny("Linux QEMU has pending configuration");
    seen.add(row.key);
  }
  if (Object.keys(config).some((key) => !seen.has(key)))
    deny("Linux QEMU pending evidence does not match current configuration");
}

function validateSnapshots(value: unknown): void {
  if (!Array.isArray(value) || value.length !== 1)
    deny("Linux QEMU snapshots are not qualified");
  const snapshot = record(value[0], "Linux QEMU snapshots are not qualified");
  if (
    snapshot.name !== "current" ||
    Object.keys(snapshot).some(
      (key) => !["name", "description", "digest", "running"].includes(key),
    )
  )
    deny("Linux QEMU snapshots are not qualified");
}

function validateFirewall(
  options: unknown,
  rules: unknown,
  aliases: unknown,
  ipsets: unknown,
): void {
  const actual = record(options, "Linux QEMU firewall options are incomplete");
  if (
    Object.keys(actual).length !== 1 ||
    typeof actual.digest !== "string" ||
    actual.digest.length === 0 ||
    !Array.isArray(rules) ||
    rules.length !== 0 ||
    !Array.isArray(aliases) ||
    aliases.length !== 0 ||
    !Array.isArray(ipsets) ||
    ipsets.length !== 0
  )
    deny("Linux QEMU firewall state is not qualified");
}

function validateHa(value: unknown, vmid: string): void {
  if (!Array.isArray(value)) deny("Linux QEMU HA evidence is incomplete");
  for (const item of value) {
    const row = record(item, "Linux QEMU HA evidence is incomplete");
    if (
      row.sid === `vm:${vmid}` ||
      row.vmid === vmid ||
      row.vmid === Number(vmid)
    )
      deny("Linux QEMU is managed by HA");
  }
}

export function qualifyLinuxImportQemuGraph(
  configValue: unknown,
  evidence: LinuxQualifiedQemuEvidence,
  expected: LinuxQualifiedQemuExpected,
): LinuxQualifiedQemuGraph {
  if (
    !VMID.test(expected.vmid) ||
    evidence.vmid !== expected.vmid ||
    !NATIVE.test(expected.storage) ||
    !NATIVE.test(expected.volume) ||
    !expected.tags.length
  )
    deny("Linux QEMU plan is invalid");
  const config = record(configValue, "Linux QEMU config is incomplete");
  if (Object.keys(config).some((key) => !CONFIG_KEYS.has(key)))
    deny("Linux QEMU config has an unexpected field");
  if (
    config.bios !== "seabios" ||
    config.boot !== "order=scsi0" ||
    config.cores !== 2 ||
    config.cpu !== "kvm64" ||
    config.memory !== "2048" ||
    config.scsihw !== "virtio-scsi-pci" ||
    config.serial0 !== "socket" ||
    typeof config.digest !== "string" ||
    !DIGEST.test(config.digest) ||
    config.template !== (expected.template ? 1 : undefined) ||
    config.scsi0 !== `${expected.storage}:${expected.volume},size=8G`
  )
    deny("Linux QEMU config exceeds the qualified profile");
  if (
    expected.name === null
      ? config.name !== undefined
      : config.name !== expected.name
  )
    deny("Linux QEMU name does not match the saved plan");
  exactTags(config.tags, expected.tags);
  const meta = string(config.meta, "Linux QEMU generated metadata is invalid");
  const ctime = /^creation-qemu=11\.0\.0,ctime=(\d+)$/.exec(meta)?.[1];
  const uuid = /^uuid=([0-9a-f-]{36})$/i.exec(
    string(config.smbios1, "Linux QEMU generated identity is invalid"),
  )?.[1];
  const vmgenid = string(
    config.vmgenid,
    "Linux QEMU generated identity is invalid",
  );
  if (!ctime || !uuid || !UUID.test(uuid) || !UUID.test(vmgenid))
    deny("Linux QEMU generated identity is invalid");
  const status = record(evidence.status, "Linux QEMU status is incomplete");
  if (status.status !== expected.status)
    deny("Linux QEMU power state does not match the qualified phase");
  validatePending(evidence.pending, config);
  validateSnapshots(evidence.snapshots);
  validateFirewall(
    evidence.firewallOptions,
    evidence.firewallRules,
    evidence.firewallAliases,
    evidence.firewallIpsets,
  );
  validateHa(evidence.haResources, expected.vmid);
  return {
    vmid: expected.vmid,
    configDigest: config.digest,
    bootVolume: `${expected.storage}:${expected.volume}`,
    template: expected.template,
    generatedCtime: ctime,
    generatedUuid: uuid.toLowerCase(),
    vmgenid: vmgenid.toLowerCase(),
  };
}

export function canonicalLinuxQualifiedQemuIdentity(
  graph: LinuxQualifiedQemuGraph,
): string {
  return createHash("sha256")
    .update(
      JSON.stringify({
        vmid: graph.vmid,
        bootVolume: graph.bootVolume,
        template: graph.template,
        generatedCtime: graph.generatedCtime,
        generatedUuid: graph.generatedUuid,
        vmgenid: graph.vmgenid,
      }),
    )
    .digest("hex");
}
