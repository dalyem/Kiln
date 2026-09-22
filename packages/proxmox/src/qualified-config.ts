import { createHash } from "node:crypto";

export interface SavedOwnershipProof {
  installationId: string;
  resourceId: string;
  nonce: string;
  tags: string[];
}

export interface ExpectedQualifiedQemuPlan {
  vmid: string;
  storage: "local-lvm";
  volume: string;
  template: boolean;
  name: string | null;
  ownership: SavedOwnershipProof;
}

export interface QualifiedQemuEvidence {
  vmid: string;
  pending: unknown;
  snapshots: unknown;
  firewallOptions: unknown;
  firewallRules: unknown;
  firewallAliases: unknown;
  firewallIpsets: unknown;
  haResources: unknown;
}

export interface QualifiedQemuInput {
  config: unknown;
  evidence: QualifiedQemuEvidence;
  expected: ExpectedQualifiedQemuPlan;
}

export interface QualifiedQemuGraph {
  vmid: string;
  configDigest: string;
  bootVolume: string;
  template: boolean;
  ownershipTags: string[];
  ctime: string | null;
  smbiosUuid: string | null;
  vmgenid: string | null;
}

export class QualifiedQemuConfigError extends Error {
  constructor(message: string) {
    super(message);
  }
}

const VMID = /^[1-9][0-9]{2,8}$/;
const NATIVE = /^[A-Za-z0-9._:-]+$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CONFIG_KEYS = new Set([
  "bios",
  "boot",
  "cores",
  "cpu",
  "digest",
  "meta",
  "memory",
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
  throw new QualifiedQemuConfigError(message);
}

function record(value: unknown, message: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    deny(message);
  return value as Record<string, unknown>;
}

function string(value: unknown, message: string): string {
  if (typeof value !== "string" || value.length === 0) deny(message);
  return value;
}

function exactTags(value: unknown, expected: string[]): string[] {
  const tags = string(value, "QEMU ownership tags are invalid").split(";");
  const sortedExpected = [...expected].sort();
  if (
    tags.length !== expected.length ||
    tags.some((tag) => !NATIVE.test(tag)) ||
    new Set(tags).size !== tags.length ||
    [...tags].sort().some((tag, index) => tag !== sortedExpected[index])
  )
    deny("QEMU ownership tags do not match the saved plan");
  return sortedExpected;
}

function exactDisk(
  value: unknown,
  expected: ExpectedQualifiedQemuPlan,
): string {
  const disk = string(value, "QEMU boot disk is invalid");
  if (disk !== `${expected.storage}:${expected.volume},size=4M`)
    deny("QEMU boot disk does not match the saved plan");
  return `${expected.storage}:${expected.volume}`;
}

function validatePending(
  value: unknown,
  config: Record<string, unknown>,
): void {
  if (!Array.isArray(value) || value.length === 0)
    deny("QEMU pending evidence is incomplete");
  const seen = new Set<string>();
  for (const item of value) {
    const row = record(item, "QEMU pending evidence is incomplete");
    if (
      typeof row.key !== "string" ||
      !Object.hasOwn(row, "value") ||
      Object.hasOwn(row, "pending") ||
      Object.hasOwn(row, "delete") ||
      seen.has(row.key) ||
      !Object.hasOwn(config, row.key) ||
      row.value !== config[row.key]
    )
      deny("QEMU has pending configuration");
    seen.add(row.key);
  }
  if (
    seen.size !== Object.keys(config).length ||
    Object.keys(config).some((key) => !seen.has(key))
  )
    deny("QEMU pending evidence does not match current configuration");
}

function validateSnapshots(value: unknown): void {
  if (!Array.isArray(value) || value.length !== 1)
    deny("QEMU snapshots are not qualified");
  const snapshot = record(value[0], "QEMU snapshots are not qualified");
  if (
    snapshot.name !== "current" ||
    Object.keys(snapshot).some(
      (key) => !["name", "description", "digest", "running"].includes(key),
    )
  )
    deny("QEMU snapshots are not qualified");
}

function validateFirewall(
  options: unknown,
  rules: unknown,
  aliases: unknown,
  ipsets: unknown,
): void {
  const optionRecord = record(options, "QEMU firewall options are incomplete");
  if (
    Object.keys(optionRecord).length !== 1 ||
    typeof optionRecord.digest !== "string" ||
    optionRecord.digest.length === 0 ||
    !Array.isArray(rules) ||
    rules.length !== 0 ||
    !Array.isArray(aliases) ||
    aliases.length !== 0 ||
    !Array.isArray(ipsets) ||
    ipsets.length !== 0
  )
    deny("QEMU firewall state is not qualified");
}

function validateHa(value: unknown, vmid: string): void {
  if (!Array.isArray(value)) deny("QEMU HA evidence is incomplete");
  if (
    value.some((item) => {
      const row = record(item, "QEMU HA evidence is incomplete");
      return (
        row.sid === `vm:${vmid}` ||
        row.vmid === vmid ||
        row.vmid === Number(vmid)
      );
    })
  )
    deny("QEMU is managed by HA");
}

function generatedIdentity(
  config: Record<string, unknown>,
): Pick<QualifiedQemuGraph, "ctime" | "smbiosUuid" | "vmgenid"> {
  const smbios = config.smbios1;
  const vmgenid = config.vmgenid;
  const meta = config.meta;
  if (smbios === undefined && vmgenid === undefined && meta === undefined)
    return { ctime: null, smbiosUuid: null, vmgenid: null };
  const metaCtime =
    typeof meta === "string"
      ? /^creation-qemu=11\.0\.0,ctime=(\d+)$/.exec(meta)?.[1]
      : undefined;
  if (!metaCtime || typeof smbios !== "string" || typeof vmgenid !== "string")
    deny("QEMU generated identity is incomplete");
  const uuid = /^uuid=([0-9a-f-]{36})$/i.exec(smbios)?.[1];
  if (!uuid || !UUID.test(uuid) || !UUID.test(vmgenid))
    deny("QEMU generated identity is invalid");
  return {
    ctime: metaCtime,
    smbiosUuid: uuid.toLowerCase(),
    vmgenid: vmgenid.toLowerCase(),
  };
}

export function qualifyQemuConfig(
  input: QualifiedQemuInput,
): QualifiedQemuGraph {
  const config = record(input.config, "QEMU config is incomplete");
  const { expected, evidence } = input;
  if (
    !VMID.test(expected.vmid) ||
    evidence.vmid !== expected.vmid ||
    expected.storage !== "local-lvm" ||
    expected.volume !==
      `${expected.template ? "base" : "vm"}-${expected.vmid}-disk-0`
  )
    deny("QEMU plan is not the qualified native profile");
  if (Object.keys(config).some((key) => !CONFIG_KEYS.has(key)))
    deny("QEMU config has an unexpected field");
  if (
    config.bios !== "seabios" ||
    config.scsihw !== "virtio-scsi-single" ||
    config.boot !== "order=scsi0" ||
    config.serial0 !== "socket" ||
    config.memory !== "128" ||
    config.cores !== 1 ||
    config.cpu !== "kvm64" ||
    typeof config.digest !== "string" ||
    config.digest.length === 0
  )
    deny("QEMU config does not match the qualified native profile");
  if (config.template !== (expected.template ? 1 : undefined))
    deny("QEMU template marker does not match the saved plan");
  if (
    expected.name === null
      ? config.name !== undefined
      : config.name !== expected.name
  )
    deny("QEMU name does not match the qualified plan");
  if (
    config.meta !== undefined &&
    (typeof config.meta !== "string" ||
      !/^creation-qemu=11\.0\.0,ctime=\d+$/.test(config.meta))
  )
    deny("QEMU metadata is invalid");
  const bootVolume = exactDisk(config.scsi0, expected);
  const ownershipTags = exactTags(config.tags, expected.ownership.tags);
  if (
    !expected.ownership.installationId ||
    !expected.ownership.resourceId ||
    !expected.ownership.nonce ||
    expected.ownership.tags.some((tag) => !NATIVE.test(tag))
  )
    deny("QEMU ownership proof is invalid");
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
    bootVolume,
    template: expected.template,
    ownershipTags,
    ...generatedIdentity(config),
  };
}

export function canonicalQualifiedQemuConfig(
  graph: QualifiedQemuGraph,
): string {
  return createHash("sha256")
    .update(
      JSON.stringify({
        vmid: graph.vmid,
        configDigest: graph.configDigest,
        bootVolume: graph.bootVolume,
        template: graph.template,
        ownershipTags: graph.ownershipTags,
        ctime: graph.ctime,
        smbiosUuid: graph.smbiosUuid,
        vmgenid: graph.vmgenid,
      }),
    )
    .digest("hex");
}

export function canonicalQualifiedQemuIdentity(
  graph: QualifiedQemuGraph,
): string {
  return createHash("sha256")
    .update(
      JSON.stringify({
        vmid: graph.vmid,
        bootVolume: graph.bootVolume,
        template: graph.template,
        ctime: graph.ctime,
        smbiosUuid: graph.smbiosUuid,
        vmgenid: graph.vmgenid,
      }),
    )
    .digest("hex");
}
