export interface LinuxBuildMetadata {
  schemaVersion: 1;
  name: "kiln-dev-base";
  arch: "amd64";
  profile: "debian13-nic-free-development-v1";
  recipe: "images/dev/build.sh";
  recipeSha256: string;
  baseSha512: string;
  kilndSha256: string;
  artifactSha256: string;
  packages: string[];
  reproducible: false;
}
const fields = ["schemaVersion", "name", "arch", "profile", "recipe", "recipeSha256", "baseSha512", "kilndSha256", "artifactSha256", "packages", "reproducible"];
export function parseLinuxBuildMetadata(bytes: Buffer): LinuxBuildMetadata {
  let value: unknown; try { value = JSON.parse(bytes.toString("utf8")); } catch { throw new Error("Linux build metadata is invalid"); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Linux build metadata is invalid");
  const metadata = value as Partial<LinuxBuildMetadata>;
  if (Object.keys(metadata).length !== fields.length || fields.some((field) => !(field in metadata)) || metadata.schemaVersion !== 1 || metadata.name !== "kiln-dev-base" || metadata.arch !== "amd64" || metadata.profile !== "debian13-nic-free-development-v1" || metadata.recipe !== "images/dev/build.sh" || metadata.reproducible !== false || !/^[a-f0-9]{64}$/.test(metadata.recipeSha256 ?? "") || !/^[a-f0-9]{128}$/.test(metadata.baseSha512 ?? "") || !/^[a-f0-9]{64}$/.test(metadata.kilndSha256 ?? "") || !/^[a-f0-9]{64}$/.test(metadata.artifactSha256 ?? "") || !Array.isArray(metadata.packages) || !metadata.packages.length || metadata.packages.some((entry) => typeof entry !== "string" || !/^[^\t\n]+\t[^\t\n]+$/.test(entry))) throw new Error("Linux build metadata is invalid");
  return metadata as LinuxBuildMetadata;
}
