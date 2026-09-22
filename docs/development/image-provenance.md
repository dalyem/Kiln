# Exercise image provenance with fake compute

This path verifies image signatures and ownership behavior without a Proxmox cluster. It does not create a VM or install a real operating-system image. The import API accepts at most 128 KiB of decoded fixture data. Large image distribution and real provider import are Stage 2 work.

Install dependencies and configure PostgreSQL and independent API/infrastructure tokens as described in [CONTRIBUTING.md](../../CONTRIBUTING.md). Run these commands from the repository root.

Generate an ephemeral signing key, a public trust policy and a signed fixture request. The private key stays in this process and is not written to disk:

```sh
export KILN_IMAGE_DEMO_DIR="$(mktemp -d)"
node --import tsx --input-type=module <<'JS'
import { generateKeyPairSync, createHash, sign } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { canonicalImageManifest } from '@kiln/core';
const directory = process.env.KILN_IMAGE_DEMO_DIR;
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const artifact = Buffer.from('Kiln fake development image');
const manifest = {
  schemaVersion: 1, name: 'kiln-dev-demo', version: '0.0.1', arch: 'amd64',
  artifactSha256: createHash('sha256').update(artifact).digest('hex'),
  artifactSize: artifact.length, sourceBuild: 'local-demo',
  capabilities: ['development'], keyId: 'demo',
};
const policy = { demo: {
  publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
  allowedNames: ['kiln-dev-demo'], allowedCapabilities: ['development'],
  allowedArchitectures: ['amd64'],
} };
const request = {
  manifest,
  signature: sign(null, Buffer.from(canonicalImageManifest(manifest)), privateKey).toString('base64'),
  artifactBase64: artifact.toString('base64'),
};
await writeFile(`${directory}/trust.json`, JSON.stringify(policy), { mode: 0o600 });
await writeFile(`${directory}/import.json`, JSON.stringify(request), { mode: 0o600 });
JS
export KILN_PROVIDER=fake
export KILN_IMAGE_TRUSTED_KEYS_FILE="$KILN_IMAGE_DEMO_DIR/trust.json"
npm run dev
```

The API reads trust policy at startup. Import requests cannot supply a trusted public key. In a second shell with the same token and demo-directory environment, import the fixture:

```sh
curl --fail-with-body http://127.0.0.1:4000/v1/images/import \
  -H "Authorization: Bearer $KILN_INFRASTRUCTURE_TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: demo-image-import' \
  --data-binary "@$KILN_IMAGE_DEMO_DIR/import.json"
```

The response includes `templateId`, `imageManifestDigest` and the import state. A synchronous fake import should become `READY`. Repeating the same request and key returns the original template; changing its payload is a conflict. A new artifact requires a new image version.

Create a resource through `POST /v1/resources` using the routine API token, a new `Idempotency-Key`, and this body, replacing the template ID with the returned value:

```json
{
  "type": "development",
  "ttlSeconds": 600,
  "templateId": "tmpl_REPLACE_WITH_RETURNED_ID"
}
```

Read `GET /v1/resources/{id}/provenance` to inspect the sanitized lineage and attachment classes. The ordinary stop, delete and lease endpoints use the same ownership guards for this resource. `POST /v1/templates/{templateId}/retire` requires the infrastructure token and refuses retirement while a live resource or unresolved operation depends on the template. Retirement removes eligibility; it does not delete provider disks.

Fake provider objects are process-local. PostgreSQL preserves provenance and operation history across API restart, but it does not reconstruct simulated disks. Missing provider observations deny lifecycle operations. The automated restart tests retain a controlled fake provider when testing recovery of submitted tasks.

The trust file is contributor configuration, not a production signing-key management service. The manifest proves which approved publisher signed the fixture and which bytes were checked. It does not prove continuous disk integrity, physical network isolation or real template installation.
