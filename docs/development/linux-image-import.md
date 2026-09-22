# Linux image import operator setup

Linux image import is off until all of these settings are present:

```text
KILN_PROVIDER=proxmox-read-only
KILN_PROXMOX_URL=https://pve.example:8006
KILN_PROXMOX_TOKEN=PVEAPIToken=user@realm!linux-import=secret
KILN_PROXMOX_LINUX_IMPORT_FILE=/run/kiln/linux-import.json
KILN_LINUX_IMAGE_STAGING_DIR=/var/lib/kiln/linux-staging
KILN_LINUX_IMPORT_TOKEN=<separate operator credential>
```

The control plane also needs PostgreSQL, `KILN_INFRASTRUCTURE_TOKEN`, and a trusted-image-key file. The Linux import credential must differ from the API, infrastructure and BIOS qualification credentials.

Grant the Proxmox token only the paths needed for this profile. File-backed staging needs `Datastore.AllocateTemplate`; import-source checks need `Datastore.Audit`; target allocation needs `Datastore.AllocateSpace`. The planned VM IDs or the owned `kiln` pool need `VM.Allocate`, `VM.Config.Disk`, `VM.Config.CPU`, `VM.Config.Memory`, `VM.Config.Options`, `VM.Config.HWType`, `VM.Clone` on the template and `VM.PowerMgmt`. `VM.Allocate` also permits deletion, so restrict it to the exact planned IDs or owned pool. Do not grant Network, Cloud-init, SDN, `Sys.Modify` or `Datastore.Allocate`. The pinned Proxmox evidence and source links are in [proxmox-evidence.md](../architecture/proxmox-evidence.md).

The profile file is a private regular JSON file. Its `tokenIdentity` must match the Proxmox API token. Its pool fields must name the completed BIOS qualification run and retained pool allocation recorded by Kiln. Do not copy a pool name from Proxmox into this file without the matching run, allocation, nonce and comment.

```json
{
  "enabled": true,
  "node": "pve-01",
  "pool": "kiln",
  "stageStorage": "local",
  "targetStorage": "local-lvm",
  "pveVersion": "9.2.2",
  "tokenIdentity": "user@realm!linux-import",
  "storageConfigDigest": "40 lowercase hex characters",
  "templateVmid": "301",
  "cloneVmid": "302",
  "templateName": "kiln-linux-template",
  "cloneName": "kiln-linux-probe",
  "sourcePoolRunId": "qual_<32 lowercase hex characters>",
  "sourcePoolAllocationId": "alloc_pool_qual_<32 lowercase hex characters>",
  "sourcePoolNonce": "saved pool nonce",
  "sourcePoolComment": "saved pool comment"
}
```

The staging directory must be an absolute private appliance path. Kiln accepts only an opaque staging ID through the API. It never accepts an operator-supplied server path. It reserves bytes before reading the upload, keeps interrupted uploads for inspection and refuses a staged file once a run claims it.

Upload bytes with `POST /v1/linux-import-staging`, `Content-Type: application/octet-stream`, `Content-Length`, `Idempotency-Key` and `X-Kiln-Artifact-SHA256`. Kiln records the authenticated subject, a hash of the idempotency key, declared size and digest before it accepts upload bytes. It records the opaque stage ID after publication. The staging service accepts at most 4 GiB across eight artifacts and stops a stalled upload after 20 minutes. A completed or interrupted stage remains retained. A failed unpublished stream releases its reservation.

Then send the opaque staging ID, signed manifest, signature and base64 build metadata as JSON to `POST /v1/linux-imports`, with the same infrastructure bearer token, `X-Kiln-Linux-Import-Token` and an idempotency key. Use `POST /v1/linux-imports/<id>/advance` to advance one recorded phase and `GET /v1/linux-imports/<id>` to inspect its safe status. The status response includes phase names, timestamps and safe reasons. It never includes receipts, credentials or local paths. The normal project API, MCP and CLI credentials cannot use these endpoints. If a phase has no saved receipt after a restart, Kiln marks it `UNKNOWN` and does not retry it. A transient task observation stays submitted until its reconciliation deadline. Upload has 25 minutes. Every other phase has 15 minutes.
