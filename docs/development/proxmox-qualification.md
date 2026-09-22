# Proxmox lifecycle qualification

This administrator-only test exercises real image upload, disk import, template
conversion, full clone, ownership stamping, start, stop and VM deletion through
Kiln Core. General resource APIs continue to use fake lifecycle operations or
read-only Proxmox discovery.

The supported test profile is deliberately narrow: PVE 9.2.2, QEMU 11.0.0,
file-backed `local` import storage, `local-lvm` LVM-thin target storage, a signed
4 MiB BIOS disk, and no NIC. This is not a deployment installer or a Development
Lease. See the [architecture](../architecture/proxmox-lifecycle-qualification.md)
and [probe image build](stage2-probe-image.md).

## Local tests

`npm test` runs provider HTTP fixtures without Proxmox. PostgreSQL tests run when
`KILN_TEST_DATABASE_URL` names a disposable development database whose role can
create databases. Each qualification integration test creates and removes its own
UUID-named database. For the full suite, two workers avoid contention between
short-timeout database tests:

```sh
KILN_TEST_DATABASE_URL=postgresql://user@localhost/kiln_test npm test -- --maxWorkers=2
npm run build
```

The tests cover exact provider requests, changed ownership and attachments,
transactional audit failures, duplicate advances, lost and saved receipts,
restart recovery, deadline expiry and retained allocation records.

## Explicit live configuration

Use a dedicated test Proxmox environment. Configure verified HTTPS and a
short-lived token with the audit and exact-object permissions described in the
architecture document. Never supply production credentials to a nested lab.
Select two unused VMIDs. An existing `kiln` pool is rejected; it is not adopted.

Start the API with PostgreSQL, `KILN_PROVIDER=proxmox-read-only`, the usual
`KILN_PROXMOX_URL` and `KILN_PROXMOX_TOKEN`, and three distinct credentials:
`KILN_API_TOKEN`, `KILN_INFRASTRUCTURE_TOKEN`, and `KILN_QUALIFICATION_TOKEN`.
`KILN_IMAGE_TRUSTED_KEYS_FILE` must identify a signer policy permitting the probe
image. Keep all credential and configuration files outside the repository.

`KILN_PROXMOX_QUALIFICATION_FILE` points to a private JSON file with these fields:

```json
{
  "enabled": true,
  "tokenIdentity": "qualification@pve!test",
  "node": "test-pve",
  "pool": "kiln",
  "stageStorage": "local",
  "targetStorage": "local-lvm",
  "pveVersion": "9.2.2",
  "storageConfigDigest": "<40-character digest from GET /storage>",
  "templateVmid": "9100",
  "probeVmid": "9101"
}
```

The configured node, VMIDs, token and storage digest must still match the saved
plan after restart. A changed configuration does not authorize continuing an old
run under a new scope.

## Operator API

Every qualification request requires the infrastructure bearer credential and
`X-Kiln-Qualification-Token`. Routine agent credentials cannot invoke these routes.

1. `POST /v1/qualifications` with an `Idempotency-Key` and signed image body
   `{manifest, signature, artifactBase64}` saves the run, resources and allocation
   intents atomically. Repeating the same request returns the existing run.
2. `POST /v1/qualifications/{id}/advance` dispatches one phase or reconciles its
   saved receipt. Use `GET /v1/qualifications/{id}` to inspect progress and the
   fixed reconciliation deadline. An advance response is not proof of guest
   execution.
3. After START completes, independently observe the serial marker
   `KILN-PROBE-READY` from the managed probe. Continue through stop and both VM
   deletions, then verify terminal status and external configuration baselines.

A receiptless intent becomes UNKNOWN after restart. Task errors, mismatched
observations and expired deadlines also stop the run. Kiln will not retry the
mutation or clean up uncertain resources automatically. Investigate the saved
records and provider tasks; do not delete journal rows to force a retry.

A successful run intentionally retains its signed staging image and empty pool.
Their managed allocation records remain in PostgreSQL. Both test VMs and their
attached disks must be absent. Back up the database before retiring the test
control plane, and revoke the temporary provider credential only after all
recorded tasks are resolved. There is no standalone disk, staging-file or pool
delete API in this qualification.
