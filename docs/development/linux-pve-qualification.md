# Linux PVE qualification

KILN-26 attempted the live nested-PVE Linux import on 2026-09-22. The attempt
did not qualify import, boot, restart recovery, or cleanup. It stopped before
Proxmox received a write.

## Checked before the attempt

The build worktree was `e82602c`. Nested PVE reported 9.2.2 and QEMU 11.0.0 on
`kiln-lab-pve-01`. `local` is file-backed import storage and `local-lvm` is the
LVM-thin target. Both returned the same storage digest,
`645facdb5319ae2893de12926e9231160a3f8b02`. TLS was verified against the nested
host CA. The certificate allows `127.0.0.1`, which is how the API reached the
forwarded API port.

The completed Stage 2 database was restored into disposable PostgreSQL 16 and
migrated by API startup. All 23 historical table checksums matched the KILN-25
record. The retained pool allocation, nonce, and comment matched that record,
and all ten BIOS phases were `COMPLETED`. VMIDs 9100 and 9101 are absent on
PVE, but their disk identities remain owned in that database, so this attempt
used absent VMIDs 9102 and 9103.

The PostgreSQL Linux import tests passed (37 tests), then the full suite passed
(286 tests in 30 files, `--maxWorkers=2`). `npm run build` passed. Routine,
infrastructure-only, and wrong Linux-import credentials each received HTTP 403.
All 25 Stage 2 configuration hashes matched before the attempt.

## Where it stopped

Staging the signed 1,686,634,496-byte image succeeded. The stage ID was
`lstg_1588eaa0087e83d3e5e54318ef7702a0` and the digest was
`db9d5ed652fffb94d002e605433b61b17cffb0b8c45dcc9c21e2ce357ea02cd1`. Creating the
run returned HTTP 201 for `limp_01903ec044344190b95ac944045e631a`. Repeating
that request returned HTTP 200 with the same ID and `replayed=true`.

`UPLOAD` returned `SAFETY_DENIED` with `Proxmox Linux import evidence is
incomplete`. The phase is `UNKNOWN`, reason `DISPATCH_UNKNOWN`, and it has no
receipt. The node task list has no `imgcopy` from this attempt. The import
directory still contains only the retained BIOS image.

`GET /nodes/kiln-lab-pve-01/qemu` returns the three running guests with a VMID
and no `type` field. `vmInventory` in
`packages/proxmox/src/linux-import.ts` requires `type` to be `qemu`, so the
node list fails that check. `GET /cluster/resources?type=vm` does include
`type: qemu`; version 9.2.2 and the audit permissions were present. The HTTP
fixtures in `tests/proxmox-linux-import.test.ts` put `type: qemu` on the node
list, so the suite does not catch this live shape.

No product code was changed. The journal rows were not edited.

## Terminal state

The unknown run still reserves VMIDs 9102 and 9103 and its staging ID. A later
attempt has to restore the Stage 2 database again rather than continue this
one. No new VM, disk, or upload was created. The temporary token was removed
and then rejected with HTTP 401; its user, ACLs, and six roles are gone. The
25 configuration hashes still matched after removal. Private logs and the
database dump are under
`/home/daly/.local/state/kiln/kiln26-b93eb839`.

Guest boot, saved-receipt recovery, cleanup, and `KILN_DEV_BASE_READY` were
not reached.

## Second attempt

The node QEMU parser now accepts a missing `type` only for
`GET /nodes/{node}/qemu`. A present type must still be `qemu`, and the mixed
cluster list still requires an explicit `qemu` or `lxc` type. The provider
suite includes the live typeless rows for guests 100, 101 and 102, and it
rejects a non-QEMU type, a null type, an invalid VMID, a malformed node row,
and a cluster list that omits `type`. With a disposable database, `npm test --
--maxWorkers=2` passed 291 tests in 30 files, and `npm run build` passed.

The Stage 2 dump was restored into a new database. All 23 historical table
checksums matched before and after API migration. VMIDs 9102 and 9103 were
absent on the nested host and unreserved in that database. All 25 external
configuration hashes matched the first attempt. The first unknown database and
its staging directory were left in place.

Staging and run creation succeeded for `limp_f69cb1921c904cf8a00eacc5ca734111`.
The reused staging idempotency key produced the same staging ID as the first
attempt, `lstg_1588eaa0087e83d3e5e54318ef7702a0`, and this time the `imgcopy`
task finished with exit OK. The saved receipt stayed `SUBMITTED`. Stopping and
starting the API did not submit a second task. Startup operation recovery set
both Linux import resources to `ERROR` (`resource.provisioning_recovered`,
`MISSING_CREATE_OPERATION`) because they were `PROVISIONING` without a generic
create operation. Linux import recovery then rejected that proof and marked
`UPLOAD` `UNKNOWN` with `RECOVERY_SAFETY_PROOF_FAILED`. The journal was not
edited.

The uploaded file remains at
`local:import/lstg_1588eaa0087e83d3e5e54318ef7702a0.qcow2` (1,686,634,496
bytes), beside the retained BIOS image. No VM or target disk was created.
Disk identities for 9102 and 9103 stay reserved by this unknown run. All 25
hashes still matched afterward. The temporary token was removed and then
rejected with HTTP 401. Private logs and the database dump are under
`/home/daly/.local/state/kiln/kiln26-retry-44ceb4`.

Guest boot, cleanup, and `KILN_DEV_BASE_READY` were not reached. A later
attempt has to restore Stage 2 again. It cannot continue this journal, and it
has to account for the uploaded file that now uses the first attempt's staging
ID.
