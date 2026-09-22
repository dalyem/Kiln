# Stage 2 live lifecycle qualification

Completed on 2026-09-21. Run `qual_350a9cad94f444c4bef10f8ab2dfb4ef` passed the ten-phase lifecycle through the actual Kiln REST API, Core, PostgreSQL journal and Proxmox adapter.

## What ran

The target was the existing isolated nested PVE 9.2.2 host on physical cluster node Zeus. Its QEMU version was 11.0.0. This was a single nested-node test using file-backed `local` import storage and `local-lvm` LVM-thin disks.

Kiln created template VM 9100 and probe VM 9101. The signed BIOS image had a 4 MiB virtual disk and a 7,168-byte QCOW2 artifact, SHA-256 `8a4a3dbb7e4114b09265b43eb80ed7e6bd563b29c3f918c33302da089a6901b4`. The probe had no NIC, cloud-init, EFI or TPM device. Kiln injected no guest credentials.

| Phase | Completed, UTC | Result |
| --- | --- | --- |
| POOL_CREATE | 02:24:47 | COMPLETED |
| UPLOAD | 02:25:06 | COMPLETED |
| IMPORT | 02:25:31 | COMPLETED |
| TEMPLATE | 02:25:50 | COMPLETED |
| CLONE | 02:25:57 | COMPLETED |
| STAMP | 02:26:07 | COMPLETED |
| START | 02:26:24 | COMPLETED |
| STOP | 02:27:00 | COMPLETED |
| DESTROY_PROBE | 02:27:08 | COMPLETED |
| DESTROY_TEMPLATE | 02:27:15 | COMPLETED |

Eight `KILN-PROBE-READY` serial messages were captured through the existing host serial socket. This proves guest code execution in addition to successful power-task completion.

## Recovery and safeguards

The API replay and authorization results below are operator observations from this session. Saved database and provider evidence supports the lifecycle, recovery and cleanup results.

- The API was stopped with UPLOAD in SUBMITTED state and restarted against the same database. Kiln polled the identical saved task ID, completed the phase, and retained exactly one upload submission event.
- Repeating the create request returned the same run with `replayed=true`. Advancing the completed run returned COMPLETED.
- A separate installation database targeted existing external VMs 101 and 102. The native absence check rejected the operation before pool creation, and the run became UNKNOWN. It was not retried or adopted.
- A routine credential with the qualification header and an infrastructure credential without the qualification header both received HTTP 403.
- Automated tests rejected deletion after ownership tags, disks, NICs, pending configuration, snapshots, HA membership or audit visibility changed. Other tests covered receipt tampering, changed clone identity and a remaining disk after deletion.
- PostgreSQL tests exercised missing ownership proof, concurrent dispatch/completion, failed audit writes, lost receipts, saved receipts, deadline expiry and actual startup recovery ordering.

Two integration defects were found before provisioning: the built QCOW2 image used a 112-byte header rather than the 104-byte test fixture, and generic startup recovery incorrectly marked qualification records ERROR. Both were fixed and reviewed. Those zero-dispatch attempt databases were preserved; no ownership records were reset to force a retry.

## Final infrastructure state

Both qualification VMs and their attached disks are absent. Both Kiln resource records are DESTROYED and the run is COMPLETED. Existing inner VMs 100, 101 and 102 remain running. All 25 saved configuration hashes matched: 17 across the three physical hosts and eight on the nested host. The nested HA inventory remained empty.

The empty `kiln` pool and uploaded signed image are intentionally retained. Their allocation records are RETAINED, and a final read-only SHA-256 check matched the saved artifact digest. This milestone has no standalone disk, uploaded-file or pool deletion path.

The completed database was exported and restored into a fresh local database. The restore check verified the completed run, ten completed phases and two retained allocation records. Dumps and detailed phase, serial, baseline, final artifact-digest, HA and stopped-service evidence are kept in the operator's private local state directory. This was an evidence backup, not an implementation of `kiln backup`.

The temporary Proxmox token was revoked and verified to return HTTP 401. Its backing user, ACL entries and five task-specific roles were removed. Temporary API instances, the HTTPS tunnel and local PostgreSQL server were stopped. The qualification used Proxmox APIs and the host’s existing serial-socket tooling.

## Verification and limits

The final suite passed **228 tests in 23 files**, including PostgreSQL tests, with `--maxWorkers=2`. The full npm build passed. An earlier unrestricted parallel run timed out in an existing five-second PostgreSQL test; limiting database concurrency passed without extending its timeout. Independent review found no remaining material issues after the fixes.

This qualifies the narrow lifecycle above. It does not qualify a Linux development image, `kilnd` workload enrollment, workspace transfer, preview routing, lease expiry against live VMs, workload networking, Ceph, cross-node migration, HA, appliance installation or general live provisioning. The normal Proxmox observer remains read-only. The next development milestone must add those capabilities incrementally.

See [the design](../architecture/proxmox-lifecycle-qualification.md) and [operator/contributor instructions](proxmox-qualification.md).
