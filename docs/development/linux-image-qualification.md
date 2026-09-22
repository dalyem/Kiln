# Linux development image qualification

This increment builds and signs a Debian 13 development base, verifies a large
local artifact without loading it into memory, and boots Linux to exercise the
shipped `kilnd` workspace materializer. It does not create a Development Lease.
See the [design](../architecture/linux-development-image.md) and
[contributor commands](../../images/dev/README.md).

## Environment and evidence

Qualification was performed on 2026-09-21 using contributor-host QEMU 8.2.2,
libguestfs 1.52.0, Node 22.23.2 and Go 1.22.2. PostgreSQL tests use an isolated
PostgreSQL 16.15 instance. Build tools were installed on the contributor machine,
not a Proxmox host. Private artifacts and logs are under
`/home/daly/.local/state/kiln/dev-image-qhxs_5nr`.

The pinned Debian source was verified against the official dated HTTPS checksum.
No detached Debian signature was available. Kiln's output uses an explicitly
trusted local Ed25519 qualification key; it is not a published release key.
The signed manifest binds both the disk digest and the raw build-metadata digest.
Metadata includes the recipe, base, daemon and installed package identities.

## Checks

The native QCOW2 integrity check and strict 8 GiB disk-profile checks passed.
Qualification boots a private copy through a disposable overlay, with two vCPUs,
2 GiB RAM and no NIC. The golden disk is never booted directly.

The guest self-check exercises the shipped static Linux daemon. It reconstructs
a fixture containing committed files, separate staged and unstaged edits,
untracked binary data and an executable file. HEAD, status, both diffs, bytes and
file modes must match before `KILN_DEV_BASE_READY` appears on the serial console.
The check also requires fresh machine identity, locked passwords, absent SSH
keys and Kiln credentials, and disabled SSH activation.

The first boot exposed a systemd-generated local SSH socket despite masking the
normal SSH units. That artifact is superseded: a passing workspace check alone
was insufficient to accept the intended disabled-SSH profile.

The rebuilt artifact passed. Its serial log contains the readiness marker and
no SSH listener or SSH-generator failure. Both the source and private boot-copy
digests match after shutdown:

| Evidence | Value |
| --- | --- |
| Final image | `build-final/kiln-dev-base.qcow2` |
| Artifact SHA-256 | `db9d5ed652fffb94d002e605433b61b17cffb0b8c45dcc9c21e2ce357ea02cd1` |
| Recipe SHA-256 | `5d51fce1f905db746258f5a65e2b01dba29d95e1448daf9a6503aaa193901eb2` |
| Signed bundle | `signed-final/` |
| Boot evidence | `boot-final/serial.log`, `boot-final/artifact.sha256` |

Core's streaming verifier and an independent OpenSSL signature check passed.
The metadata digest, recipe digest and shipped-daemon digest matched their
actual files. All 236 TypeScript/PostgreSQL tests passed across 25 files, as did
the repository typecheck, standalone typecheck for the signing tools and shell
syntax checks. Independent review found no remaining material issue.

The malformed-disk smoke test failed without publishing qualification evidence
or leaving its private boot copy. Reusing an evidence directory was refused.
Actual signing-tool checks rejected altered metadata, unknown signers, invalid
signatures, oversized and FIFO manifest inputs, and existing output directories.
A fresh signing run produced an identical bundle. These checks caught a helper
comparing ctime to mtime; it now compares like fields, with a regression test
using deliberately different timestamps.
An initial missing-serial-file diagnostic is harmless: QEMU creates the file and
the qualifier waits for its exact readiness line. The guest reports missing
nested SVM CPU support on this host; it needs no further nested virtualization.

## Remaining limits

This is local Linux boot qualification. No Proxmox resource was mutated during
this increment. The nested lab was inspected read-only; its operator-created
router and probe fixtures remain EXTERNAL.

The existing Proxmox qualifier accepts only its small BIOS probe. Its API,
attachment parser and mutation paths were not widened. A separate Linux import
journal/profile and bounded staging transport are still required before testing
this disk on the nested Proxmox host. Retained allocations require the existing
installation database; matching names or tags never authorize adoption.

Networking, workload enrollment, code upload, language-specific runtimes,
application startup, preview routing and real lease expiry remain unimplemented.
The QCOW2 header verifier is not a complete parser for arbitrary disk contents;
native integrity checks and actual boot complement it. Tests do not prove power
loss durability, malicious-root resistance, PVE compatibility or byte-for-byte
reproducible builds.
