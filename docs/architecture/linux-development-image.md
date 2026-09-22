# Linux development image

## Scope and completion criteria

Build the first `kiln-dev-base` amd64 QCOW2 artifact and qualify an actual Linux
boot. A successful boot must run the shipped `kilnd` workspace materializer,
check the resulting Git state, and emit a readiness record only after the
checks pass. Verify the finished artifact through an operator-configured
Ed25519 signer policy and a bounded file reader.

This is image qualification. It does not enable the existing Proxmox BIOS
qualifier to accept Linux images. That qualifier pins a 4 MiB disk and 128 MiB
VM and cannot safely import this image by increasing its upload limit. Live
Linux import needs a separate journaled profile and attachment parser. Workload
networking, enrollment, language-specific profiles and previews remain later work.

## Decision

Building Linux from a minimal filesystem would give Kiln control over every
package, at the cost of owning bootloader, kernel and cloud-image maintenance.
Customizing an established cloud image reuses those tested components, but
requires a pinned upstream digest and a record of the packages added. Merely
redistributing the upstream image would not qualify Kiln's daemon or workspace
support.

Use Debian 13 genericcloud, customized inside libguestfs on a contributor build
machine. No build dependencies run on a Proxmox host. The initial guest has Git,
Python 3, CA certificates, curl, build tools and a static amd64 `kilnd`. It does
not start the daemon's health server or expose an administrative listener.

The base is the dated Debian build `20260831-2587`. Its SHA-512 is pinned before
parsing or customization. The official dated directory supplies checksums over
HTTPS but no detached checksum signature. This is HTTPS-based upstream trust;
the resulting Kiln artifact receives its own Ed25519 signature. Do not describe
the base checksum as a verified Debian signature.

## Artifact and trust boundary

The supported output is a standalone QCOW2 v3 image with an 8 GiB virtual disk,
64 KiB clusters, 16-bit refcounts and no backing file, internal snapshots,
encryption or external data file. `qemu-img check` and an actual guest boot
complement header checks. There is one boot disk and no runtime seed disk in
this qualification. A future Proxmox profile must account for every attachment
before importing the image.

Build metadata records the base digest, recipe identity, shipped daemon digest
and exact package versions. The signed manifest's `sourceBuild` is the SHA-256
of the exact metadata file, so metadata cannot be swapped independently of the
artifact signature. Package repositories and image filesystem metadata
can change between builds; this is a traceable build, not a claim of identical
output bytes. Private signing keys remain outside the guest and repository.

The large-file verifier uses the existing canonical manifest and signer policy,
with a separate 2 GiB bound. It reads regular files without following a final
symlink, checks size and digest, and rejects observed file changes. It does not
accept a URL or put image bytes into PostgreSQL. Existing small inline API
limits remain unchanged. Verification proves artifact identity, not permission
to import it or ownership of any VM.

## Guest lifecycle and qualification

Remove machine identity, instance cache, SSH host keys, authorized keys and build
secrets before publishing. Lock password accounts and disable SSH. The initial
profile boots without a NIC or credentials. Qualify with a disposable overlay
so boot-generated machine state never changes the golden artifact.

The build and qualification commands refuse existing outputs, bound runtime,
and clean up only their own staging files and processes. Failures leave no
apparently qualified output. A self-check failure must not emit readiness.
Record final artifact hashes, tool versions, native disk checks and the guest
result. A local QEMU result does not qualify the PVE configuration parser,
storage import semantics, sandbox connectivity or enrollment.

## Subsequent integration

The next Proxmox import path must bind this verified artifact to durable staging
and VM allocation records, stream its bytes with an exact checksum, parse a
separate strict Linux configuration, and validate every effect before accepting
completion. Restore the existing lab installation database before reusing its
retained pool or staging allocation. Existing names and tags cannot substitute
for those records. General live provisioning remains disabled until that path
passes tests and nested-lab qualification.

Sources: [dated Debian image directory](https://cloud.debian.org/images/cloud/trixie/20260831-2587/),
[checksums](https://cloud.debian.org/images/cloud/trixie/20260831-2587/SHA512SUMS).
