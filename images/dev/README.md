# Linux development image

`build.sh` produces a local unsigned `kiln-dev-base` image. It accepts no URL
and never downloads a base image. The dated Debian 13 base must be present
locally and its SHA-512 must match before QEMU or libguestfs reads it.

Use a Linux builder with KVM access, QEMU, libguestfs tools, Git, Python 3,
Go and Node 22+. For example, Ubuntu packages `qemu-system-x86`, `qemu-utils`
and `guestfs-tools` provide the virtualization tools. The build needs root
because it uses libguestfs direct mode. Ubuntu 24.04
builders also need `isc-dhcp-client` so the libguestfs appliance can use its
temporary build network. It creates an absent mode-0700 output directory and
refuses to replace it. It expands the
Debian root filesystem from 3 GiB to 8 GiB, installs Git, Python 3, CA
certificates, curl, and build-essential through the temporary libguestfs build
network, then injects the supplied static `kilnd` binary. It records exact
installed package versions, base digest, daemon digest and recipe identity in
`kiln-dev-base.metadata.json`. The result is traceable, not byte reproducible.

Build `kiln` for the host and a static Linux `kilnd` outside the repository.

```sh
go build -o /private/kiln ./cmd/kiln
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /private/kilnd ./cmd/kilnd
```

Download only the dated Debian image. Check its SHA-512 before passing it to
the builder. Do not substitute a `latest` URL.

```sh
curl --fail --location --output /private/debian-13-genericcloud-amd64.qcow2 \
  https://cloud.debian.org/images/cloud/trixie/20260831-2587/debian-13-genericcloud-amd64-20260831-2587.qcow2
sha512sum /private/debian-13-genericcloud-amd64.qcow2
```

```sh
kiln_sha256=$(sha256sum /private/kiln | awk '{print $1}')
kilnd_sha256=$(sha256sum /private/kilnd | awk '{print $1}')
sudo -n env LIBGUESTFS_BACKEND=direct images/dev/build.sh \
  --base /private/debian-13-genericcloud-amd64.qcow2 \
  --base-sha512 8ea9faae810043a0b35b0149f05014f26705c2339ffb11ead308f33e844a87cc3ef46ec81d5262b38817b6a88af404874d48a5857ebe072ef6a31dfb6e371f50 \
  --kiln /private/kiln --kiln-sha256 "$kiln_sha256" \
  --kilnd /private/kilnd --kilnd-sha256 "$kilnd_sha256" \
  --output-dir /private/kiln-dev-base-build
```

The image has no runtime seed, enrollment data, SSH host key, authorized key,
enabled password account, or Kiln machine credential. It disables cloud-init, locks
all password fields, disables SSH service and generated local SSH sockets, and
does not start the `kilnd` listener. The no-NIC rule belongs to the local
qualification VM configuration, not to the disk image. The one-shot
`kiln-image-selfcheck` unit creates a temporary private directory, runs `kilnd
workspace materialize` on a built-in nonsecret snapshot, compares Git HEAD,
status, staged and unstaged diffs, file bytes, and modes, removes its output,
then prints `KILN_DEV_BASE_READY` to `ttyS0`.

Sign the image with an explicit private key. The tool never generates or prints
a key. It hashes the complete build metadata into the signed `sourceBuild`
field and rejects metadata whose artifact digest does not match the image.

```sh
npx tsx images/dev/sign.ts --artifact /private/kiln-dev-base-build/kiln-dev-base.qcow2 \
  --metadata /private/kiln-dev-base-build/kiln-dev-base.metadata.json \
  --version 2026.09.21 --key-id operator-dev \
  --private-key /private/signer.pem --output-dir /private/kiln-dev-base-signature
```

Verify with an operator-maintained JSON trust file that maps key IDs to the
same `TrustedImageKeys` policy used by Core.

```sh
npx tsx images/dev/verify.ts --artifact /private/kiln-dev-base-build/kiln-dev-base.qcow2 \
  --metadata /private/kiln-dev-base-signature/build-metadata.json \
  --manifest /private/kiln-dev-base-signature/manifest.json \
  --signature /private/kiln-dev-base-signature/manifest.sig --trust /private/trusted-image-keys.json
```

Run the local no-NIC boot check with a disposable overlay. It keeps the golden
artifact unchanged and waits at most 180 seconds for the exact serial marker.

```sh
sudo -n images/dev/qualify-local.sh /private/kiln-dev-base-build/kiln-dev-base.qcow2 \
  --evidence-dir /private/kiln-dev-base-boot-evidence
```

The dated Debian source is HTTPS-pinned by its SHA-512. It has no upstream
detached checksum signature. The Kiln Ed25519 signature covers the finished
artifact. This check does not qualify Proxmox import or a networked workload.
