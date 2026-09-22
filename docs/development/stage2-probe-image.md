# Stage 2 probe image

The first real Proxmox qualification uses a disposable BIOS probe instead of a
general development image. It has one raw SCSI disk, no NIC, no cloud-init,
no EFI or TPM state, no firewall rules, and no guest credentials.

Build it with:

```bash
images/probe/build-bios-probe.sh /tmp/kiln-stage2-probe
```

The builder produces a 4 MiB raw image and a QCOW2 file. Only the QCOW2 is a
candidate upload artifact. The builder checks that it is at most 128 KiB, that
`qemu-img check` accepts it, that a raw round trip preserves the boot sector,
and that the sector ends with the BIOS `55aa` signature.

The boot sector writes `KILN-PROBE-READY` to COM1 about once a second and
sleeps on BIOS timer interrupts between writes. A VM start task does not prove
that serial marker without an available QEMU serial console. Record that
limitation in the qualification evidence if the host running the builder lacks
`qemu-system-x86_64`.

Do not commit generated artifacts. Before upload, compute the QCOW2 SHA-256,
create the signed manifest, allocate a fresh staging filename, and record its
exact target storage and expected volume ID in the operation journal.
