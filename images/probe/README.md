# Stage 2 BIOS probe

This directory builds a tiny, source-controlled QCOW2 used only to qualify the
first guarded Proxmox lifecycle path. It is not a workload image and it does
not contain `kilnd`, a package manager, credentials, or a network interface.

The image is a 4 MiB BIOS disk. Its boot sector writes `KILN-PROBE-READY` to
COM1 about once a second, then sleeps on BIOS timer interrupts. A successful
start task is the lifecycle signal. The repeating serial marker is an
additional guest-boot signal when a QEMU serial console is available.

Build outside the repository so generated raw and QCOW2 files never become
source artifacts:

```bash
images/probe/build-bios-probe.sh /tmp/kiln-stage2-probe
```

The script requires GNU `as`, `ld`, `objcopy`, `objdump`, `qemu-img`,
`dd`, and `truncate`. It checks that linking left no relocations, checks the
QCOW2 structure, converts it back to raw, verifies the boot-sector signature
and marker, and refuses an artifact larger than 128 KiB. It does not sign,
upload, or import the image.

The Stage 2 operator must generate a fresh signed manifest from the produced
QCOW2 digest and bind the upload to a new, database-recorded staging filename.
Never overwrite or clean up an existing storage import by name alone.
