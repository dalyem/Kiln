# Image build plan

The Linux development image is the first real QCOW2 build artifact. Its local build, signing, file verification and no-NIC boot check are in [dev](dev/README.md). The directories also reserve appliance, runner, browser, desktop and workflow roles.

The appliance contains the Compose control plane. Every workload image later contains kilnd and capability-specific tools, never Proxmox credentials. Versioned manifests must identify digest, architecture, source build, node/storage requirements and signature before installation.

See [deployment architecture](../docs/architecture/deployment.md) and [image manager design](../docs/architecture/providers.md).

The contributor scaffold can verify signed fixture bytes and exercise managed fake template/clone provenance. See the [walkthrough](../docs/development/image-provenance.md). This does not build or import a real qcow2 image.

The bounded Stage 2 lifecycle qualification has one exception: its [BIOS probe](probe/README.md) is built from source into a caller-chosen temporary directory. It has no network device or workload runtime and is not distributed with Kiln.
