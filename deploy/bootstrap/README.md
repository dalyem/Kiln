# Proxmox bootstrap

`go run ./cmd/kiln bootstrap proxmox` explains the deployment plan. Phase 1 cannot apply it. There is no hypervisor installation script.

The future automatic-network bootstrap will use one existing PVE cluster endpoint for discovery. A standalone host is supported. A multi-node selection must already be part of one quorate cluster, and every selected node must be online and qualified. Kiln will not create or join a cluster, force quorum, or repair Corosync.

During initial automatic-network preparation, Kiln will use temporary host-key-verified read-only SSH checks on selected nodes. The checks install nothing and Kiln will not retain SSH credentials. They recur when an administrator prepares a node, after a relevant PVE upgrade, or after a declared host-network change. They do not run for each workload VM.

Automatic mode plans one protected gateway VM per prepared node. The gateway is not a disposable workload. Monitoring and the proposed `kiln doctor` recovery flow are described in [gateway operations](../../docs/architecture/gateway-operations.md). These features remain unimplemented.

See [appliance and bootstrap design](../../docs/architecture/deployment.md) for the resumable journal, API import constraints, ownership checks, first-boot enrollment, and questions required before implementation.
