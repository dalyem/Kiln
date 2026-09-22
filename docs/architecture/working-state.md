# Working state

## Completed Plane work — KILN-25 and KILN-85

GOAL: Implement the separately guarded Linux image import/clone qualification
path (KILN-25), then run and qualify the contributor Compose stack (KILN-85).

PLAN: Both tickets implemented, independently reviewed and locally qualified.

FACTS: VERIFIED: KILN-25 passed 286 tests across 30 files with PostgreSQL and two
workers, plus the full npm build. KILN-85 passed actual Compose build/startup,
API/dashboard/authentication, migrations, secret handling checks and persistence
across container recreation. Direct Node startup fixed npm wrapper shutdown
errors; all three containers exited 0. KILN-26 owns
live nested-Proxmox Linux qualification. The signed Linux disk exists locally;
existing BIOS limits and records must remain valid. Docker client/server are
available. The baseline passed all 236 tests with disposable PostgreSQL and
50 focused safety/profile tests. No PVE mutation is part of this implementation.
The actual 1.6 GiB local HTTP upload, signature/metadata verification and restored
historical-pool import intent passed at about 199 MiB peak RSS. Migration 0008
preserved all 23 historical tables. A separate actual Core/Postgres run completed
all nine phases with a local receipt provider and a store/service restart after
each phase. Independent review cleared staging, provider, Core, database and API.
All four protected BIOS/build source hashes remain unchanged. See
[Linux import evidence](../development/linux-import-qualification.md).

PARKED: Live Linux lab qualification (KILN-26), networking admission, workload
enrollment, previews, real lease cleanup, HA and production deployment.

STATE: Isolated Compose containers, network and database volume removed;
unrelated Plane containers unchanged. Disposable local PostgreSQL is stopped.
See [Compose evidence](../development/contributor-compose-qualification.md).

NEXT: KILN-26 is ready for the real nested-PVE Linux lifecycle qualification.
Private run evidence is under
/home/daly/.local/state/kiln/kiln25-6yd7k0oz.

## Completed Linux development image increment

GOAL: Signed Linux development base built and locally boot-qualified; general
Proxmox provisioning remains disabled. See [image design](linux-development-image.md)
and [qualification evidence](../development/linux-image-qualification.md).

FACTS: VERIFIED: Native QCOW2 checks, signed artifact/metadata verification and
actual no-NIC QEMU boot passed. The shipped static kilnd restored committed,
staged, unstaged and untracked fixture state. SSH activation is disabled,
passwords are locked, and source/boot-copy digests match after qualification.
Final artifact SHA-256 is
db9d5ed652fffb94d002e605433b61b17cffb0b8c45dcc9c21e2ce357ea02cd1.
The initial artifact was superseded after review found systemd's local SSH socket.
Independent review found no remaining material issue. The full 236-test suite
passed with isolated PostgreSQL; TypeScript and script checks passed.

STATE: Final image, signed bundle and boot evidence live under
/home/daly/.local/state/kiln/dev-image-qhxs_5nr/{build-final,signed-final,boot-final}.
The signing key is private local qualification material, not a release key.
Temporary QEMU guests and the disposable PostgreSQL server are stopped.
No Proxmox resources were mutated; existing API/BIOS qualification boundaries
and operator fixture ownership are unchanged.

NEXT: Implement a separate journaled Linux import profile and bounded staging
transport, then qualify this disk on nested Proxmox. Restore the existing lab
installation database before reusing retained allocations; never adopt them by
name or tags. Managed networking, workload enrollment/code upload, preview and
real lease expiry follow. This is not yet a Development Lease.

## Completed workspace increment

GOAL: Exact workspace capture/materialization implemented and locally qualified as the first increment toward a real Development Lease.

PLAN: Shared Go snapshot contract, CLI capture/inspect and kilnd materialize implemented. Real Git round trips and hostile-input regressions pass. See [Development Lease design](development-lease.md) and [workspace evidence](../development/workspace-qualification.md).

CHECKS: Final-source Go tests, race tests, vet, Linux binary qualification and Darwin arm64 CLI cross-build passed. The lead verified the independent run's source fingerprints and output comparisons. Capture/materialization remain Linux-only.

FACTS: VERIFIED: Final-source local restoration matches HEAD, status, cached and uncached binary diffs, passes Git fsck, omits the exact parent object and source remotes, and uses a private destination. The regression suite covers tampering, limits, hooks, concurrent changes and unsupported Git state. Real development creation, workload enrollment, Linux image staging and preview routing do not exist. The network remains LAB_PROBE_ONLY and existing lab router/probe fixtures remain EXTERNAL.

PARKED: Linux image/profile qualification, managed gateway construction, workload transport and preview integration follow the workspace boundary. No provider permission or network admission changes belong to this increment.

NEXT: Build and qualify the signed Linux image/profile and bounded large-image staging. Restore the existing lab installation database before reusing retained allocations; never adopt them from matching names. Follow with managed networking, workload enrollment/transport, preview and actual lease expiration. No Proxmox resources were changed during the workspace increment.

## Completed Stage 2

GOAL: Stage 2 guarded Proxmox lifecycle qualification completed on 2026-09-21.

FACTS: VERIFIED: 228 tests in 23 files passed with PostgreSQL and two workers; full npm build passed. Independent review is clear. The actual REST/Core/PostgreSQL/Proxmox flow completed pool creation, signed upload, import, template conversion, full clone, ownership stamping, start, stop and both VM deletions. Eight serial readiness markers proved guest execution. Restart retained the upload task ID with one submission. External VM targets were denied. All 25 current-session external configuration hashes matched. Inner VMs 100/101/102 remain running.

STATE: Qualification VMIDs 9100/9101 and their disks are absent. The empty kiln pool and signed staging image remain explicit RETAINED allocations. The database backup restored successfully; the check confirmed the completed run, ten phases and two retained allocations. Temporary API instances, tunnel and PostgreSQL server are stopped; the test Proxmox token, user, ACLs and five roles are removed. Private evidence/backups are under /home/daly/.local/state/kiln/stage2-leynrkzf. No Proxmox credentials belong in repository files or workloads.

NEXT: Build the first real Development Lease incrementally: a signed Linux development image, authenticated kilnd workload enrollment, exact working-state materialization, qualified network admission, preview routing and guarded TTL cleanup. The completed BIOS lifecycle is not a development environment. Use the [qualification evidence](../development/stage2-qualification-evidence.md) and [operator instructions](../development/proxmox-qualification.md).

PARKED: General live provisioning, appliance/bootstrap packaging, automatic gateway deployment/repair, HA and production authentication remain later work. The outer fixture lost its manually assigned LAN address after a networkd restart; restarting its existing LAN and DNS services recovered access. Persistent appliance readiness must check actual network state. No network-policy files were changed.


## Gateway identity implementation

- Core stores hashed enrollment tokens, installation-bound issuer identity, device certificates, bounded renewal grace, monotonic heartbeat sequences and revocation in PostgreSQL. Management mutations require the separate infrastructure credential.
- Go `kilnd gateway` creates and persists its own key, verifies Core TLS, enrolls over HTTPS and sends heartbeats over mTLS. It opens no administrative listener. Normal shutdown exits successfully.
- Enrollment or revocation permanently stops trusting simulated heartbeat evidence for that gateway. Revocation invalidates pending and consumed tokens while preserving the admission hold. Independent network probes remain required.
- Actual local Go-to-TypeScript TLS enrollment, heartbeat, Core restart, revoked-certificate denial and recovery after certificate expiry during a Core outage passed against PostgreSQL. The outage test used shortened leaf lifetimes and explicit restoration of the fake provider's observations. No Proxmox resource was changed.
- A permanent cross-runtime integration test passes with actual short-lived certificate expiry and revocation on a keep-alive mTLS connection. All 85 TypeScript/PostgreSQL tests passed with no skips, as did the full npm build, Go tests/vet and four Python SDK tests. Independent review found no remaining material product issues; its final CA-lifetime test gap is covered by the permanent runtime test.


## Verified foundation

- 73 TypeScript/Postgres tests, a clean npm build, Go tests/vet and four Python SDK tests passed for the completed gateway monitoring slice. They were not rerun for this HA documentation change.
- Actual Postgres-backed HTTP lifecycle, auth, idempotency, audit-failure denial, scheduled expiry, singleton writer, restart and installation mismatch checks passed.
- MCP, CLI and SDK calls reached the API. The dashboard rendered API data without exposing its token in HTML.
- The live Proxmox provider remains GET-only. Existing resources remain EXTERNAL; unknown tags never authorize adoption or mutation.

## Verified nested lab

- Physical cluster has three nodes. Only operator-created outer fixtures on Zeus were added: nested PVE VM 103, egress VM 104 and private bridge klab103. Existing VMs 100/101/102 remain untouched.
- Outer bridge has no physical uplink, host addresses or bridge-self VLAN membership. Gateway stop, invalid firewall replacement and reboot tests passed. No production credentials are in either guest.
- VM 103 runs standalone PVE 9.2.2, kernel 7.0.2-6-pve, with nested KVM. It has not joined the production cluster. No Kiln runtime dependencies were installed on a PVE host.
- Dedicated, expiring tokens separately performed read-only discovery, the controlled SDN experiment and exact operator fixture operations. TLS certificates were verified. The private helper validates explicit plans, fresh config digests, ownership metadata, pool membership, all attachments and durable task results.
- SDN global-lock staging/apply created only the planned node-local Simple zone and VLAN-aware VNet. The asynchronous apply completed before lock release. Clustered apply remains unqualified.
- Inner gateway 100 and probes 101/102 were created through the nested API from a checksum-verified image and reviewed private NoCloud seeds. Kiln's existing REST inventory handler classified all three as EXTERNAL with GET-only provider calls.
- Both probes received reserved DHCP addresses and passed public DNS/HTTPS plus local HTTP service checks. Reciprocal peer HTTP connections timed out.
- Actual tap captures verified A-to-B tagged/untagged isolation, reciprocal B-to-A forgery denial, input and forwarding IPv4 source-spoof rejection, and denial of one new inbound WAN UDP flow. Independent review inspected original frames, NAT transformations and replies.
- Actual VM IPv6 UDP to the host bridge MAC/link-local address was captured at source but not delivered to a working host listener, with promiscuity off and on. Host TCP 22/8006 attempts timed out while local controls connected. Earlier native-VLAN veth controls worked. Guest IPv6 addresses/neighbors were absent afterward and disable flags/promiscuity were restored.
- The inner gateway retained its drop policy and disabled forwarding/LAN when its firewall stopped or an invalid policy failed to load. Its own reboot recovered all services and public HTTPS.
- A guarded, one-shot reboot of outer VM 103 completed with PVE task OK. The nested host restored the same SDN objects and VLAN configuration, automatically started only its gateway, and held probes stopped. After gateway readiness, both probes recovered DHCP/DNS/HTTPS and local HTTP. The forwarding/isolation matrix and peer HTTP checks passed again.
- All 27 saved pre-existing configuration hashes across the three physical hosts matched after the nested-host reboot.
- The outer and inner fixture suites passed 21 tests with no skips, including real network-namespace packets. Exact evidence and limits are in [nested-lab-evidence.md](nested-lab-evidence.md).

## Accepted qualification and remaining limits

- ACCEPTED: Default bootstrap uses temporary, host-key-verified, read-only SSH qualification for each selected node during installation, node expansion, relevant upgrades or declared network changes. It installs nothing, retains no SSH credential and does not run SSH per workload creation. The user did not approve the alternative API-only attestation. PVE's structured SDN API omits bridge-self VLAN membership; a broad node report exposes addresses/promiscuity but still omits that membership.
- The inner API-created bridge has an automatic IPv6 link-local address on self VLAN 1. Tested workloads use separate VLANs 210/211. The strict no-host-address target therefore still needs an explicit production construction or a qualified host-VLAN separation design.
- The lab remains LAB_PROBE_ONLY. Point-in-time tests do not provide continuous admission assurance or qualify other PVE/kernel versions, physical-node reboot behavior or clustered SDN apply.
- Both gateway addresses expose the same DNS resolver. Separate DNS policies will require destination binding and resolver policy separation.
- The private packet runner's marker-only evaluator needs header/direction parsing before it becomes a reusable release test. This experiment's claims rely on the inspected raw captures.

NOT DONE: General live workload provisioning, workload enrollment/transport, exact dirty-worktree transfer, authenticated preview, actual VM lease cleanup, appliance image/bootstrap executor, Docker Compose execution, production authentication, backup/upgrade executors and browser/workflow runtime.

ACCEPTED: Trusted PVE administrators, restore quarantine, team structure within one organization, automatic private networking by default, advanced existing-network mode, standard MIT licensing, one appliance for one- and two-node installations, and three-replica Core HA for qualified clusters with three or more physical hosts. No trusted-LAN fallback is approved.

COMPLETED IMPLEMENTATION TASK: The first gateway slice now persists protected `gateway` records, health and incidents; runs a monitor every 10 seconds; holds fake workload admission when configured gateways lack fresh ready evidence; and exposes read-only doctor data through REST, CLI, MCP and dashboard. Generic resource creation, stop, destroy, lease extension and TTL cleanup reject gateways. Setup and explicit scan require a separate infrastructure token; repairs remain disabled. All 73 TypeScript/Postgres tests, the full build, Go tests/vet and four Python SDK tests passed. Actual HTTP, immediate restart admission holds, CLI, MCP, browser refresh/staleness and read-only nested-PVE checks passed. Independent review reported no remaining material findings. No infrastructure changes were performed.

LATER: Qualify actual workload placement and network canaries before real private-network admission, then build a reproducible local Core HA fault test using the fake provider. Do not turn on mutations in the Phase 1 observer or adopt the operator fixtures into Core.
