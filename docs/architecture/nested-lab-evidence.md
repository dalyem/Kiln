# Nested network experiment

This records an operator-controlled experiment inside the isolated test VM. It is not a production readiness certificate. Fixture resources remain EXTERNAL to Kiln Core.

## Verified environment

The outer test VM runs standalone Proxmox VE 9.2.2, kernel 7.0.2-6-pve, libpve-network-perl 1.6.5 and ifupdown2 3.3.0. Nested KVM is available. The outer egress VM permits public DNS and HTTP/HTTPS while blocking private management destinations. Its firewall failure and reboot behavior have been exercised. Production cluster membership was not changed.

Kiln's existing read-only provider discovered the nested node and local storage with a dedicated auditor token and verified TLS. This does not enable provider mutations.

## SDN apply result

A separate, expiring token holds SDN.Audit, SDN.Allocate, SDN.Use and Sys.Audit. The experiment acquired the global SDN lock with allow-pending=0, recorded a baseline under that lock, and staged one Simple zone restricted to the nested node plus one VLAN-aware VNet. The pending diff contained only the expected bridge and the stock first-apply FRR configuration rewrite.

The apply request used release-lock=0. The asynchronous task reported OK. Runtime inspection completed before explicit lock release. HTTP DELETE parameters must be encoded in the query string for this PVE endpoint. Sending the lock token in a DELETE form body did not release it.

The generated bridge has VLAN filtering enabled, no physical member ports, default PVID 1, self VLAN 1 and promiscuity 0. Proxmox automatically assigned an IPv6 link-local address. Guest access VLANs are 210 and 211. The gateway has tagged membership in both, with native VLAN 4094 and no untagged layer-three configuration.

The PVE 9.2.2 multipart upload parser processes form fields in the fixed order `content`, `checksum-algorithm`, `checksum`, then `filename`. Sending checksum before checksum-algorithm failed before creating a seed image. The installed `PVE/APIServer/AnyEvent.pm` parser supplied the corrective contract.

The node SDN bridges API reports VLAN filtering and guest-port VLAN assignments. It does not expose all the bridge-self, address, or promiscuity data needed by the proposed host-isolation check. Read-only host inspection supplied those observations in this experiment. API-only readiness remains unresolved.

## Admission and test gates

Current admission is LAB_PROBE_ONLY. Only these controlled fixture probes may attach; ordinary workloads must not be admitted.

| Check | Required observation | Result |
| --- | --- | --- |
| Gateway first boot | Cloud-init completes; rules and tagged interfaces agree; native interface has no address | Passed through authenticated QGA and independently pinned SSH |
| Gateway reboot | Same policy and addresses recover without manual service restart | Passed; new boot ID, exact addresses/services, HTTPS 200 observed within 32.1 seconds of submission |
| DHCP and public egress | Each probe receives its reserved address; DNS and public HTTPS succeed | Passed on both real VMs, with clean cloud-init completion |
| Peer isolation | Known listening peer service remains unreachable; no forged packet arrives on peer tap | Passed in both directions: HTTP 8080 positives, peer TCP timeouts, and reciprocal direct/forged-VLAN packet captures |
| VLAN injection | Forged tags cannot cross into another lease or the host VLAN | A-to-B matrix passed. Priority VLAN 0 and own VLAN 210 retain permitted egress; peer/native/reserved outer tags stop at the source tap. Double tags and 802.1ad did not reach the peer |
| Source spoofing | Forged peer/public source cannot forward or cause DNS reflection | Passed for the tested IPv4 UDP paths: gateway-input drops incremented twice; forged peer/public sources addressed to public DNS reached the gateway trunk but not WAN |
| Host delivery probes | Test the listed IPv4 management ports and direct host-MAC IPv6 UDP/TCP paths | Probe A management TCP timeouts; actual VM IPv6 UDP to host MAC captured at source but not delivered to a working host listener. Host TCP 22/8006 timed out |
| Promiscuous bridge | Repeat host probes with promiscuity temporarily enabled inside the lab, then restore it | Actual VM IPv6 UDP was not delivered with promiscuity off or on; TCP 22/8006 attempts timed out while same-address local controls connected. Guest IPv6 flags and host promiscuity restored |
| Protected egress | Private, link-local, metadata and gateway WAN destinations remain blocked | TCP probes to nested management, outer gateway, production management, gateway SSH and metadata timed out while public HTTPS connected |
| Inbound access | Test new WAN traffic addressed to the private workload | A marked new UDP flow reached gateway WAN but neither its private trunk nor probe A. This is one tested UDP flow, not every inbound protocol |
| Gateway failure | Invalid rules or stopped firewall leave forwarding off and lease interfaces unavailable | Passed; both cases retained the old drop policy, forwarding 0 and no lease interfaces. Reviewed policy restored and services recovered |
| Nested host reboot | Guest VLAN assignments persist; gateway recovers before probe admission | Passed: new PVE and gateway boot IDs, unchanged SDN objects, restored self/trunk VLANs, gateway autostart, probes held stopped until readiness, then reserved DHCP addresses and public HTTPS recovered |
| Ownership classification | Real fixture VMs remain EXTERNAL in Kiln discovery | Passed through the existing REST handler with a fresh empty test store and real GET-only provider |

Capture only on individual taps with promiscuous mode disabled. A timeout alone is insufficient: establish the target works from an allowed context, and inspect packet delivery or firewall counters where applicable. Deliberate host-promiscuity testing is confined to this disposable nested host.

A successful single-node experiment does not qualify clustered apply behavior. PVE applies SDN configuration across cluster nodes even when the created zone restricts workload placement to one node. Unknown task results, incomplete visibility, ownership mismatch or unexpected attachments must stop automation without deleting resources.

The gateway seed passed nine focused tests and independent review, including real namespace packets for spoofed DNS source rejection and broadcast DHCP responses. These tests do not replace guest boot checks.

The initial IPv4 temporary-veth test was inconclusive because it targeted the hypervisor's other interface and failed its positive control. A kernel UDP sender also failed that path. Targeting a temporary IPv4 address directly on the bridge succeeded; that address was then removed.

A subsequent IPv6 test used the bridge's actual automatically assigned link-local address. Native access VLAN 1 reached the listener, access VLAN 210 did not, VLAN 210 with bridge promiscuity enabled did not, and a final native VLAN 1 control reached it again. These are valid positive controls for the tested IPv6 UDP path on this exact kernel. They do not prove forged-tag rejection or all host protocols. The temporary namespace and veth pair were removed, and promiscuity was restored to zero.

Private operation journals contain exact resource plans, task IDs, artifact hashes and runtime evidence. Credentials and rendered seed data stay outside the repository.

## Packet evidence and limits

The first actual-VM matrix captured only marked packets on four individual taps without enabling promiscuous capture. All 16 markers appeared on their source tap. Valid DNS controls from both probes reached the gateway WAN and received replies. No A marker appeared on B's tap. An independent review rebuilt the frames and matched every sender byte count and SHA-256. VLAN 4095 was deliberately a malformed negative case, not a supported VLAN.

Both source-spoof cases in that matrix addressed the gateway itself. They exercised input filtering, not forwarding. Likewise, the tagged IPv4 packets addressed the gateway MAC, so they cannot substantiate host CPU isolation. Separate IPv6 tests targeted the actual host bridge MAC and link-local listener. Those tests temporarily enabled guest IPv6, supplied a fixed neighbor, sent a marked UDP frame and attempted host TCP 22/8006, then restored the original guest settings. The host listener had a successful local control in each phase, and source-tap capture confirmed transmission. The earlier native-VLAN veth controls independently proved network delivery to that listener.

Probe A can query the shared DNS resolver using either lease gateway address. WAN DNS is not listening. This is an alternate address for the same resolver policy, not access to the other workload. Future per-profile DNS policy requires destination-bound firewall rules and resolver policy separation.

A separate post-test read confirmed the probe had no IPv6 addresses or neighbors. Same-address local IPv6 TCP controls successfully connected to host ports 22 and 8006. This confirms those listeners existed; the recorded workload attempts remain specific port checks, not an all-protocol guarantee.

## Reboot and preservation results

A single guarded outer PVE API reboot restarted only the operator-owned nested VM. The wrapper compared the exact VM configuration and digest, checked pending changes and HA exclusion, and validated both outer and inner bridge topology before submission. A durable exclusive attempt record prevents automatic resubmission after an uncertain response. The PVE reboot task reported OK.

After boot, all five checked PVE services were active. The SDN zone and VNet, including their digests, matched the pre-reboot records. Only gateway VM 100 started automatically. Probe VMs 101 and 102 remained stopped until the gateway's clean cloud-init state, service health, exact policy hash, drop chains, IPv4 addresses, disabled IPv6, and public DNS/HTTPS were verified. Both probes then recovered their reserved DHCP addresses, local HTTP services and public HTTPS. The bridge's generated MAC and IPv6 link-local address changed across boot; these are runtime observations, not durable ownership identifiers.

The seven-case forwarding, reciprocal-forgery and inbound-UDP matrix passed again after reboot, and both peer HTTP attempts still timed out with functioning local services. Independent review distinguished original query frames, NAT transformations and replies in the recorded captures. The private runner's marker-only evaluator is not sufficient for a reusable release qualification suite without header/direction parsing.

All 27 baseline configuration hashes across the three physical hosts still matched after the nested-host reboot. The check covers the saved pre-existing VM, cluster, storage, HA and network configuration files; it does not claim to hash every file on each host.

The two fixture suites passed 21 tests with no skips, including actual namespace packets. The real Core Development Lease, appliance/bootstrap executor, continuous node admission and clustered apply are still unimplemented or unqualified. The lab remains LAB_PROBE_ONLY.
