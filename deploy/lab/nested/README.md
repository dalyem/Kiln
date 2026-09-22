# Nested private-network probe fixture

This renderer creates three private NoCloud seed directories for a disposable test inside VM 103. It creates no Proxmox resources, ISO files, bridges, firewall rules, or network changes. The gateway and probes are operator-owned fixtures and remain external to Kiln Core.

Copy [`example.toml`](example.toml) to a private directory outside the repository. Set `ssh_public_key_file` to the existing lab public key. Render into another private directory:

```sh
install -d -m 700 /private/kiln-lab/nested
python3 deploy/lab/nested/render.py \
  --config /private/kiln-lab/nested/fixture.toml \
  --output-dir /private/kiln-lab/nested/rendered
```

The result has exact NoCloud filenames in `gateway`, `probe_a`, and `probe_b`, plus a manifest that omits the public key. Every rendered file is mode `0600`. Build seed ISOs and create VMs only through the separate operator procedure after review.

The gateway is VM 100 with static WAN address `10.250.103.30/24` through nested `vmbr0`. Its second NIC is a trunk on PVE VLAN 4094 carrying only VLANs 210 and 211. The seed gives that trunk no untagged layer-three configuration. `kiln-nested-lan.service` creates `lease210` and `lease211` only after the firewall has loaded successfully. It removes both interfaces and disables forwarding when the firewall stops or fails. The firewall retains its own drop policy when stopped.

Probe VMs 101 and 102 each have one DHCP access NIC, on VLAN 210 and 211 respectively. They receive the fixed addresses `10.242.0.2` and `10.242.0.18`. The gateway permits only public DNS, HTTP, and HTTPS egress for those exact source addresses. It blocks protected and reserved addresses before egress rules, blocks peer forwarding, and does not use a global established-forward rule. IPv6 is disabled. Gateway SSH permits only the outer lab PVE at `10.250.103.10`; probes have no gateway SSH exception. All guests use the supplied public key and contain no PVE or Kiln credentials.

Boot and verify the gateway before booting either probe. A successful render is not readiness proof. Confirm in the gateway that the firewall, LAN unit, and dnsmasq are active; forwarding is `1`; `trunk0` has no address; `lease210` and `lease211` have only their stated addresses; and the nftables table contains the expected anti-spoof and protected-destination rules. Then boot the probes and prove the actual DHCP leases, allowed public HTTP/DNS egress, peer denial, protected-range denial, and failure behavior by using the QEMU guest agent.

Run renderer checks with:

```sh
python3 -m unittest deploy.lab.nested.tests.test_render
```
