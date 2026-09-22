# Outer nested-PVE lab fixture

This directory renders private files for a disposable outer PVE test fixture. It does not call PVE, edit a bridge, create a VM, or build an ISO.

Copy [`example.toml`](example.toml) to a private directory outside this repository. Set the public-key and password-hash file paths there, then render the artifacts into a private build directory.

```sh
install -d -m 700 /private/build/kiln-lab
python3 deploy/lab/render.py \
  --config /private/build/kiln-lab/fixture.toml \
  --output-dir /private/build/kiln-lab/rendered
```

The renderer rejects an output directory inside the repository. It creates all artifacts with mode `0600`, prints no key or password-hash material, and rejects values that could alter generated firewall or installer syntax. Keep the private root key on the workstation. The configuration takes only its matching public key.

The three NoCloud seed files at the ISO root are `user-data`, `meta-data`, and `network-config`. The renderer writes those exact filenames. The network config uses MAC matching to name the DHCP WAN `wan0` and the private LAN `lan0`. The LAN is optional because it has no netplan address and stays down until the firewall-controlled LAN service starts. User-data does not embed network settings because cloud-init ignores networking in user-data.

The user-data configures a Debian 13 generic-cloud router VM. Its WAN uses DHCP on the configured existing bridge and VLAN. Its LAN gets its address only after the firewall unit loads. The firewall enables IPv4 forwarding after `nft -c` and an atomic `nft -f` transaction succeed. That transaction destroys and recreates only the fixture's `inet kiln_router` table. It disables IPv6, defaults INPUT, FORWARD, and OUTPUT to drop, permits WAN SSH only from the configured orchestrator address, and permits router-originated ProxyJump traffic only to the configured PVE ports. It denies protected and reserved IPv4 destinations before NAT. DHCP is restricted to reservations. Add a `dhcp-host=` line in the generated dnsmasq config only if a later lab probe needs one.

The firewall unit stops IPv4 forwarding but retains its own drop policy when it stops. A failed start triggers a fail-closed unit that disables forwarding and takes `lan0` down. The LAN unit binds to the firewall unit, so a firewall stop also removes the LAN address. User-data masks the stock `nftables.service` before commissioning, because it can flush unrelated tables on stop. The initial cloud-init package phase happens before this hardening. Keep VM 103 disconnected until the router has booted and these checks succeed on the router:

```sh
systemctl is-active kiln-router-firewall.service kiln-router-lan.service dnsmasq.service
sysctl net.ipv4.ip_forward net.ipv6.conf.all.disable_ipv6
nft list table inet kiln_router
ip -4 address show dev lan0
/usr/local/sbin/kiln-router-verify
```

The verifier confirms service state and forwarding settings. It also feeds invalid nftables input to `nft -c` and confirms the installed table did not change. On the disposable router, reboot it once and repeat the checks before attaching VM 103.

The router has no PVE or Kiln credentials. It can make public HTTP and HTTPS requests after the firewall starts, so later package maintenance still works. Its firewall denies protected ranges before those public rules. Do not use it as a product egress image. In particular, product nodes must not add a LAN management listener.

`pve-103-answer.toml` is an official PVE auto-install answer file. It installs the configured PVE VM with ext4 on the exact configured disk, static LAN settings, the supplied public key, and `power-off` after installation. The PVE assistant accepts `UTC` for its timezone field. It contains the password hash, so keep it private. The outer VM remains disconnected from Core. Build or attach the unattended ISO with the separate installer workflow, then use the host-side outer-fixture procedure for the exact VM and bridge configuration.

Run the focused checks with:

```sh
python3 -m unittest deploy.lab.tests.test_render
```

The test invokes the locally installed `proxmox-auto-install-assistant validate-answer` when available. It only uses a temporary public key and test password hash.
