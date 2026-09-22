from __future__ import annotations

import base64
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


NESTED = Path(__file__).resolve().parents[1]
RENDERER = NESTED / "render.py"
TEST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEh6N5wIx33RlXdWtdn0w7qJxGgH0Ek1fZLYrR3Z4nJ6 nested-test"


class RenderNestedFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.key = self.root / "lab.pub"
        self.key.write_text(TEST_KEY + "\n", encoding="utf-8")
        self.config = self.root / "fixture.toml"
        self.output = self.root / "out"
        self.write_config()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_config(self) -> None:
        self.config.write_text(
            f'''[gateway]
vmid = 100
hostname = "kiln-nested-gateway-01"
instance_id = "kiln-nested-gateway-100"
wan_mac = "BC:24:11:20:00:00"
trunk_mac = "BC:24:11:20:00:01"
ssh_public_key_file = "{self.key}"

[probe_a]
vmid = 101
hostname = "kiln-nested-probe-a"
instance_id = "kiln-nested-probe-a-101"
mac = "BC:24:11:20:01:00"

[probe_b]
vmid = 102
hostname = "kiln-nested-probe-b"
instance_id = "kiln-nested-probe-b-102"
mac = "BC:24:11:20:02:00"

[probes]
enable_http_test = true
''',
            encoding="utf-8",
        )

    def render(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["python3", str(RENDERER), "--config", str(self.config), "--output-dir", str(self.output)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)

    @staticmethod
    def embedded_file(cloud_init: str, path: str) -> str:
        lines = cloud_init.splitlines()
        index = next(index for index, line in enumerate(lines) if line == f"  - path: {path}")
        encoded = next(line.removeprefix("    content: ") for line in lines[index:] if line.startswith("    content: "))
        return base64.b64decode(encoded).decode("utf-8")

    def test_renders_three_private_nocloud_seeds_with_isolation_policy(self) -> None:
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn(TEST_KEY, result.stdout + result.stderr)
        for name in ("gateway", "probe_a", "probe_b"):
            for seed_name in ("user-data", "meta-data", "network-config"):
                artifact = self.output / name / seed_name
                self.assertTrue(artifact.is_file())
                self.assertEqual(artifact.stat().st_mode & 0o777, 0o600)
        gateway = (self.output / "gateway" / "user-data").read_text(encoding="utf-8")
        network = (self.output / "gateway" / "network-config").read_text(encoding="utf-8")
        self.assertNotIn("net.ipv4.ip_forward=0", gateway)
        self.assertIn('macaddress: "bc:24:11:20:00:00"', network)
        self.assertIn('macaddress: "bc:24:11:20:00:01"', network)
        self.assertIn("trunk0:", network)
        self.assertNotIn("addresses:", network[network.index("  trunk0:"):])
        firewall = self.embedded_file(gateway, "/etc/nftables.conf")
        forward = firewall[firewall.index("  chain forward {"):firewall.index("  chain output {")]
        self.assertLess(forward.index('iifname "lease210" ip saddr != 10.242.0.2 drop'), forward.index("ct state established,related accept"))
        self.assertNotIn("\n    ct state established,related accept", forward)
        self.assertLess(forward.index("ip daddr @protected_ipv4 drop"), forward.index('iifname "lease210" oifname "wan0"'))
        self.assertLess(forward.index('iifname "wan0" oifname "lease210" ip daddr 10.242.0.2 ct state established,related accept'), forward.index("ip daddr @protected_ipv4 drop"))
        self.assertIn('iifname "lease210" oifname "lease211" drop', firewall)
        self.assertIn('iifname "lease211" oifname "lease210" drop', firewall)
        self.assertIn('iifname "lease210" ip saddr 10.242.0.2 udp dport 53 accept', firewall)
        self.assertIn('iifname "lease211" ip saddr 10.242.0.18 udp dport 53 accept', firewall)
        self.assertIn('iifname "lease210" ip saddr { 0.0.0.0, 10.242.0.2 } udp sport 68 udp dport 67 accept', firewall)
        self.assertIn('iifname "lease210" ip saddr != 10.242.0.2 counter drop', firewall)
        self.assertNotIn("\n    ct state established,related accept", firewall)
        self.assertIn('iifname "wan0" ct state established,related accept', firewall)
        output = firewall[firewall.index("  chain output {"):firewall.index("  chain postrouting {")]
        self.assertNotIn("ct state established,related accept", output)
        self.assertIn('oifname "lease210" ip daddr { 255.255.255.255, 10.242.0.2 } udp sport 67 udp dport 68 counter accept', output)
        self.assertIn("AllowUsers root@10.250.103.10", self.embedded_file(gateway, "/etc/ssh/sshd_config.d/60-kiln-nested.conf"))
        lan = self.embedded_file(gateway, "/etc/systemd/system/kiln-nested-lan.service")
        self.assertIn("BindsTo=kiln-nested-firewall.service", lan)
        self.assertIn("Wants=network-online.target", lan)
        self.assertIn("After=kiln-nested-firewall.service network-online.target", lan)
        self.assertIn("type vlan id 210", lan)
        self.assertIn("type vlan id 211", lan)
        fail_closed = self.embedded_file(gateway, "/usr/local/sbin/kiln-nested-fail-closed")
        self.assertIn("net.ipv4.ip_forward=0", fail_closed)
        self.assertIn("ip link delete", fail_closed)
        dnsmasq = self.embedded_file(gateway, "/etc/dnsmasq.d/kiln-nested.conf")
        self.assertIn("dhcp-host=bc:24:11:20:01:00,set:lease210,10.242.0.2", dnsmasq)
        self.assertIn("dhcp-host=bc:24:11:20:02:00,set:lease211,10.242.0.18", dnsmasq)
        manifest = (self.output / "fixture-manifest.toml").read_text(encoding="utf-8")
        self.assertNotIn(TEST_KEY, manifest)
        self.assertIn("pve_trunk_native_vlan = 4094", manifest)
        self.assertIn("trunk_vlans = [210, 211]", manifest)

    def test_rejects_any_probe_mac_outside_fixed_topology(self) -> None:
        self.config.write_text(self.config.read_text(encoding="utf-8").replace("BC:24:11:20:02:00", "BC:24:11:20:02:01"), encoding="utf-8")
        result = self.render()
        self.assertEqual(result.returncode, 2)
        self.assertIn("probe_b.mac must match", result.stderr)

    def test_rejects_vm_ids_outside_fixed_topology(self) -> None:
        self.config.write_text(self.config.read_text(encoding="utf-8").replace("vmid = 101", "vmid = 110"), encoding="utf-8")
        result = self.render()
        self.assertEqual(result.returncode, 2)
        self.assertIn("probe_a.vmid must match", result.stderr)

    def test_rejects_output_inside_repository(self) -> None:
        result = subprocess.run(["python3", str(RENDERER), "--config", str(self.config), "--output-dir", str(NESTED / "forbidden-output")], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("output directory must be outside the repository", result.stderr)

    @unittest.skipUnless(shutil.which("nft") and shutil.which("sudo") and shutil.which("unshare"), "nft, sudo, or unshare is not installed")
    def test_generated_firewall_passes_nft_syntax_check(self) -> None:
        self.assertEqual(self.render().returncode, 0)
        gateway = (self.output / "gateway" / "user-data").read_text(encoding="utf-8")
        firewall = self.embedded_file(gateway, "/etc/nftables.conf")
        firewall_path = self.root / "nftables.conf"
        firewall_path.write_text(firewall, encoding="utf-8")
        sudo = subprocess.run(["sudo", "-n", "true"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if sudo.returncode != 0:
            self.skipTest("noninteractive sudo is unavailable")
        result = subprocess.run(["sudo", "-n", "unshare", "-n", "nft", "-c", "-f", str(firewall_path)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which("nft") and shutil.which("sudo") and shutil.which("unshare"), "nft, sudo, or unshare is not installed")
    def test_invalid_firewall_replacement_keeps_the_installed_drop_table(self) -> None:
        self.assertEqual(self.render().returncode, 0)
        gateway = (self.output / "gateway" / "user-data").read_text(encoding="utf-8")
        firewall_path = self.root / "nftables.conf"
        firewall_path.write_text(self.embedded_file(gateway, "/etc/nftables.conf"), encoding="utf-8")
        invalid_path = self.root / "invalid.conf"
        invalid_path.write_text("destroy table inet kiln_nested\ntable inet kiln_nested { invalid }\n", encoding="utf-8")
        before = self.root / "before.txt"
        after = self.root / "after.txt"
        sudo = subprocess.run(["sudo", "-n", "true"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if sudo.returncode != 0:
            self.skipTest("noninteractive sudo is unavailable")
        script = 'nft -f "$1"; nft list table inet kiln_nested > "$2"; if nft -f "$3"; then exit 1; fi; nft list table inet kiln_nested > "$4"; cmp "$2" "$4"'
        result = subprocess.run(["sudo", "-n", "unshare", "-n", "sh", "-ec", script, "sh", str(firewall_path), str(before), str(invalid_path), str(after)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which("nft") and shutil.which("ip") and shutil.which("sudo") and shutil.which("unshare"), "nft, ip, sudo, or unshare is not installed")
    def test_spoofed_public_dns_source_reaches_the_drop_counter(self) -> None:
        self.assertEqual(self.render().returncode, 0)
        gateway = (self.output / "gateway" / "user-data").read_text(encoding="utf-8")
        firewall_path = self.root / "nftables.conf"
        firewall_path.write_text(self.embedded_file(gateway, "/etc/nftables.conf"), encoding="utf-8")
        sudo = subprocess.run(["sudo", "-n", "true"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if sudo.returncode != 0:
            self.skipTest("noninteractive sudo is unavailable")
        script = '''
peer_namespace=kiln-nested-peer-$$
trap 'ip netns delete "$peer_namespace"' EXIT
ip netns add "$peer_namespace"
ip link add lease210 type veth peer name peer0
ip link set peer0 netns "$peer_namespace"
ip link set lease210 up
ip address add 10.242.0.1/28 dev lease210
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.lease210.rp_filter=0
ip netns exec "$peer_namespace" ip link set lo up
ip netns exec "$peer_namespace" ip link set peer0 up
ip netns exec "$peer_namespace" ip address add 10.242.0.2/28 dev peer0
ip netns exec "$peer_namespace" ip address add 8.8.8.8/32 dev peer0
nft -f "$1"
ip netns exec "$peer_namespace" python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("10.242.0.2", 55353)); s.sendto(b"known", ("10.242.0.1", 53))'
ip netns exec "$peer_namespace" python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("8.8.8.8", 55353)); s.sendto(b"x", ("10.242.0.1", 53))'
nft list chain inet kiln_nested input | grep -Eq 'ip saddr != 10.242.0.2 counter packets [1-9][0-9]* bytes [0-9]+ drop'
'''
        result = subprocess.run(["sudo", "-n", "unshare", "-n", "sh", "-ec", script, "sh", str(firewall_path)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(shutil.which("nft") and shutil.which("ip") and shutil.which("sudo") and shutil.which("unshare"), "nft, ip, sudo, or unshare is not installed")
    def test_dhcp_broadcast_offer_passes_the_gateway_output_rule(self) -> None:
        self.assertEqual(self.render().returncode, 0)
        gateway = (self.output / "gateway" / "user-data").read_text(encoding="utf-8")
        firewall_path = self.root / "nftables.conf"
        firewall_path.write_text(self.embedded_file(gateway, "/etc/nftables.conf"), encoding="utf-8")
        sudo = subprocess.run(["sudo", "-n", "true"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if sudo.returncode != 0:
            self.skipTest("noninteractive sudo is unavailable")
        script = r'''
ip link add lease210 type veth peer name peer0
ip link set lease210 up
ip link set peer0 up
ip address add 10.242.0.1/28 dev lease210
ip route add 255.255.255.255/32 dev lease210
nft -f "$1"
python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1); s.bind(("10.242.0.1", 67)); s.sendto(b"offer", ("255.255.255.255", 68))'
nft list chain inet kiln_nested output | grep -Eq 'oifname "lease210" ip daddr \{ 10.242.0.2, 255.255.255.255 \} udp sport 67 udp dport 68 counter packets [1-9][0-9]* bytes [0-9]+ accept'
'''
        result = subprocess.run(["sudo", "-n", "unshare", "-n", "sh", "-ec", script, "sh", str(firewall_path)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(shutil.which("dnsmasq"), "dnsmasq is not installed")
    def test_generated_dnsmasq_configuration_passes_its_parser(self) -> None:
        self.assertEqual(self.render().returncode, 0)
        gateway = (self.output / "gateway" / "user-data").read_text(encoding="utf-8")
        config = self.root / "dnsmasq.conf"
        config.write_text(self.embedded_file(gateway, "/etc/dnsmasq.d/kiln-nested.conf"), encoding="utf-8")
        result = subprocess.run(["dnsmasq", "--test", f"--conf-file={config}"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
