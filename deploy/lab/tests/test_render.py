from __future__ import annotations

import base64
import importlib.util
import os
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path


LAB_DIRECTORY = Path(__file__).resolve().parents[1]
RENDERER = LAB_DIRECTORY / "render.py"
INSTALLER_ASSISTANT = Path("/home/daly/.local/state/kiln/tools/pve-auto/usr/bin/proxmox-auto-install-assistant")
TEST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEh6N5wIx33RlXdWtdn0w7qJxGgH0Ek1fZLYrR3Z4nJ6 kiln-lab-test"
TEST_HASH = "$6$rounds=5000$kilnlabtest$Xklc9maOiuEKe9bgqVukrm6AvlT8hnIYqWsyh4JnY1OkwLz4T4kyuD9UJBhfy4mCMeBBDh07f9q8ESShO/G03."
GUEST_NETWORKING_SOURCE = Path(
    os.environ.get(
        "KILN_GUEST_CLOUD_INIT_NETWORKING",
        "/home/daly/.local/state/kiln/labs/16103ac7-1083-4b51-8124-f83d3f322d8b/router-diagnostic-mount/usr/lib/python3/dist-packages/cloudinit/distros/networking.py",
    )
)


class RenderLabFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary_directory.name)
        self.key_path = self.directory / "root.pub"
        self.hash_path = self.directory / "root.hash"
        self.key_path.write_text(TEST_KEY + "\n", encoding="utf-8")
        self.hash_path.write_text(TEST_HASH + "\n", encoding="utf-8")
        self.config_path = self.directory / "fixture.toml"
        self.output_directory = self.directory / "private-output"
        self.write_config()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def write_config(self) -> None:
        self.config_path.write_text(
            f'''[router]
vmid = 104
hostname = "kiln-lab-router-01"
instance_id = "kiln-lab-router-104"
wan_bridge = "vmbr0"
wan_vlan = 119
wan_mac = "BC:24:11:10:04:00"
lan_vnet = "klab103"
lan_vlan = 103
lan_mac = "BC:24:11:10:04:01"
lan_ip = "10.250.103.1"
lan_cidr = "10.250.103.0/24"
orchestrator_ip = "10.63.119.100"
upstream_dns = ["1.1.1.1", "9.9.9.9"]
protected_ipv4_cidrs = [
  "0.0.0.0/8", "10.0.0.0/8", "10.63.99.0/24", "10.63.100.0/24", "10.63.119.0/24", "100.64.0.0/10", "127.0.0.0/8",
  "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
  "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
  "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
]
permit_open = ["10.250.103.10:22", "10.250.103.10:8006"]
ssh_public_key_file = "{self.key_path}"
[pve]
vmid = 103
hostname = "kiln-lab-pve-01.test"
ip = "10.250.103.10"
prefix = 24
gateway = "10.250.103.1"
dns = "10.250.103.1"
mac = "BC:24:11:0F:63:CC"
disk = "sda"
country = "us"
keyboard = "en-us"
timezone = "UTC"
mailto = "admin@kiln.test"
ssh_public_key_file = "{self.key_path}"
root_password_hash_file = "{self.hash_path}"
''',
            encoding="utf-8",
        )

    def render(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(RENDERER), "--config", str(self.config_path), "--output-dir", str(self.output_directory)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_renders_private_outputs_with_required_policy(self) -> None:
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(TEST_KEY, result.stdout + result.stderr)
        self.assertNotIn(TEST_HASH, result.stdout + result.stderr)
        cloud_init = (self.output_directory / "user-data").read_text(encoding="utf-8")
        network_config = (self.output_directory / "network-config").read_text(encoding="utf-8")
        meta_data = (self.output_directory / "meta-data").read_text(encoding="utf-8")
        self.assertNotIn("\nnetwork:\n", cloud_init)
        self.assertNotIn("net.ipv4.ip_forward=0", cloud_init)
        self.assertIn('macaddress: "bc:24:11:10:04:00"', network_config)
        self.assertIn('macaddress: "bc:24:11:10:04:01"', network_config)
        self.assertIn("use-dns: false", network_config)
        self.assertIn("addresses: [1.1.1.1, 9.9.9.9]", network_config)
        self.assertIn("  lan0:\n", network_config)
        self.assertIn("    optional: true\n", network_config)
        self.assertIn("instance-id: kiln-lab-router-104", meta_data)
        self.assertNotIn("Kiln lab router is configured", cloud_init)
        self.assertIn("kiln-router-firewall.service", cloud_init)
        self.assertIn("[systemctl, mask, --now, nftables.service]", cloud_init)
        self.assertIn("[systemctl, restart, qemu-guest-agent.service]", cloud_init)
        self.assertIn("ExecStartPost=/usr/sbin/sysctl -w net.ipv4.ip_forward=1", base64.b64decode(self.file_content(cloud_init, "/etc/systemd/system/kiln-router-firewall.service")).decode())
        firewall = base64.b64decode(self.file_content(cloud_init, "/etc/nftables.conf")).decode()
        self.assertLess(firewall.index("ct state established,related accept"), firewall.index("ip daddr @protected_ipv4 drop"))
        self.assertIn("10.63.119.100 tcp dport 22 accept", firewall)
        self.assertIn("tcp dport { 80, 443 } accept", firewall)
        self.assertIn("ip daddr @public_dns udp dport 53 accept", firewall)
        self.assertLess(firewall.index("ip daddr 10.250.103.10 tcp dport"), firewall.rindex("ip daddr @protected_ipv4 drop"))
        self.assertLess(firewall.index('oifname "lan0" udp sport 67 udp dport 68 accept'), firewall.rindex("ip daddr @protected_ipv4 drop"))
        self.assertTrue(firewall.startswith("destroy table inet kiln_router\n"))
        loader = base64.b64decode(self.file_content(cloud_init, "/usr/local/sbin/kiln-router-load-firewall")).decode()
        self.assertEqual(loader.count("nft -f /etc/nftables.conf"), 1)
        self.assertIn("nft -c -f /etc/nftables.conf", loader)
        firewall_unit = base64.b64decode(self.file_content(cloud_init, "/etc/systemd/system/kiln-router-firewall.service")).decode()
        self.assertIn("OnFailure=kiln-router-fail-closed.service", firewall_unit)
        self.assertNotIn("nft delete table", firewall_unit)
        self.assertIn("After=local-fs.target systemd-sysctl.service", firewall_unit)
        sysctl = base64.b64decode(self.file_content(cloud_init, "/etc/sysctl.d/90-kiln-router.conf")).decode()
        self.assertIn("net.ipv4.ip_forward = 0", sysctl)
        lan_unit = base64.b64decode(self.file_content(cloud_init, "/etc/systemd/system/kiln-router-lan.service")).decode()
        self.assertIn("BindsTo=kiln-router-firewall.service", lan_unit)
        sshd = base64.b64decode(self.file_content(cloud_init, "/etc/ssh/sshd_config.d/60-kiln-lab.conf")).decode()
        self.assertIn("AllowUsers root@10.63.119.100", sshd)
        verifier = base64.b64decode(self.file_content(cloud_init, "/usr/local/sbin/kiln-router-verify")).decode()
        self.assertIn("nft -c -f", verifier)
        self.assertIn("cmp \"$before\" \"$after\"", verifier)
        self.assertNotIn(TEST_HASH, cloud_init)
        self.assertEqual((self.output_directory / "user-data").stat().st_mode & 0o777, 0o600)

    def test_rejects_injection_in_a_network_field(self) -> None:
        self.config_path.write_text(
            self.config_path.read_text(encoding="utf-8").replace(
                'wan_bridge = "vmbr0"', 'wan_bridge = "vmbr0; drop table inet filter"'
            ),
            encoding="utf-8",
        )
        result = self.render()
        self.assertEqual(result.returncode, 2)
        self.assertIn("wan_bridge has an invalid value", result.stderr)

    def test_rejects_permit_open_for_any_host_but_the_lab_pve(self) -> None:
        self.config_path.write_text(
            self.config_path.read_text(encoding="utf-8").replace(
                'permit_open = ["10.250.103.10:22", "10.250.103.10:8006"]',
                'permit_open = ["10.63.119.1:22"]',
            ),
            encoding="utf-8",
        )
        result = self.render()
        self.assertEqual(result.returncode, 2)
        self.assertIn("may only name the lab PVE", result.stderr)

    @unittest.skipUnless(GUEST_NETWORKING_SOURCE.is_file(), "mounted Debian guest cloud-init source is unavailable")
    def test_guest_cloud_init_physical_device_gate_requires_lowercase_macs(self) -> None:
        specification = importlib.util.spec_from_file_location("kiln_guest_networking", GUEST_NETWORKING_SOURCE)
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)

        class StubNetworking:
            def __init__(self, expected_macs: list[str]) -> None:
                self.expected_macs = expected_macs
                self.settle_calls = 0

            def extract_physdevs(self, _netcfg: object) -> list[tuple[str, str]]:
                return [(mac, f"ens{18 + index}") for index, mac in enumerate(self.expected_macs)]

            def get_interfaces_by_mac(self) -> dict[str, str]:
                return {
                    "bc:24:11:10:04:00": "ens18",
                    "bc:24:11:10:04:01": "ens19",
                }

            def settle(self, *, exists: str) -> None:
                self.settle_calls += 1

        uppercase = StubNetworking(["BC:24:11:10:04:00", "BC:24:11:10:04:01"])
        with self.assertRaisesRegex(RuntimeError, "Not all expected physical devices present"):
            module.Networking.wait_for_physdevs(uppercase, object())
        lowercase = StubNetworking(["bc:24:11:10:04:00", "bc:24:11:10:04:01"])
        module.Networking.wait_for_physdevs(lowercase, object())
        self.assertEqual(lowercase.settle_calls, 0)

    def test_quotes_a_public_key_comment_before_putting_it_in_cloud_init(self) -> None:
        self.key_path.write_text(TEST_KEY + " ' # test comment\n", encoding="utf-8")
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        cloud_init = (self.output_directory / "user-data").read_text(encoding="utf-8")
        self.assertIn("- 'ssh-ed25519", cloud_init)
        self.assertIn("'' # test comment'", cloud_init)

    @unittest.skipUnless(INSTALLER_ASSISTANT.exists(), "local PVE installer assistant is not installed")
    def test_pve_answer_passes_the_local_installer_validator(self) -> None:
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        answer_path = self.output_directory / "pve-103-answer.toml"
        answer = answer_path.read_text(encoding="utf-8")
        parsed = tomllib.loads(answer)
        self.assertEqual(parsed["network"]["source"], "from-answer")
        self.assertEqual(parsed["network"]["filter"], {"ID_NET_NAME_MAC": "enxbc24110f63cc"})
        self.assertTrue(parsed["network"]["filter"])
        self.assertEqual(parsed["network"]["cidr"], "10.250.103.10/24")
        self.assertEqual(parsed["global"]["root-ssh-keys"], [TEST_KEY])
        validation = subprocess.run(
            [str(INSTALLER_ASSISTANT), "validate-answer", str(answer_path)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        diagnostics = validation.stdout + validation.stderr
        self.assertEqual(validation.returncode, 0, diagnostics)
        self.assertIn("parsed successfully", diagnostics.lower(), diagnostics)
        self.assertNotIn("error:", diagnostics.lower(), diagnostics)

    @unittest.skipUnless(shutil.which("cloud-init"), "cloud-init is not installed")
    def test_nocloud_user_and_network_artifacts_pass_cloud_init_schema(self) -> None:
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        for schema_type, filename in (
            ("cloud-config", "user-data"),
            ("network-config", "network-config"),
        ):
            validation = subprocess.run(
                ["cloud-init", "schema", "--schema-type", schema_type, "--config-file", str(self.output_directory / filename)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(validation.returncode, 0, validation.stdout + validation.stderr)

    @unittest.skipUnless(shutil.which("dnsmasq"), "dnsmasq is not installed")
    def test_dnsmasq_configuration_passes_its_parser(self) -> None:
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        cloud_init = (self.output_directory / "user-data").read_text(encoding="utf-8")
        configuration = base64.b64decode(self.file_content(cloud_init, "/etc/dnsmasq.d/kiln-lab.conf")).decode()
        self.assertIn("dhcp-range=10.250.103.0,static,255.255.255.0", configuration)
        configuration_path = self.directory / "dnsmasq.conf"
        configuration_path.write_text(configuration, encoding="utf-8")
        validation = subprocess.run(
            ["dnsmasq", "--test", f"--conf-file={configuration_path}"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(validation.returncode, 0, validation.stdout + validation.stderr)

    @unittest.skipUnless(shutil.which("nft") and shutil.which("sudo") and shutil.which("unshare"), "nft, sudo, or unshare is not installed")
    def test_rendered_nftables_transaction_keeps_the_old_table_on_invalid_replacement(self) -> None:
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        cloud_init = (self.output_directory / "user-data").read_text(encoding="utf-8")
        firewall = base64.b64decode(self.file_content(cloud_init, "/etc/nftables.conf")).decode()
        firewall_path = self.directory / "nftables.conf"
        firewall_path.write_text(firewall, encoding="utf-8")
        sudo_check = subprocess.run(
            ["sudo", "-n", "true"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if sudo_check.returncode != 0:
            self.skipTest("noninteractive sudo is unavailable")
        namespace_check = subprocess.run(
            ["sudo", "-n", "unshare", "-n", "true"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if namespace_check.returncode != 0:
            self.skipTest("a private privileged network namespace is unavailable")
        invalid_path = self.directory / "invalid-nftables.conf"
        invalid_path.write_text(
            "destroy table inet kiln_router\n"
            "table inet kiln_router { invalid }\n",
            encoding="utf-8",
        )
        before_path = self.directory / "before-nftables.txt"
        after_path = self.directory / "after-nftables.txt"
        script = (
            'nft -f "$1"\n'
            'nft list table inet kiln_router > "$2"\n'
            'if nft -f "$3"; then exit 1; fi\n'
            'nft list table inet kiln_router > "$4"\n'
            'cmp "$2" "$4"\n'
        )
        transaction = subprocess.run(
            [
                "sudo", "-n", "unshare", "-n", "/bin/sh", "-ec", script, "sh",
                str(firewall_path), str(before_path), str(invalid_path), str(after_path),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(transaction.returncode, 0, transaction.stdout + transaction.stderr)

    @staticmethod
    def file_content(cloud_init: str, path: str) -> str:
        lines = cloud_init.splitlines()
        target = f"  - path: {path}"
        start = lines.index(target)
        return next(line.removeprefix("    content: ") for line in lines[start:] if line.startswith("    content: "))


if __name__ == "__main__":
    unittest.main()
