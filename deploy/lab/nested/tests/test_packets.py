from __future__ import annotations

import importlib.util
import shutil
import struct
import subprocess
import unittest
from pathlib import Path


PACKET_PROBE = Path(__file__).resolve().parents[1] / "packet_probe.py"
specification = importlib.util.spec_from_file_location("kiln_packet_probe", PACKET_PROBE)
probe = importlib.util.module_from_spec(specification)
specification.loader.exec_module(probe)


class PacketProbeTests(unittest.TestCase):
    def test_builds_decodable_vlan_ipv4_udp_frame_with_valid_checksum(self):
        frame = probe.build_frame("02:00:00:00:00:01", "02:00:00:00:00:02", "192.0.2.1", "192.0.2.2", 8123, "known-marker", [(probe.TPID_8021Q, 210)])
        self.assertEqual(frame[:6], bytes.fromhex("020000000002"))
        self.assertEqual(frame[6:12], bytes.fromhex("020000000001"))
        self.assertEqual(struct.unpack("!HH", frame[12:16]), (probe.TPID_8021Q, 210))
        self.assertEqual(struct.unpack("!H", frame[16:18])[0], probe.ETHERTYPE_IPV4)
        ipv4 = frame[18:38]
        self.assertEqual(probe._checksum(ipv4), 0)
        self.assertEqual(struct.unpack("!HHHH", frame[38:46]), (49152, 8123, 20, 0))
        self.assertEqual(frame[46:], b"known-marker")

    def test_rejects_more_than_two_tags_and_invalid_vlan(self):
        with self.assertRaises(ValueError):
            probe.build_frame("02:00:00:00:00:01", "02:00:00:00:00:02", "192.0.2.1", "192.0.2.2", 1, "x", [1, 2, 3])
        with self.assertRaises(ValueError):
            probe.build_frame("02:00:00:00:00:01", "02:00:00:00:00:02", "192.0.2.1", "192.0.2.2", 1, "x", [(probe.TPID_8021Q, 4096)])

    @unittest.skipUnless(shutil.which("sudo") and shutil.which("unshare") and shutil.which("ip"), "sudo, unshare, or ip is unavailable")
    def test_raw_sender_delivers_to_a_normal_udp_listener_in_private_network_namespace(self):
        if subprocess.run(["sudo", "-n", "true"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False).returncode:
            self.skipTest("noninteractive sudo is unavailable")
        script = r'''
ip link add sender0 type veth peer name listener0
ip link set sender0 address 02:00:00:00:00:01
ip link set listener0 address 02:00:00:00:00:02
ip link set sender0 up
ip link set listener0 up
ip address add 192.0.2.1/24 dev sender0
ip address add 192.0.2.2/24 dev listener0
sysctl -w net.ipv4.conf.listener0.accept_local=1 >/dev/null
python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("192.0.2.2",8123)); s.settimeout(3); data,_=s.recvfrom(128); raise SystemExit(0 if data == b"packet-positive" else 1)' &
listener=$!
sleep 0.1
python3 "$1" --interface sender0 --source-mac 02:00:00:00:00:01 --destination-mac 02:00:00:00:00:02 --source-ipv4 192.0.2.1 --destination-ipv4 192.0.2.2 --destination-port 8123 --marker packet-positive >/dev/null
wait "$listener"
'''
        result = subprocess.run(["sudo", "-n", "unshare", "-n", "sh", "-ec", script, "sh", str(PACKET_PROBE)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
