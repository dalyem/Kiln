#!/usr/bin/env python3
"""Send one caller-specified Ethernet/IPv4/UDP frame for a lab packet probe."""

import argparse
import hashlib
import ipaddress
import json
import socket
import struct
import sys


ETHERTYPE_IPV4 = 0x0800
TPID_8021Q = 0x8100
TPID_8021AD = 0x88A8


def _mac(value):
    parts = value.split(":")
    if len(parts) != 6:
        raise ValueError("MAC address must have six octets")
    try:
        result = bytes(int(part, 16) for part in parts)
    except ValueError as error:
        raise ValueError("MAC address is invalid") from error
    if len(result) != 6:
        raise ValueError("MAC address is invalid")
    return result


def _ipv4(value):
    parsed = ipaddress.ip_address(value)
    if not isinstance(parsed, ipaddress.IPv4Address):
        raise ValueError("address must be IPv4")
    return parsed.packed


def _checksum(payload):
    if len(payload) % 2:
        payload += b"\0"
    total = sum(struct.unpack(f"!{len(payload) // 2}H", payload))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _tags(tags):
    if len(tags) > 2:
        raise ValueError("at most two VLAN tags are allowed")
    result = []
    for tag in tags:
        if isinstance(tag, int):
            tpid, vlan = TPID_8021Q, tag
        elif isinstance(tag, tuple) and len(tag) == 2:
            tpid, vlan = tag
        else:
            raise ValueError("VLAN tag is invalid")
        if tpid not in {TPID_8021Q, TPID_8021AD} or not isinstance(vlan, int) or not 0 <= vlan <= 4095:
            raise ValueError("VLAN tag is invalid")
        result.append((tpid, vlan))
    return result


def build_frame(source_mac, destination_mac, source_ipv4, destination_ipv4, destination_port, marker, vlan_tags=(), source_port=49152):
    """Build one Ethernet frame. UDP's IPv4 checksum field is deliberately zero."""
    if not isinstance(destination_port, int) or not 1 <= destination_port <= 65535 or not isinstance(source_port, int) or not 1 <= source_port <= 65535:
        raise ValueError("UDP ports must be from 1 through 65535")
    payload = marker.encode("utf-8") if isinstance(marker, str) else marker
    if not isinstance(payload, bytes) or not payload or len(payload) > 65000:
        raise ValueError("marker must encode to 1 through 65000 bytes")
    udp = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload
    source, destination = _ipv4(source_ipv4), _ipv4(destination_ipv4)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0x4B4C, 0, 64, socket.IPPROTO_UDP, 0, source, destination)
    ipv4 = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
    ethernet = _mac(destination_mac) + _mac(source_mac)
    for tpid, vlan in _tags(vlan_tags):
        ethernet += struct.pack("!HH", tpid, vlan)
    return ethernet + struct.pack("!H", ETHERTYPE_IPV4) + ipv4 + udp


def _parse_tag(value):
    if ":" in value:
        style, text = value.split(":", 1)
        if style != "802.1ad":
            raise argparse.ArgumentTypeError("VLAN tag prefix must be 802.1ad")
        tpid = TPID_8021AD
    else:
        text, tpid = value, TPID_8021Q
    try:
        vlan = int(text, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("VLAN ID must be an integer") from error
    try:
        return _tags([(tpid, vlan)])[0]
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--source-mac", required=True)
    parser.add_argument("--destination-mac", required=True)
    parser.add_argument("--source-ipv4", required=True)
    parser.add_argument("--destination-ipv4", required=True)
    parser.add_argument("--destination-port", required=True, type=int)
    parser.add_argument("--source-port", type=int, default=49152)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--vlan", action="append", default=[], type=_parse_tag)
    arguments = parser.parse_args()
    try:
        frame = build_frame(arguments.source_mac, arguments.destination_mac, arguments.source_ipv4, arguments.destination_ipv4, arguments.destination_port, arguments.marker, arguments.vlan, arguments.source_port)
        protocol = socket.htons(0x0003)  # ETH_P_ALL; the frame itself carries IPv4.
        raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, protocol)
        raw.bind((arguments.interface, 0))
        raw.sendto(frame, (arguments.interface, 0))
    except (OSError, ValueError) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 2
    print(json.dumps({"marker": arguments.marker, "frame_sha256": hashlib.sha256(frame).hexdigest()}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
