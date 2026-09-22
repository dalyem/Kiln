#!/usr/bin/env python3
"""Render private NoCloud seeds for the disposable nested-network probe."""

from __future__ import annotations

import argparse
import base64
import ipaddress
import os
import re
import stat
import sys
import tempfile
import tomllib
from pathlib import Path
from string import Template
from typing import Any


NESTED_DIRECTORY = Path(__file__).resolve().parent
REPOSITORY_ROOT = NESTED_DIRECTORY.parents[2]
TEMPLATE_DIRECTORY = NESTED_DIRECTORY / "templates"
MAC = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
KEY_TYPES = frozenset({"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"})

GATEWAY_WAN = ipaddress.IPv4Interface("10.250.103.30/24")
GATEWAY_DEFAULT = ipaddress.IPv4Address("10.250.103.1")
UPSTREAM_DNS = (ipaddress.IPv4Address("1.1.1.1"), ipaddress.IPv4Address("9.9.9.9"))
PROBE_NETWORKS = {
    "probe_a": (210, ipaddress.IPv4Interface("10.242.0.1/28"), ipaddress.IPv4Address("10.242.0.2"), "bc:24:11:20:01:00"),
    "probe_b": (211, ipaddress.IPv4Interface("10.242.0.17/28"), ipaddress.IPv4Address("10.242.0.18"), "bc:24:11:20:02:00"),
}
PROTECTED_IPV4 = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)


class ConfigurationError(ValueError):
    pass


def require(mapping: dict[str, Any], key: str) -> Any:
    value = mapping.get(key)
    if value is None:
        raise ConfigurationError(f"missing required field: {key}")
    return value


def text(mapping: dict[str, Any], key: str, pattern: re.Pattern[str] = NAME) -> str:
    value = require(mapping, key)
    if not isinstance(value, str) or "\n" in value or "\r" in value or not pattern.fullmatch(value):
        raise ConfigurationError(f"{key} has an invalid value")
    return value


def integer(mapping: dict[str, Any], key: str) -> int:
    value = require(mapping, key)
    if isinstance(value, bool) or not isinstance(value, int) or not 100 <= value <= 999_999_999:
        raise ConfigurationError(f"{key} must be a VM ID")
    return value


def mac(mapping: dict[str, Any], key: str) -> str:
    value = text(mapping, key, MAC)
    return value.lower()


def public_key(path_value: str) -> str:
    try:
        content = Path(path_value).expanduser().read_text(encoding="utf-8").strip()
    except OSError as error:
        raise ConfigurationError("cannot read ssh_public_key_file") from error
    if "\n" in content or "\r" in content:
        raise ConfigurationError("ssh_public_key_file must contain one OpenSSH public key")
    fields = content.split(maxsplit=2)
    if len(fields) < 2 or fields[0] not in KEY_TYPES:
        raise ConfigurationError("ssh_public_key_file must contain one OpenSSH public key")
    try:
        decoded = base64.b64decode(fields[1] + "=" * (-len(fields[1]) % 4), validate=True)
    except ValueError as error:
        raise ConfigurationError("ssh_public_key_file must contain one OpenSSH public key") from error
    if not decoded:
        raise ConfigurationError("ssh_public_key_file must contain one OpenSSH public key")
    return content


def boolean(mapping: dict[str, Any], key: str) -> bool:
    value = require(mapping, key)
    if not isinstance(value, bool):
        raise ConfigurationError(f"{key} must be true or false")
    return value


def template(name: str, values: dict[str, str]) -> str:
    return Template((TEMPLATE_DIRECTORY / name).read_text(encoding="utf-8")).substitute(values)


def yaml_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def encoded_files(files: list[tuple[str, str, str]]) -> str:
    return "\n".join(
        f"  - path: {path}\n    permissions: '{mode}'\n    encoding: b64\n    content: {base64.b64encode(content.encode()).decode()}"
        for path, content, mode in files
    )


def validate(config: dict[str, Any]) -> dict[str, Any]:
    gateway = require(config, "gateway")
    probes = require(config, "probes")
    if not isinstance(gateway, dict) or not isinstance(probes, dict):
        raise ConfigurationError("gateway and probes must be TOML tables")
    values: dict[str, Any] = {
        "public_key": public_key(text(gateway, "ssh_public_key_file", re.compile(r"^.+$"))),
        "gateway_vmid": integer(gateway, "vmid"),
        "gateway_hostname": text(gateway, "hostname"),
        "gateway_instance_id": text(gateway, "instance_id"),
        "gateway_wan_mac": mac(gateway, "wan_mac"),
        "gateway_trunk_mac": mac(gateway, "trunk_mac"),
        "probe_http": boolean(probes, "enable_http_test"),
    }
    if values["gateway_vmid"] != 100:
        raise ConfigurationError("gateway.vmid must be 100 for the disposable nested lab topology")
    if values["gateway_wan_mac"] != "bc:24:11:20:00:00" or values["gateway_trunk_mac"] != "bc:24:11:20:00:01":
        raise ConfigurationError("gateway MACs must match the disposable nested lab topology")
    for name, (_, _, _, expected_mac) in PROBE_NETWORKS.items():
        probe = require(config, name)
        if not isinstance(probe, dict):
            raise ConfigurationError(f"{name} must be a TOML table")
        values[f"{name}_vmid"] = integer(probe, "vmid")
        if values[f"{name}_vmid"] != {"probe_a": 101, "probe_b": 102}[name]:
            raise ConfigurationError(f"{name}.vmid must match the disposable nested lab topology")
        values[f"{name}_hostname"] = text(probe, "hostname")
        values[f"{name}_instance_id"] = text(probe, "instance_id")
        actual_mac = mac(probe, "mac")
        if actual_mac != expected_mac:
            raise ConfigurationError(f"{name}.mac must match the disposable nested lab topology")
        values[f"{name}_mac"] = actual_mac
    vmids = [values["gateway_vmid"], values["probe_a_vmid"], values["probe_b_vmid"]]
    if len(set(vmids)) != len(vmids):
        raise ConfigurationError("fixture VM IDs must be unique")
    return values


def gateway_user_data(values: dict[str, Any]) -> str:
    leases = []
    for name, (vlan, interface, client, _) in PROBE_NETWORKS.items():
        leases.append({"name": name, "vlan": str(vlan), "interface": interface, "client": client})
    firewall = template(
        "gateway-nftables.conf.tmpl",
        {
            "LEASE_A_INTERFACE": "lease210", "LEASE_A_CLIENT": str(leases[0]["client"]),
            "LEASE_B_INTERFACE": "lease211", "LEASE_B_CLIENT": str(leases[1]["client"]),
            "UPSTREAM_DNS": ", ".join(str(address) for address in UPSTREAM_DNS),
            "PROTECTED_IPV4": ", ".join(PROTECTED_IPV4),
            "FIXTURE_SSH_SOURCE": "10.250.103.10",
        },
    )
    lan_service = template(
        "gateway-lan.service.tmpl",
        {
            "TRUNK": "trunk0", "LEASE_A_INTERFACE": "lease210", "LEASE_A_VLAN": "210", "LEASE_A_ADDRESS": str(leases[0]["interface"]),
            "LEASE_B_INTERFACE": "lease211", "LEASE_B_VLAN": "211", "LEASE_B_ADDRESS": str(leases[1]["interface"]),
        },
    )
    dnsmasq = template(
        "gateway-dnsmasq.conf.tmpl",
        {
            "LEASE_A_INTERFACE": "lease210", "LEASE_A_NETWORK": "10.242.0.0", "LEASE_A_NETMASK": "255.255.255.240", "LEASE_A_ROUTER": str(leases[0]["interface"].ip), "LEASE_A_CLIENT_MAC": PROBE_NETWORKS["probe_a"][3], "LEASE_A_CLIENT": str(leases[0]["client"]),
            "LEASE_B_INTERFACE": "lease211", "LEASE_B_NETWORK": "10.242.0.16", "LEASE_B_NETMASK": "255.255.255.240", "LEASE_B_ROUTER": str(leases[1]["interface"].ip), "LEASE_B_CLIENT_MAC": PROBE_NETWORKS["probe_b"][3], "LEASE_B_CLIENT": str(leases[1]["client"]),
            "UPSTREAM_DNS": "\n".join(f"server={address}" for address in UPSTREAM_DNS),
        },
    )
    files = [
        ("/etc/nftables.conf", firewall, "0600"),
        ("/usr/local/sbin/kiln-nested-load-firewall", template("gateway-load-firewall.tmpl", {}), "0700"),
        ("/usr/local/sbin/kiln-nested-fail-closed", template("gateway-fail-closed.tmpl", {}), "0700"),
        ("/etc/sysctl.d/90-kiln-nested.conf", template("gateway-sysctl.conf.tmpl", {}), "0644"),
        ("/etc/systemd/system/kiln-nested-firewall.service", template("gateway-firewall.service.tmpl", {}), "0644"),
        ("/etc/systemd/system/kiln-nested-fail-closed.service", template("gateway-fail-closed.service.tmpl", {}), "0644"),
        ("/etc/systemd/system/kiln-nested-lan.service", lan_service, "0644"),
        ("/etc/dnsmasq.d/kiln-nested.conf", dnsmasq, "0644"),
        ("/etc/systemd/system/dnsmasq.service.d/kiln-nested.conf", template("gateway-dnsmasq.service.tmpl", {}), "0644"),
        ("/etc/ssh/sshd_config.d/60-kiln-nested.conf", template("gateway-sshd.conf.tmpl", {}), "0644"),
    ]
    return template("gateway-user-data.yaml.tmpl", {"HOSTNAME": values["gateway_hostname"], "PUBLIC_KEY": yaml_quote(values["public_key"]), "WRITE_FILES": encoded_files(files)})


def gateway_network_config(values: dict[str, Any]) -> str:
    return template("gateway-network-config.yaml.tmpl", {"WAN_MAC": values["gateway_wan_mac"], "TRUNK_MAC": values["gateway_trunk_mac"]})


def probe_user_data(values: dict[str, Any], name: str) -> str:
    http_file = ""
    http_command = "/usr/bin/true"
    if values["probe_http"]:
        http_file = "  - path: /var/lib/kiln-probe/index.html\n    permissions: '0644'\n    content: nested-network-probe\n"
        http_command = "/usr/bin/python3 -m http.server 8080 --directory /var/lib/kiln-probe"
    service = template("probe-http.service.tmpl", {"HTTP_COMMAND": http_command})
    files = [("/etc/systemd/system/kiln-probe-http.service", service, "0644")]
    rendered_files = encoded_files(files)
    if http_file:
        rendered_files = http_file + rendered_files
    http_runcmd = "  - [systemctl, enable, kiln-probe-http.service]\n  - [systemctl, restart, kiln-probe-http.service]" if values["probe_http"] else ""
    return template("probe-user-data.yaml.tmpl", {"HOSTNAME": values[f"{name}_hostname"], "PUBLIC_KEY": yaml_quote(values["public_key"]), "WRITE_FILES": rendered_files, "HTTP_RUNCMD": http_runcmd})


def probe_network_config(values: dict[str, Any], name: str) -> str:
    return template("probe-network-config.yaml.tmpl", {"MAC": values[f"{name}_mac"]})


def meta_data(values: dict[str, Any], name: str) -> str:
    return template("meta-data.yaml.tmpl", {"HOSTNAME": values[f"{name}_hostname"], "INSTANCE_ID": values[f"{name}_instance_id"]})


def manifest(values: dict[str, Any]) -> str:
    return template("fixture-manifest.toml.tmpl", {key.upper(): str(value) for key, value in values.items() if key != "public_key"} | {"GATEWAY_WAN": str(GATEWAY_WAN), "GATEWAY_DEFAULT": str(GATEWAY_DEFAULT)})


def secure_output_directory(output_directory: Path) -> Path:
    absolute = output_directory.expanduser().resolve()
    if absolute.is_relative_to(REPOSITORY_ROOT):
        raise ConfigurationError("output directory must be outside the repository")
    absolute.mkdir(mode=0o700, parents=True, exist_ok=True)
    details = absolute.stat()
    if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o077:
        raise ConfigurationError("output directory must be private and owned by the current user")
    return absolute


def write_private(path: Path, content: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(content)
        os.replace(temporary_name, path)
    except BaseException:
        Path(temporary_name).unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        with arguments.config.open("rb") as source:
            values = validate(tomllib.load(source))
        output = secure_output_directory(arguments.output_dir)
        gateway = output / "gateway"
        write_private(gateway / "user-data", gateway_user_data(values))
        write_private(gateway / "network-config", gateway_network_config(values))
        write_private(gateway / "meta-data", meta_data(values, "gateway"))
        for name in PROBE_NETWORKS:
            target = output / name
            write_private(target / "user-data", probe_user_data(values, name))
            write_private(target / "network-config", probe_network_config(values, name))
            write_private(target / "meta-data", meta_data(values, name))
        write_private(output / "fixture-manifest.toml", manifest(values))
    except (ConfigurationError, OSError, tomllib.TOMLDecodeError) as error:
        print(f"render failed: {error}", file=sys.stderr)
        return 2
    print(f"rendered private nested probe seeds in {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
