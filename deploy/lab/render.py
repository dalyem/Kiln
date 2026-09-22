#!/usr/bin/env python3
"""Render private artifacts for the disposable outer nested-PVE lab."""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import stat
import sys
import tempfile
import tomllib
from pathlib import Path
from string import Template
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE_DIRECTORY = Path(__file__).resolve().parent / "templates"
MAC_PATTERN = re.compile(r"^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$")
NAME_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
FQDN_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
BRIDGE_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
HOST_PORT_PATTERN = re.compile(r"^([^:\s]+):(\d{1,5})$")
REQUIRED_PROTECTED_CIDRS = frozenset(
    {
        "0.0.0.0/8", "10.0.0.0/8", "10.63.99.0/24", "10.63.100.0/24", "10.63.119.0/24", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
        "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
        "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    }
)


class ConfigurationError(ValueError):
    pass


def require(mapping: dict[str, Any], key: str) -> Any:
    value = mapping.get(key)
    if value is None:
        raise ConfigurationError(f"missing required field: {key}")
    return value


def text_field(mapping: dict[str, Any], key: str, pattern: re.Pattern[str] | None = None) -> str:
    value = require(mapping, key)
    if not isinstance(value, str) or not value:
        raise ConfigurationError(f"{key} must be a non-empty string")
    if "\n" in value or "\r" in value:
        raise ConfigurationError(f"{key} must be one line")
    if pattern and not pattern.fullmatch(value):
        raise ConfigurationError(f"{key} has an invalid value")
    return value


def integer_field(mapping: dict[str, Any], key: str, low: int, high: int) -> int:
    value = require(mapping, key)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ConfigurationError(f"{key} must be an integer from {low} through {high}")
    return value


def ipv4_field(mapping: dict[str, Any], key: str) -> ipaddress.IPv4Address:
    value = text_field(mapping, key)
    try:
        return ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise ConfigurationError(f"{key} must be an IPv4 address") from error


def cidr_field(mapping: dict[str, Any], key: str) -> ipaddress.IPv4Network:
    value = text_field(mapping, key)
    try:
        return ipaddress.IPv4Network(value, strict=True)
    except ipaddress.AddressValueError as error:
        raise ConfigurationError(f"{key} must be an IPv4 CIDR") from error


def public_key(path_value: str, label: str) -> str:
    path = Path(path_value).expanduser()
    try:
        content = path.read_text(encoding="utf-8").strip()
    except OSError as error:
        raise ConfigurationError(f"cannot read {label}") from error
    if "\n" in content or "\r" in content:
        raise ConfigurationError(f"{label} must contain one OpenSSH public key")
    fields = content.split(maxsplit=2)
    if len(fields) < 2 or fields[0] not in {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}:
        raise ConfigurationError(f"{label} must contain one OpenSSH public key")
    try:
        decoded = base64.b64decode(fields[1] + "=" * (-len(fields[1]) % 4), validate=True)
    except ValueError as error:
        raise ConfigurationError(f"{label} must contain one OpenSSH public key") from error
    if not decoded:
        raise ConfigurationError(f"{label} must contain one OpenSSH public key")
    return content


def password_hash(path_value: str) -> str:
    path = Path(path_value).expanduser()
    try:
        content = path.read_text(encoding="utf-8").strip()
    except OSError as error:
        raise ConfigurationError("cannot read root_password_hash_file") from error
    if "\n" in content or "\r" in content or not content.startswith("$"):
        raise ConfigurationError("root_password_hash_file must contain one password hash")
    return content


def permitted_host_ports(value: Any, pve_ip: ipaddress.IPv4Address) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ConfigurationError("permit_open must be a non-empty list")
    permitted: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ConfigurationError("permit_open entries must be strings")
        match = HOST_PORT_PATTERN.fullmatch(item)
        if not match:
            raise ConfigurationError("permit_open entries must use address:port")
        host, port_text = match.groups()
        try:
            address = ipaddress.IPv4Address(host)
        except ipaddress.AddressValueError as error:
            raise ConfigurationError("permit_open host must be an IPv4 address") from error
        port = int(port_text)
        if address != pve_ip or not 1 <= port <= 65535:
            raise ConfigurationError("permit_open may only name the lab PVE IPv4 address")
        permitted.append(f"{address}:{port}")
    if len(set(permitted)) != len(permitted):
        raise ConfigurationError("permit_open must not contain duplicates")
    return permitted


def protected_cidrs(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ConfigurationError("protected_ipv4_cidrs must be a non-empty list")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ConfigurationError("protected_ipv4_cidrs entries must be IPv4 CIDRs")
        try:
            result.append(str(ipaddress.IPv4Network(item, strict=True)))
        except ipaddress.AddressValueError as error:
            raise ConfigurationError("protected_ipv4_cidrs entries must be IPv4 CIDRs") from error
    if len(set(result)) != len(result):
        raise ConfigurationError("protected_ipv4_cidrs must not contain duplicates")
    missing = REQUIRED_PROTECTED_CIDRS.difference(result)
    if missing:
        raise ConfigurationError("protected_ipv4_cidrs omits required private, reserved, link-local, or multicast ranges")
    return [str(network) for network in ipaddress.collapse_addresses(ipaddress.IPv4Network(item) for item in result)]


def render_template(name: str, values: dict[str, str]) -> str:
    return Template((TEMPLATE_DIRECTORY / name).read_text(encoding="utf-8")).substitute(values)


def b64(content: str) -> str:
    return base64.b64encode(content.encode("utf-8")).decode("ascii")


def quote_toml(value: str) -> str:
    return json.dumps(value)


def quote_yaml(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def validate_config(config: dict[str, Any]) -> dict[str, Any]:
    router = require(config, "router")
    pve = require(config, "pve")
    if not isinstance(router, dict) or not isinstance(pve, dict):
        raise ConfigurationError("router and pve must be tables")

    lan_cidr = cidr_field(router, "lan_cidr")
    router_lan_ip = ipv4_field(router, "lan_ip")
    pve_ip = ipv4_field(pve, "ip")
    if router_lan_ip not in lan_cidr or pve_ip not in lan_cidr:
        raise ConfigurationError("router.lan_ip and pve.ip must belong to router.lan_cidr")
    if router_lan_ip == pve_ip:
        raise ConfigurationError("router.lan_ip and pve.ip must differ")
    pve_gateway = ipv4_field(pve, "gateway")
    if pve_gateway != router_lan_ip:
        raise ConfigurationError("pve.gateway must equal router.lan_ip")
    pve_dns = ipv4_field(pve, "dns")
    if pve_dns != router_lan_ip:
        raise ConfigurationError("pve.dns must equal router.lan_ip")

    upstream_dns = require(router, "upstream_dns")
    if not isinstance(upstream_dns, list) or len(upstream_dns) != 2:
        raise ConfigurationError("router.upstream_dns must contain exactly two IPv4 addresses")
    upstream_addresses = []
    for item in upstream_dns:
        try:
            address = ipaddress.IPv4Address(item)
        except ipaddress.AddressValueError as error:
            raise ConfigurationError("router.upstream_dns must contain IPv4 addresses") from error
        if address.is_private or address.is_link_local or address.is_multicast or address.is_reserved:
            raise ConfigurationError("router.upstream_dns addresses must be public")
        upstream_addresses.append(str(address))

    validated = {
        "router_vmid": integer_field(router, "vmid", 100, 999999999),
        "router_hostname": text_field(router, "hostname", NAME_PATTERN),
        "router_instance_id": text_field(router, "instance_id", NAME_PATTERN),
        "wan_bridge": text_field(router, "wan_bridge", BRIDGE_PATTERN),
        "wan_vlan": integer_field(router, "wan_vlan", 1, 4094),
        "wan_mac": text_field(router, "wan_mac", MAC_PATTERN),
        "lan_vnet": text_field(router, "lan_vnet", BRIDGE_PATTERN),
        "lan_vlan": integer_field(router, "lan_vlan", 1, 4094),
        "lan_mac": text_field(router, "lan_mac", MAC_PATTERN),
        "lan_ip": str(router_lan_ip),
        "lan_cidr": str(lan_cidr),
        "lan_network": str(lan_cidr.network_address),
        "lan_netmask": str(lan_cidr.netmask),
        "lan_prefix": str(lan_cidr.prefixlen),
        "orchestrator_ip": str(ipv4_field(router, "orchestrator_ip")),
        "upstream_dns": upstream_addresses,
        "protected_ipv4_cidrs": protected_cidrs(require(router, "protected_ipv4_cidrs")),
        "router_public_key": public_key(text_field(router, "ssh_public_key_file"), "router.ssh_public_key_file"),
        "pve_vmid": integer_field(pve, "vmid", 100, 999999999),
        "pve_hostname": text_field(pve, "hostname", FQDN_PATTERN),
        "pve_ip": str(pve_ip),
        "pve_prefix": integer_field(pve, "prefix", 1, 32),
        "pve_gateway": str(pve_gateway),
        "pve_dns": str(pve_dns),
        "pve_mac": text_field(pve, "mac", MAC_PATTERN),
        "pve_public_key": public_key(text_field(pve, "ssh_public_key_file"), "pve.ssh_public_key_file"),
        "root_password_hash": password_hash(text_field(pve, "root_password_hash_file")),
        "pve_disk": text_field(pve, "disk", re.compile(r"^sd[a-z]+$")),
        "pve_country": text_field(pve, "country", re.compile(r"^[a-z]{2}$")),
        "pve_keyboard": text_field(pve, "keyboard", re.compile(r"^[a-z0-9_-]+$")),
        "pve_timezone": text_field(pve, "timezone", re.compile(r"^[A-Za-z0-9_+/-]+$")),
        "pve_mailto": text_field(pve, "mailto", re.compile(r"^[^\s@]+@[^\s@]+$")),
    }
    if validated["pve_prefix"] != lan_cidr.prefixlen:
        raise ConfigurationError("pve.prefix must equal the router LAN CIDR prefix")
    if validated["router_vmid"] == validated["pve_vmid"]:
        raise ConfigurationError("router.vmid and pve.vmid must differ")
    if len({validated["wan_mac"], validated["lan_mac"], validated["pve_mac"]}) != 3:
        raise ConfigurationError("each VM NIC MAC must be unique")
    validated["permit_open"] = permitted_host_ports(require(router, "permit_open"), pve_ip)
    return validated


def router_cloud_init(values: dict[str, Any]) -> str:
    firewall = render_template(
        "nftables.conf.tmpl",
        {
            "LAN_CIDR": values["lan_cidr"],
            "ORCHESTRATOR_IP": values["orchestrator_ip"],
            "PVE_IP": values["pve_ip"],
            "UPSTREAM_DNS": ", ".join(values["upstream_dns"]),
            "PROTECTED_IPV4": ", ".join(values["protected_ipv4_cidrs"]),
            "PERMIT_PORTS": ", ".join(item.rsplit(":", 1)[1] for item in values["permit_open"]),
        },
    )
    sshd = render_template(
        "sshd.conf.tmpl",
        {
            "ORCHESTRATOR_IP": values["orchestrator_ip"],
            "PERMIT_OPEN": " ".join(values["permit_open"]),
        },
    )
    lan_service = render_template(
        "lan.service.tmpl",
        {"LAN_IP": values["lan_ip"], "LAN_PREFIX": values["lan_prefix"]},
    )
    files = [
        ("/etc/nftables.conf", firewall, "0600"),
        ("/usr/local/sbin/kiln-router-load-firewall", render_template("load-firewall.tmpl", {}), "0700"),
        ("/usr/local/sbin/kiln-router-verify", render_template("verify-router.tmpl", {}), "0700"),
        ("/etc/sysctl.d/90-kiln-router.conf", render_template("sysctl.conf.tmpl", {}), "0644"),
        ("/etc/systemd/system/kiln-router-firewall.service", render_template("firewall.service.tmpl", {}), "0644"),
        ("/etc/systemd/system/kiln-router-fail-closed.service", render_template("fail-closed.service.tmpl", {}), "0644"),
        ("/etc/systemd/system/kiln-router-lan.service", lan_service, "0644"),
        ("/etc/dnsmasq.d/kiln-lab.conf", render_template("dnsmasq.conf.tmpl", {"LAN_IP": values["lan_ip"], "LAN_NETWORK": values["lan_network"], "LAN_NETMASK": values["lan_netmask"], "UPSTREAM_DNS": "\n".join(f"server={address}" for address in values["upstream_dns"])}), "0644"),
        ("/etc/systemd/system/dnsmasq.service.d/kiln-lan.conf", "[Unit]\nRequires=kiln-router-lan.service\nAfter=kiln-router-lan.service\n", "0644"),
        ("/etc/ssh/sshd_config.d/60-kiln-lab.conf", sshd, "0644"),
    ]
    write_files = "\n".join(
        f"  - path: {path}\n    permissions: '{mode}'\n    encoding: b64\n    content: {b64(content)}"
        for path, content, mode in files
    )
    return render_template(
        "user-data.yaml.tmpl",
        {
            "HOSTNAME": values["router_hostname"],
            "ROUTER_PUBLIC_KEY": quote_yaml(values["router_public_key"]),
            "WAN_MAC": values["wan_mac"],
            "LAN_MAC": values["lan_mac"],
            "WRITE_FILES": write_files,
        },
    )


def router_network_config(values: dict[str, Any]) -> str:
    return render_template(
        "network-config.yaml.tmpl",
        {
            "WAN_MAC": values["wan_mac"].lower(),
            "LAN_MAC": values["lan_mac"].lower(),
            "UPSTREAM_DNS": ", ".join(values["upstream_dns"]),
        },
    )


def router_meta_data(values: dict[str, Any]) -> str:
    return render_template(
        "meta-data.yaml.tmpl",
        {"HOSTNAME": values["router_hostname"], "INSTANCE_ID": values["router_instance_id"]},
    )


def installer_answer(values: dict[str, Any]) -> str:
    return render_template(
        "answer.toml.tmpl",
        {
            "HOSTNAME": quote_toml(values["pve_hostname"]),
            "COUNTRY": quote_toml(values["pve_country"]),
            "KEYBOARD": quote_toml(values["pve_keyboard"]),
            "MAILTO": quote_toml(values["pve_mailto"]),
            "TIMEZONE": quote_toml(values["pve_timezone"]),
            "ROOT_PASSWORD_HASH": quote_toml(values["root_password_hash"]),
            "PVE_NETWORK_FILTER": quote_toml("enx" + values["pve_mac"].replace(":", "").lower()),
            "PVE_CIDR": quote_toml(f"{values['pve_ip']}/{values['pve_prefix']}"),
            "PVE_GATEWAY": quote_toml(values["pve_gateway"]),
            "PVE_DNS": quote_toml(values["pve_dns"]),
            "PVE_PUBLIC_KEY": quote_toml(values["pve_public_key"]),
            "PVE_DISK": quote_toml(values["pve_disk"]),
        },
    )


def public_manifest(values: dict[str, Any]) -> str:
    return render_template(
        "fixture-manifest.toml.tmpl",
        {key: str(values[key]) for key in values if key not in {"router_public_key", "pve_public_key", "root_password_hash", "permit_open", "upstream_dns"}} | {
            "PERMIT_OPEN": json.dumps(values["permit_open"]),
            "UPSTREAM_DNS": json.dumps(values["upstream_dns"]),
            "PROTECTED_IPV4_CIDRS": json.dumps(values["protected_ipv4_cidrs"]),
        },
    )


def secure_output_directory(output_directory: Path) -> Path:
    absolute = output_directory.expanduser().resolve()
    try:
        absolute.relative_to(REPOSITORY_ROOT)
    except ValueError:
        pass
    else:
        raise ConfigurationError("output directory must be outside the repository")
    absolute.mkdir(mode=0o700, parents=True, exist_ok=True)
    details = absolute.stat()
    if details.st_uid != os.geteuid():
        raise ConfigurationError("output directory must be owned by the current user")
    if stat.S_IMODE(details.st_mode) & 0o077:
        raise ConfigurationError("output directory must not grant group or other access")
    return absolute


def write_private(path: Path, content: str) -> None:
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
        with arguments.config.open("rb") as config_file:
            values = validate_config(tomllib.load(config_file))
        output_directory = secure_output_directory(arguments.output_dir)
        write_private(output_directory / "user-data", router_cloud_init(values))
        write_private(output_directory / "network-config", router_network_config(values))
        write_private(output_directory / "meta-data", router_meta_data(values))
        write_private(output_directory / "pve-103-answer.toml", installer_answer(values))
        write_private(output_directory / "fixture-manifest.toml", public_manifest(values))
    except (ConfigurationError, OSError, tomllib.TOMLDecodeError) as error:
        print(f"render failed: {error}", file=sys.stderr)
        return 2
    print(f"rendered private lab artifacts in {output_directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
