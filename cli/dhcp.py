"""Inspect the DHCP leases already accepted by this Mac."""

import ipaddress
import re
import subprocess


def get_lease_servers(interfaces):
    """Return interface -> server IP from macOS ipconfig getpacket."""
    servers = {}
    for item in interfaces:
        interface = item["interface"]
        try:
            result = subprocess.run(["ipconfig", "getpacket", interface],
                                    capture_output=True, text=True, timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            continue
        match = re.search(r"^server_identifier \(ip\):\s*(\S+)", result.stdout, re.MULTILINE)
        if match:
            try:
                servers[interface] = str(ipaddress.IPv4Address(match.group(1)))
            except ValueError:
                pass
    return servers


def multiple_servers_on_same_subnet(interfaces, servers):
    """Find subnets where local interfaces accepted leases from different servers."""
    by_subnet = {}
    for item in interfaces:
        server = servers.get(item["interface"])
        if not server:
            continue
        subnet = str(ipaddress.IPv4Network("{}/{}".format(item["ip"], item["netmask"]), strict=False))
        by_subnet.setdefault(subnet, set()).add(server)
    return {subnet: sorted(values) for subnet, values in by_subnet.items() if len(values) > 1}
