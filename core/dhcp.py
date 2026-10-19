"""Inspect the DHCP leases already accepted by this Mac."""

import ipaddress
import platforms


def get_lease_servers(interfaces):
    """Return interface -> DHCP server IP from the active platform."""
    return platforms.get_lease_servers(interfaces)


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
