"""Operating system services consumed by every OPorts interface."""

import sys

if sys.platform == "darwin":
    from . import macos as current
elif sys.platform == "win32":
    from . import windows as current
else:
    from . import posix as current


def get_computer_name():
    return current.get_computer_name()


def get_default_gateway():
    return current.get_default_gateway()


def get_active_interfaces():
    return current.get_active_interfaces()


def get_arp_table(network):
    return current.get_arp_table(network)


def ping_command(ip, count=1, timeout_ms=200):
    return current.ping_command(ip, count, timeout_ms)


def get_local_ports():
    return current.get_local_ports()


def get_active_connections():
    return current.get_active_connections()


def get_lease_servers(interfaces):
    return current.get_lease_servers(interfaces)
