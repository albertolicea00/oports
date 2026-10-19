"""macOS network and process inspection."""

import ipaddress
import re
import socket
import subprocess


def get_computer_name():
    try:
        result = subprocess.run(["scutil", "--get", "ComputerName"], capture_output=True, text=True, timeout=1)
        if result.stdout.strip():
            return result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return socket.gethostname()


def get_default_gateway():
    try:
        result = subprocess.run(["netstat", "-rn"], capture_output=True, text=True, timeout=2)
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "default":
                try:
                    return str(ipaddress.IPv4Address(parts[1]))
                except ValueError:
                    continue
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def get_active_interfaces():
    interfaces = []
    try:
        result = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        return interfaces
    blocks = {}
    name = None
    for line in result.stdout.splitlines():
        if line and not line[0].isspace() and ":" in line:
            name = line.split(":", 1)[0]
            blocks[name] = []
        elif name:
            blocks[name].append(line.strip())
    for name, lines in blocks.items():
        if name.startswith(("lo", "utun", "bridge")):
            continue
        ip = netmask = broadcast = mac = ""
        for line in lines:
            parts = line.split()
            if line.startswith("ether ") and len(parts) > 1:
                mac = parts[1]
            elif line.startswith("inet ") and len(parts) > 1:
                ip = parts[1]
                if "netmask" in parts:
                    try:
                        netmask = str(ipaddress.IPv4Address(int(parts[parts.index("netmask") + 1], 16)))
                    except (ValueError, IndexError):
                        pass
                if "broadcast" in parts:
                    broadcast = parts[parts.index("broadcast") + 1]
        if ip and not ip.startswith("127."):
            interfaces.append({"interface": name, "ip": ip, "netmask": netmask or "255.255.255.0",
                               "broadcast": broadcast, "mac": mac})
    return interfaces


def get_arp_table(network):
    entries = {}
    try:
        result = subprocess.run(["arp", "-an"], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return entries
    for line in result.stdout.splitlines():
        match = re.search(r"\(([\d.]+)\) at ([0-9a-fA-F:]+) on (\S+)", line)
        if not match:
            continue
        ip, mac, iface = match.groups()
        try:
            if ipaddress.IPv4Address(ip) not in network:
                continue
            mac = ":".join("{:02x}".format(int(part, 16)) for part in mac.split(":"))
        except ValueError:
            continue
        if mac == "ff:ff:ff:ff:ff:ff" or ipaddress.IPv4Address(ip) == network.broadcast_address:
            continue
        permanent = "permanent" in line.lower()
        expiry = re.search(r"expires? in (\d+) seconds?", line, re.IGNORECASE)
        entries[ip] = {"ip": ip, "mac": mac, "iface": iface, "is_permanent": permanent,
                       "arp_type": "Static" if permanent else "Dynamic",
                       "arp_expires_seconds": int(expiry.group(1)) if expiry else None}
    return entries


def ping_command(ip, count=1, timeout_ms=200):
    return ["ping", "-c", str(count), "-W", str(timeout_ms), ip]


def _lsof(state):
    try:
        result = subprocess.run(["lsof", "-nP", "-iTCP", "-sTCP:" + state, "-Fpcn"],
                                capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return []
    rows = []
    pid = name = ""
    for line in result.stdout.splitlines():
        if line.startswith("p"):
            pid, name = line[1:], ""
        elif line.startswith("c"):
            name = line[1:]
        elif line.startswith("n") and pid.isdigit():
            address = line[1:]
            port = address.rsplit(":", 1)[-1]
            if state == "LISTEN" and port.isdigit():
                rows.append({"pid": int(pid), "process": name, "address": address, "port": int(port)})
            elif state == "ESTABLISHED":
                rows.append({"pid": int(pid), "process": name, "connection": address})
    return rows


def get_local_ports():
    return sorted(_lsof("LISTEN"), key=lambda row: (row["port"], row["pid"], row["address"]))


def get_active_connections():
    return _lsof("ESTABLISHED")


def get_lease_servers(interfaces):
    servers = {}
    for item in interfaces:
        try:
            result = subprocess.run(["ipconfig", "getpacket", item["interface"]],
                                    capture_output=True, text=True, timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            continue
        match = re.search(r"^server_identifier \(ip\):\s*(\S+)", result.stdout, re.MULTILINE)
        if match:
            try:
                servers[item["interface"]] = str(ipaddress.IPv4Address(match.group(1)))
            except ValueError:
                pass
    return servers
