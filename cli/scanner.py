"""
Network scanner engine for OPorts CLI.
Performs fast subnet discovery, ARP inspection, mDNS resolution, and port profiling.
"""

import concurrent.futures
import ipaddress
import re
import socket
import subprocess
import time
from typing import Dict, List, Optional, Tuple

from vendors import lookup_vendor, is_private_mac

def get_computer_name() -> str:
    """Gets the friendly name of the local computer (macOS)."""
    try:
        res = subprocess.run(["scutil", "--get", "ComputerName"], capture_output=True, text=True, timeout=1)
        name = res.stdout.strip()
        if name:
            return name
    except Exception:
        pass
    return socket.gethostname()

def get_default_gateway() -> Optional[str]:
    """Finds the default gateway IP address from the routing table."""
    try:
        res = subprocess.run(["netstat", "-rn"], capture_output=True, text=True, timeout=2)
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "default":
                gw = parts[1]
                # Filter out IPv6 and link#
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", gw):
                    return gw
    except Exception:
        pass
    return None

def get_active_interfaces() -> List[Dict[str, str]]:
    """
    Parses ifconfig to find active interfaces with private IPv4 addresses.
    Excludes loopback and point-to-point VPN tunnels.
    """
    interfaces = []
    try:
        res = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=2)
        current_iface = None
        iface_blocks = {}
        for line in res.stdout.splitlines():
            if not line.startswith("\t") and not line.startswith(" ") and ":" in line:
                current_iface = line.split(":")[0]
                iface_blocks[current_iface] = []
            elif current_iface:
                iface_blocks[current_iface].append(line.strip())

        for iface_name, lines in iface_blocks.items():
            # Skip loopback and tunnel interfaces
            if iface_name.startswith("lo") or iface_name.startswith("utun") or iface_name.startswith("bridge"):
                continue

            ip_addr, netmask, broadcast, mac_addr = None, None, None, None
            for line_str in lines:
                if line_str.startswith("ether "):
                    mac_addr = line_str.split()[1]
                if line_str.startswith("inet "):
                    parts = line_str.split()
                    ip_addr = parts[1]
                    if "netmask" in parts:
                        idx = parts.index("netmask")
                        netmask_hex = parts[idx + 1]
                        try:
                            netmask = str(ipaddress.IPv4Address(int(netmask_hex, 16)))
                        except Exception:
                            netmask = "255.255.255.0"
                    if "broadcast" in parts:
                        idx = parts.index("broadcast")
                        broadcast = parts[idx + 1]

            if ip_addr and not ip_addr.startswith("127."):
                interfaces.append({
                    "interface": iface_name,
                    "ip": ip_addr,
                    "netmask": netmask or "255.255.255.0",
                    "broadcast": broadcast or "",
                    "mac": mac_addr or ""
                })
    except Exception:
        pass
    return interfaces

def discover_mdns_names() -> Dict[str, str]:
    """
    Discovers human-readable names announced over mDNS (Bonjour)
    such as iPhones, iPads, MacBooks, Apple TVs, Google Cast, etc.
    """
    mdns_map = {}
    try:
        # Run a short browse for companion-link and smb
        cmd = "dns-sd -B _companion-link._tcp local & PID1=$!; dns-sd -B _smb._tcp local & PID2=$!; sleep 1; kill $PID1 $PID2 2>/dev/null"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=3)
        instances = []
        for line in res.stdout.splitlines():
            if " Add " in line and ("_companion-link._tcp." in line or "_smb._tcp." in line):
                parts = line.split()
                if len(parts) >= 7:
                    instance_name = " ".join(parts[6:]).replace("\\032", " ").strip()
                    if instance_name and instance_name not in instances:
                        instances.append(instance_name)

        # Resolve discovered instances to IP
        for inst in instances:
            try:
                clean_host = inst.replace(" ", "-").replace("’", "").replace("'", "")
                ip_match = socket.gethostbyname(f"{clean_host}.local")
                if ip_match:
                    mdns_map[ip_match] = inst
            except Exception:
                pass
    except Exception:
        pass
    return mdns_map

def probe_ports(ip: str, ports: List[int] = [80, 443, 3389, 22, 445, 53, 8080]) -> List[int]:
    """Probes a selection of common signature ports on a given IP."""
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.15)
        try:
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
        except Exception:
            pass
        finally:
            s.close()
    return open_ports

def scan_network(target_interface: Optional[str] = None) -> Tuple[List[Dict], str]:
    """
    Scans the local network and returns a structured list of devices.
    """
    interfaces = get_active_interfaces()
    if not interfaces:
        return [], "No active network interfaces found"

    # Select interface
    if target_interface:
        selected_iface = next((i for i in interfaces if i["interface"] == target_interface), interfaces[0])
    else:
        selected_iface = interfaces[0]

    local_ips = {i["ip"]: i for i in interfaces}
    local_macs = {i["mac"].lower(): i for i in interfaces if i["mac"]}
    gateway_ip = get_default_gateway()
    computer_name = get_computer_name()

    ip_str = selected_iface["ip"]
    netmask_str = selected_iface["netmask"]
    network = ipaddress.IPv4Network(f"{ip_str}/{netmask_str}", strict=False)
    subnet_label = f"{network.network_address}/{network.prefixlen} ({selected_iface['interface']})"

    # 1. Broadcast ping
    if selected_iface.get("broadcast"):
        subprocess.run(["ping", "-c", "2", selected_iface["broadcast"]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # 2. Concurrent ping sweep
    all_hosts = [str(h) for h in network.hosts() if str(h) != ip_str][:254]
    def fast_ping(h):
        subprocess.run(["ping", "-c", "1", "-W", "150", h], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    with concurrent.futures.ThreadPoolExecutor(max_workers=60) as executor:
        list(executor.map(fast_ping, all_hosts))

    # 3. Read ARP table
    arp_res = subprocess.run(["arp", "-an"], capture_output=True, text=True)
    arp_devices = {}

    for line in arp_res.stdout.splitlines():
        if "(" not in line or ")" not in line or " at " not in line:
            continue
        ip_match = re.search(r"\(([\d\.]+)\)", line)
        if not ip_match:
            continue
        dev_ip = ip_match.group(1)
        
        try:
            if ipaddress.IPv4Address(dev_ip) not in network:
                continue
        except Exception:
            continue

        parts = line.split()
        try:
            at_idx = parts.index("at")
            mac = parts[at_idx + 1].lower()
            iface = parts[at_idx + 3] if len(parts) > at_idx + 3 else ""
        except ValueError:
            continue

        if mac == "(incomplete)" or mac == "ff:ff:ff:ff:ff:ff":
            continue

        # Standardize MAC format
        mac_clean = ":".join(f"{int(x, 16):02x}" for x in mac.split(":"))
        arp_devices[dev_ip] = {
            "ip": dev_ip,
            "mac": mac_clean,
            "iface": iface
        }

    # Ensure local interfaces are in the list
    for iface_info in interfaces:
        lip = iface_info["ip"]
        lmac = iface_info["mac"].lower()
        if lip not in arp_devices and lmac:
            mac_clean = ":".join(f"{int(x, 16):02x}" for x in lmac.split(":"))
            arp_devices[lip] = {
                "ip": lip,
                "mac": mac_clean,
                "iface": iface_info["interface"]
            }

    # 4. Discover mDNS names
    mdns_names = discover_mdns_names()

    # 5. Enrich device information concurrently
    devices = []
    
    def enrich_device(ip: str):
        data = arp_devices[ip]
        mac = data["mac"]
        is_local = ip in local_ips or mac.lower() in local_macs
        is_gw = (ip == gateway_ip)

        vendor = lookup_vendor(mac)
        open_ports = probe_ports(ip)

        name = ""
        notes = ""

        if is_local:
            iface_used = local_ips.get(ip, {}).get("interface", data["iface"])
            name = f"This Mac ({computer_name})"
            notes = f"Current host ({iface_used})"
        elif is_gw:
            name = f"Router / Gateway"
            if 80 in open_ports or 443 in open_ports:
                notes = "Active (Web Admin Panel)"
            else:
                notes = "Active (Gateway)"
        else:
            # Check mDNS name first
            if ip in mdns_names:
                name = mdns_names[ip]
                notes = f"Active ({vendor})"
            elif 3389 in open_ports:
                name = f"PC {vendor} (Windows)" if vendor != "Unknown" else "Windows PC"
                notes = "Active (Remote Desktop / RDP)"
            elif 22 in open_ports:
                name = f"Linux / Unix Server"
                notes = "Active (SSH :22)"
            elif 80 in open_ports or 443 in open_ports:
                name = f"{vendor} Device" if vendor != "Unknown" else "Web Server"
                notes = "Active (HTTP :80/443)"
            elif is_private_mac(mac):
                name = "Mobile Device (iOS / Android)"
                notes = "Active (Private MAC Address)"
            else:
                name = f"{vendor} Device" if vendor != "Unknown" else "Network Device"
                notes = "Active"

        return {
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "name": name,
            "notes": notes,
            "is_local": is_local,
            "is_gateway": is_gw,
            "open_ports": open_ports
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(enrich_device, arp_devices.keys()))

    # Sort devices by IP address
    devices = sorted(results, key=lambda d: ipaddress.IPv4Address(d["ip"]))
    return devices, subnet_label
