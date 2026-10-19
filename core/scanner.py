"""
Network scanner engine for OPorts CLI.
Performs fast subnet discovery, ARP inspection, mDNS resolution, port profiling,
latency (RTT) and OS fingerprinting via TTL.
"""

import concurrent.futures
import ipaddress
import re
import socket
import subprocess
import time
from typing import Dict, List, Optional, Tuple

from .vendors import lookup_vendor, is_private_mac
from . import discovery
import platforms as platform
from .dhcp import get_lease_servers, multiple_servers_on_same_subnet

discover_mdns_deep = discovery.discover_mdns_deep
check_ios_lockdown = discovery.check_ios_lockdown
query_netbios = discovery.query_netbios
query_llmnr_ptr = discovery.query_llmnr_ptr
query_ssdp = discovery.query_ssdp
get_ssdp_description = discovery.get_ssdp_description
probe_ports_fast = discovery.probe_ports_fast
measure_latency_and_ttl = discovery.measure_latency_and_ttl
get_http_banner = discovery.get_http_banner
get_ssh_banner = discovery.get_ssh_banner
PORT_SERVICE_MAP = discovery.PORT_SERVICE_MAP

def get_computer_name():
    return platform.get_computer_name()


def get_default_gateway():
    return platform.get_default_gateway()


def get_active_interfaces():
    return platform.get_active_interfaces()


def get_arp_table(network):
    return platform.get_arp_table(network)


def scan_network(target_interface: Optional[str] = None) -> Tuple[List[Dict], str]:
    """
    Scans the local network and returns an enriched, sorted list of devices.
    """
    interfaces = get_active_interfaces()
    if not interfaces:
        return [], "No active network interfaces found"

    # Select interface
    if target_interface:
        selected_iface = next((i for i in interfaces if i["interface"] == target_interface), None)
        if selected_iface is None:
            raise ValueError("interface {} is not active".format(target_interface))
    else:
        selected_iface = interfaces[0]

    local_ips = {i["ip"]: i for i in interfaces}
    local_macs = {i["mac"].lower(): i for i in interfaces if i["mac"]}
    gateway_ip = get_default_gateway()
    computer_name = get_computer_name()
    dhcp_servers = get_lease_servers(interfaces)
    unusual_dhcp = multiple_servers_on_same_subnet(interfaces, dhcp_servers)

    ip_str = selected_iface["ip"]
    netmask_str = selected_iface["netmask"]
    network = ipaddress.IPv4Network(f"{ip_str}/{netmask_str}", strict=False)
    subnet_label = f"{network.network_address}/{network.prefixlen} ({selected_iface['interface']})"

    # Concurrently ping hosts; each process has a firm deadline because some
    # platforms wait indefinitely on broadcast or ARP resolution.
    all_hosts = [str(h) for h in network.hosts() if str(h) != ip_str][:254]
    def fast_ping(h):
        try:
            subprocess.run(platform.ping_command(h, timeout_ms=150),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.5)
        except (OSError, subprocess.TimeoutExpired):
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=48) as executor:
        list(executor.map(fast_ping, all_hosts))

    # 3. Read ARP cache with flags
    arp_devices = get_arp_table(network)

    # Ensure local interfaces are included
    for iface_info in interfaces:
        lip = iface_info["ip"]
        lmac = iface_info["mac"].lower()
        if lip not in arp_devices and lmac:
            mac_clean = ":".join(f"{int(x, 16):02x}" for x in lmac.split(":"))
            arp_devices[lip] = {
                "ip": lip,
                "mac": mac_clean,
                "iface": iface_info["interface"],
                "is_permanent": True,
                "arp_type": "Static",
                "arp_expires_seconds": None
            }

    # Count occurrences of MACs across the subnet to detect duplicates
    mac_counts = {}
    for entry in arp_devices.values():
        m = entry["mac"]
        mac_counts[m] = mac_counts.get(m, 0) + 1

    # 4. Concurrently run deep mDNS and SSDP discovery
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as discovery_pool:
        mdns_future = discovery_pool.submit(discover_mdns_deep)
        ssdp_future = discovery_pool.submit(query_ssdp, 1.0)

        mdns_ip_map, mdns_mac_map = mdns_future.result()
        ssdp_devices = ssdp_future.result()

    # 5. Enrich each discovered device
    def enrich_device(ip: str) -> Dict:
        data = arp_devices[ip]
        mac = data["mac"]
        is_local = ip in local_ips or mac.lower() in local_macs
        is_gw = (ip == gateway_ip)
        has_dup_mac = (mac_counts.get(mac, 0) > 1)

        vendor = lookup_vendor(mac)
        open_ports = probe_ports_fast(ip)
        has_ios_sync = check_ios_lockdown(ip) if (62078 in open_ports or is_private_mac(mac)) else False
        rtt, ttl, os_guess = measure_latency_and_ttl(ip, open_ports)

        nb_info = query_netbios(ip, timeout=0.25) if not is_local and not is_gw else None
        llmnr_name = query_llmnr_ptr(ip) if not is_local and not is_gw and not nb_info and ip not in mdns_ip_map and mac.lower() not in mdns_mac_map else None
        ssdp_info = get_ssdp_description(ip, ssdp_devices[ip].get("location", "")) if ip in ssdp_devices else {}

        # Name resolution hierarchy:
        # 1. Local machine
        # 2. Gateway router
        # 3. mDNS name by IP or MAC
        # 4. NetBIOS name (if port 137 or Windows)
        # 5. iOS Lockdown detection
        # 6. Port/Service fingerprint
        name = ""
        service_notes = []

        if has_dup_mac and not is_local:
            service_notes.append("[!] Duplicate MAC")
        if ip in dhcp_servers.values():
            service_notes.append("DHCP server (accepted lease)")
        if ip in unusual_dhcp.get(str(network), []):
            service_notes.append("[!] Multiple DHCP servers in local leases")

        if is_local:
            iface_used = local_ips.get(ip, {}).get("interface", data["iface"])
            name = f"This Computer ({computer_name})"
            service_notes.append(f"Current host ({iface_used}, {data['arp_type'].lower()})")
        elif is_gw:
            name = "Router / Gateway"
            if 80 in open_ports or 443 in open_ports:
                service_notes.append("Web Admin Panel")
            else:
                service_notes.append("Gateway")
        else:
            # Check mDNS
            if ip in mdns_ip_map:
                name = mdns_ip_map[ip]
            elif mac.lower() in mdns_mac_map:
                name = mdns_mac_map[mac.lower()]
            elif nb_info and nb_info.get("computer_name"):
                name = nb_info["computer_name"]
                if nb_info.get("workgroup"):
                    service_notes.append("Workgroup: {}".format(nb_info["workgroup"]))
            elif llmnr_name:
                name = llmnr_name
            elif ssdp_info.get("friendlyName") or ssdp_info.get("modelName"):
                name = ssdp_info.get("friendlyName") or ssdp_info["modelName"]
            elif 3389 in open_ports or 445 in open_ports or 139 in open_ports:
                name = f"PC {vendor} (Windows)" if vendor != "Unknown" else "Windows PC"
                service_notes.append("Windows sharing / RDP")
            elif has_ios_sync or 62078 in open_ports:
                name = "Apple iPhone / iPad"
                vendor = "Apple (iOS-Sync)"
                service_notes.append("iOS Lockdown :62078")
            elif 22 in open_ports:
                name = f"Linux / Unix Server ({vendor})" if vendor != "Unknown" else "Linux Server"
                service_notes.append("SSH :22")
            elif 80 in open_ports or 443 in open_ports:
                name = f"{vendor} Device" if vendor != "Unknown" else "Web Server"
                service_notes.append("Web :80/443")
            elif is_private_mac(mac):
                name = "Mobile Device (iOS / Android)"
                service_notes.append("Private MAC")
            else:
                name = f"{vendor} Device" if vendor != "Unknown" else "Network Device"

        if ip in ssdp_devices:
            server = ssdp_devices[ip].get("server", "")
            if server:
                service_notes.append("UPnP: {}".format(server[:60]))
            if ssdp_info.get("modelName"):
                service_notes.append("Model: {}".format(ssdp_info["modelName"]))

        # Format open ports badge if any
        port_badges = []
        for p in open_ports:
            if p in PORT_SERVICE_MAP and p != 62078:
                port_badges.append(str(p))
        if port_badges:
            service_notes.append(f"Ports: {','.join(port_badges[:3])}")

        # Add OS / TTL note if available
        if ttl is not None:
            if ttl == 254 or ttl == 255:
                service_notes.append(f"TTL: ~255 (Net)")
            elif ttl <= 64:
                service_notes.append(f"TTL: ~64 (UNIX/iOS)")
            elif ttl <= 128:
                service_notes.append(f"TTL: ~128 (Win)")

        # Add interface
        service_notes.append(f"[{data['iface']}]")

        notes_str = " | ".join(service_notes) if service_notes else "Active"

        return {
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "name": name,
            "notes": notes_str,
            "rtt": rtt,
            "ttl": ttl,
            "os_guess": os_guess,
            "is_local": is_local,
            "is_gateway": is_gw,
            "has_dup_mac": has_dup_mac,
            "interface": data["iface"],
            "arp_type": data["arp_type"],
            "arp_expires_seconds": data.get("arp_expires_seconds"),
            "open_ports": open_ports,
            "ios_sync": has_ios_sync,
            "netbios": nb_info,
            "llmnr": llmnr_name,
            "ssdp": ssdp_info
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(enrich_device, arp_devices.keys()))

    devices = sorted(results, key=lambda d: ipaddress.IPv4Address(d["ip"]))
    return devices, subnet_label

def inspect_host(target_ip: str, progress=None) -> Dict:
    """
    Performs an in-depth forensic inspection of a single target IP.
    Returns full port status, HTTP title, SSH banners, NetBIOS name, RTT jitter, and OS fingerprint.
    """
    gateway_ip = get_default_gateway()
    # Read the platform's neighbour cache for this host.
    mac, iface, arp_type, arp_expires_seconds = "Unknown", "Unknown", "Unknown", None
    network = ipaddress.IPv4Network(target_ip + "/32")
    entry = get_arp_table(network).get(target_ip)
    if entry:
        mac = entry["mac"]
        iface = entry["iface"]
        arp_type = entry["arp_type"]
        arp_expires_seconds = entry.get("arp_expires_seconds")

    vendor = lookup_vendor(mac) if mac != "Unknown" else "Unknown"

    # Ping 3 times to compute min/avg/max/jitter
    rtts = []
    ttl = None
    try:
        ping_res = subprocess.run(platform.ping_command(target_ip, count=3, timeout_ms=300),
                                  capture_output=True, text=True, timeout=2)
        for line in ping_res.stdout.splitlines():
            m_time = re.search(r"time=(\d+\.?\d*)\s*ms", line)
            m_ttl = re.search(r"ttl=(\d+)", line)
            if m_time:
                rtts.append(float(m_time.group(1)))
            if m_ttl and not ttl:
                ttl = int(m_ttl.group(1))
    except Exception:
        pass

    # Scan top 25 ports
    ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 548, 993, 3306, 3389, 5000, 5353, 5900, 8000, 8080, 8443, 62078]
    open_ports = probe_ports_fast(target_ip, ports_to_scan, on_progress=progress)

    # Measure connect latency if ping failed
    if not rtts and open_ports:
        for _ in range(3):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            t0 = time.time()
            try:
                if s.connect_ex((target_ip, open_ports[0])) == 0:
                    rtts.append(round((time.time() - t0) * 1000.0, 2))
            except Exception:
                pass
            finally:
                s.close()

    # Banners
    web_results = [get_http_banner(target_ip, port) for port in (80, 443, 8080) if port in open_ports]
    http_info = next((item for item in web_results if item.get("title") or item.get("server")), web_results[0] if web_results else {})
    ssh_banner = get_ssh_banner(target_ip, 22) if 22 in open_ports else ""
    netbios_info = query_netbios(target_ip)
    llmnr_name = query_llmnr_ptr(target_ip) if not netbios_info else None
    ios_sync = check_ios_lockdown(target_ip)

    # OS Guessing
    if ios_sync:
        os_detected = "Apple iOS / iPadOS (Lockdown Wi-Fi Sync)"
    elif ttl == 254 or ttl == 255:
        os_detected = "Network Appliance (Router / Managed Switch)"
    elif ttl and ttl <= 64:
        os_detected = "Apple macOS / iOS / Linux / Android"
    elif ttl and ttl <= 128:
        os_detected = "Microsoft Windows"
    elif 3389 in open_ports:
        os_detected = "Microsoft Windows (RDP enabled)"
    else:
        os_detected = "Unknown / Generic OS"

    return {
        "ip": target_ip,
        "mac": mac,
        "vendor": vendor,
        "iface": iface,
        "arp_type": arp_type,
        "arp_expires_seconds": arp_expires_seconds,
        "is_gateway": (target_ip == gateway_ip),
        "rtts": rtts,
        "ttl": ttl,
        "os_detected": os_detected,
        "open_ports": open_ports,
        "http_info": http_info,
        "ssh_banner": ssh_banner,
        "netbios_info": netbios_info,
        "llmnr_name": llmnr_name,
        "ios_sync": ios_sync
    }
