"""
Advanced network discovery and protocol profiling for OPorts CLI.
Includes:
- mDNS / Bonjour (Apple Mobile Devices, AirPlay, Companion-Link, Google Cast, Printers)
- iOS Lockdown Wi-Fi Sync detection (TCP 62078)
- NetBIOS Node Status (UDP 137) and LLMNR reverse lookup (TCP 5355)
- SSDP / UPnP device announcement (UDP 1900)
- HTTP/HTTPS banner & title grabber (Ports 80, 443, 8080)
- SSH banner grabber (Port 22)
- ICMP / TCP Latency (RTT) and TTL measurement
"""

import concurrent.futures
import ipaddress
import re
import shlex
import socket
import sys
import struct
import subprocess
import time
import urllib.request
import urllib.parse
import ssl
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

import platforms

KEY_PORTS = [21, 22, 53, 80, 135, 139, 443, 445, 3389, 5000, 5353, 62078, 8000, 8080, 8443]

PORT_SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    53: "DNS",
    80: "HTTP",
    135: "RPC",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    5000: "UPnP/Flask",
    5353: "mDNS",
    62078: "iOS-Sync",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt"
}

def check_ios_lockdown(ip: str, timeout: float = 0.25) -> bool:
    """
    Checks if TCP port 62078 (iphone-sync / lockdown) is open.
    Apple iOS and iPadOS devices with Wi-Fi sync have this port open.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, 62078)) == 0
    except Exception:
        return False
    finally:
        s.close()

def query_netbios(ip: str, timeout: float = 0.5) -> Optional[Dict[str, str]]:
    """
    Queries NetBIOS Node Status (UDP port 137) to discover Windows machine names and workgroups.
    """
    query = (
        b"\x13\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
        b"\x00\x21\x00\x01"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (ip, 137))
        data, _ = sock.recvfrom(1024)
        if len(data) < 12 or data[:2] != query[:2] or not (data[2] & 0x80):
            return None

        def skip_name(offset):
            while offset < len(data):
                size = data[offset]
                if size & 0xC0 == 0xC0:
                    return offset + 2
                offset += 1
                if size == 0:
                    return offset
                offset += size
            return len(data)

        offset = 12
        questions, answers = struct.unpack_from(">HH", data, 4)
        for _ in range(questions):
            offset = skip_name(offset) + 4
        for _ in range(answers):
            offset = skip_name(offset)
            if offset + 10 > len(data):
                break
            record_type, _, _, rdlength = struct.unpack_from(">HHIH", data, offset)
            offset += 10
            if record_type != 0x21 or offset + rdlength > len(data) or rdlength < 1:
                offset += rdlength
                continue
            count = data[offset]
            computer_name = workgroup = ""
            first_unique = ""
            pos = offset + 1
            for _ in range(min(count, 25)):
                if pos + 18 > offset + rdlength:
                    break
                name = data[pos:pos+15].decode("latin-1", errors="ignore").strip()
                suffix = data[pos+15]
                flags = struct.unpack_from(">H", data, pos+16)[0]
                if flags & 0x8000:
                    if suffix == 0x00 and not workgroup:
                        workgroup = name
                elif name:
                    if not first_unique:
                        first_unique = name
                    if suffix in (0x00, 0x20) and not computer_name:
                        computer_name = name
                pos += 18
            if computer_name or first_unique or workgroup:
                return {"computer_name": computer_name or first_unique, "workgroup": workgroup}
            offset += rdlength
    except Exception:
        pass
    finally:
        sock.close()
    return None


def _dns_name(packet: bytes, offset: int) -> Tuple[str, int]:
    """Decode a DNS name, including compression pointers, with bounded hops."""
    labels = []
    next_offset = None
    for _ in range(32):
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        size = packet[offset]
        if size & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated DNS pointer")
            if next_offset is None:
                next_offset = offset + 2
            offset = ((size & 0x3F) << 8) | packet[offset + 1]
            continue
        if size & 0xC0:
            raise ValueError("invalid DNS label")
        offset += 1
        if size == 0:
            return ".".join(labels), next_offset if next_offset is not None else offset
        if offset + size > len(packet):
            raise ValueError("truncated DNS label")
        labels.append(packet[offset:offset + size].decode("utf-8", errors="replace"))
        offset += size
    raise ValueError("DNS pointer loop")


def query_llmnr_ptr(ip: str, timeout: float = 0.35) -> Optional[str]:
    """Ask a link-local host for its reverse PTR record via LLMNR/TCP."""
    try:
        address = ipaddress.IPv4Address(ip)
        name = ".".join(reversed(str(address).split("."))) + ".in-addr.arpa"
        qname = b"".join(bytes((len(part),)) + part.encode("ascii") for part in name.split(".")) + b"\x00"
        query = struct.pack(">HHHHHH", 0x4F50, 0, 1, 0, 0, 0) + qname + struct.pack(">HH", 12, 1)
        with socket.create_connection((ip, 5355), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(struct.pack(">H", len(query)) + query)

            def receive(count):
                chunks = bytearray()
                while len(chunks) < count:
                    part = sock.recv(count - len(chunks))
                    if not part:
                        raise OSError("short LLMNR response")
                    chunks.extend(part)
                return bytes(chunks)

            length = struct.unpack(">H", receive(2))[0]
            if length > 4096:
                return None
            packet = receive(length)
        if len(packet) < 12 or packet[:2] != query[:2] or not (packet[2] & 0x80) or packet[3] & 0x0F:
            return None
        questions, answers = struct.unpack_from(">HH", packet, 4)
        offset = 12
        for _ in range(questions):
            _, offset = _dns_name(packet, offset)
            offset += 4
        for _ in range(answers):
            _, offset = _dns_name(packet, offset)
            if offset + 10 > len(packet):
                return None
            record_type, record_class, _, length = struct.unpack_from(">HHIH", packet, offset)
            offset += 10
            if offset + length > len(packet):
                return None
            if record_type == 12 and record_class == 1:
                answer, _ = _dns_name(packet, offset)
                return answer[:100] or None
            offset += length
    except (OSError, ValueError, struct.error):
        pass
    return None

def query_ssdp(timeout: float = 1.0) -> Dict[str, Dict[str, str]]:
    """
    Broadcasts SSDP M-SEARCH (UDP 1900) to discover UPnP devices (Smart TVs, Routers, Media Servers).
    """
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 1\r\n"
        "ST: ssdp:all\r\n\r\n"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)
    devices = {}
    try:
        sock.bind(("", 0))
        sock.sendto(msg.encode(), ("239.255.255.250", 1900))
        t_end = time.time() + timeout
        while time.time() < t_end:
            try:
                data, addr = sock.recvfrom(2048)
                ip = addr[0]
                text = data.decode("utf-8", errors="ignore")
                server, location = "", ""
                for line in text.splitlines():
                    if line.upper().startswith("SERVER:"):
                        server = line.split(":", 1)[1].strip()
                    elif line.upper().startswith("LOCATION:"):
                        location = line.split(":", 1)[1].strip()
                if ip not in devices and (server or location):
                    devices[ip] = {"server": server, "location": location}
            except socket.timeout:
                break
    except Exception:
        pass
    finally:
        sock.close()
    return devices


def get_ssdp_description(ip: str, location: str, timeout: float = 1.0) -> Dict[str, str]:
    """Read a UPnP description only when LOCATION points back to its sender."""
    try:
        url = urllib.parse.urlsplit(location)
        if url.scheme != "http" or ipaddress.ip_address(url.hostname) != ipaddress.ip_address(ip):
            return {}
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, request, fp, code, msg, headers, newurl):
                return None

        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
        with opener.open(location, timeout=timeout) as response:
            document = response.read(32768)
        root = ET.fromstring(document)
        values = {}
        for field in ("friendlyName", "manufacturer", "modelName", "serialNumber"):
            element = root.find(".//{*}" + field)
            if element is not None and element.text:
                values[field] = " ".join(element.text.split())[:100]
        return values
    except (OSError, ValueError, ET.ParseError, TypeError):
        return {}

def discover_mdns_deep() -> Tuple[Dict[str, str], Dict[str, str]]:
    """
    Deep mDNS resolution for Apple devices, companion links, airplay, and printers.
    Returns:
      (ip_to_name_map, mac_to_name_map)
    """
    if sys.platform == "win32":
        return {}, {}
    ip_map = {}
    mac_map = {}

    # Browse apple-mobdev2, companion-link, and airplay
    cmd = (
        "dns-sd -B _apple-mobdev2._tcp local & P1=$!; "
        "dns-sd -B _companion-link._tcp local & P2=$!; "
        "dns-sd -B _airplay._tcp local & P3=$!; "
        "sleep 1.2; kill $P1 $P2 $P3 2>/dev/null"
    )
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=3)
        instances = []
        for line in res.stdout.splitlines():
            if " Add " in line:
                parts = line.split()
                if len(parts) >= 7:
                    stype = parts[5]
                    instance = " ".join(parts[6:]).replace("\\032", " ").strip()
                    if instance and (instance, stype) not in instances:
                        instances.append((instance, stype))

        # Check apple-mobdev2 instances: instance name often contains MAC address!
        # e.g.: c6:cc:36:dc:d5:85@fe80::c4cc:36ff:fedc:d585-supportsRP-24
        def resolve_single_instance(item):
            inst, stype = item
            mac_embedded = None
            mac_match = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", inst)
            if mac_match:
                mac_embedded = mac_match.group(1).lower()

            lookup_cmd = "dns-sd -L {} {} local & PID=$!; sleep 1; kill $PID 2>/dev/null".format(
                shlex.quote(inst), shlex.quote(stype)
            )
            lookup_res = subprocess.run(lookup_cmd, shell=True, capture_output=True, text=True)
            model_match = re.search(r"(?:^|\s)(?:model|am|md)=([^\s]+)", lookup_res.stdout, re.IGNORECASE)
            model = model_match.group(1).strip('"') if model_match else ""
            for line in lookup_res.stdout.splitlines():
                if "can be reached at" in line:
                    m = re.search(r"reached at (.*?):(\d+)", line)
                    if m:
                        host = m.group(1).rstrip(".")
                        clean_name = host.replace(".local", "").replace("-", " ")
                        if model:
                            clean_name = "{} ({})".format(clean_name, model)
                        try:
                            resolved_ip = socket.gethostbyname(f"{host}.")
                            return resolved_ip, mac_embedded, clean_name
                        except Exception:
                            return None, mac_embedded, clean_name
            return None, mac_embedded, None

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(resolve_single_instance, instances[:12])

        for resolved_ip, mac_emb, name in results:
            if name:
                if resolved_ip:
                    ip_map[resolved_ip] = name
                if mac_emb:
                    mac_map[mac_emb] = name
    except Exception:
        pass

    return ip_map, mac_map

def probe_ports_fast(ip: str, ports: List[int] = KEY_PORTS, on_progress=None) -> List[int]:
    """Rapid parallel probe of key ports."""
    open_ports = []
    def check_port(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.12)
        try:
            if s.connect_ex((ip, port)) == 0:
                return port
        except Exception:
            pass
        finally:
            s.close()
        return None

    if not ports:
        return []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(ports), 32)) as executor:
        futures = [executor.submit(check_port, port) for port in ports]
        for completed, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            p = future.result()
            if p:
                open_ports.append(p)
            if on_progress:
                on_progress(completed, len(ports))
    return sorted(open_ports)

def measure_latency_and_ttl(ip: str, open_ports: List[int]) -> Tuple[Optional[float], Optional[int], str]:
    """
    Measures RTT latency in milliseconds and ICMP/TCP TTL.
    Returns:
      (rtt_ms, ttl, os_guess)
    """
    # Try ICMP Ping first
    try:
        res = subprocess.run(platforms.ping_command(ip), capture_output=True, text=True, timeout=1.5)
        out = res.stdout
        ttl_match = re.search(r"ttl=(\d+)", out, re.IGNORECASE)
        time_match = re.search(r"time=(\d+\.?\d*)\s*ms", out, re.IGNORECASE)

        ttl = int(ttl_match.group(1)) if ttl_match else None
        rtt = float(time_match.group(1)) if time_match else None

        if ttl is not None:
            if ttl <= 64:
                os_guess = "macOS / iOS / Linux"
            elif ttl <= 128:
                os_guess = "Windows"
            else:
                os_guess = "Router / Switch"
            return rtt, ttl, os_guess
    except Exception:
        pass

    # If ICMP was blocked (e.g. Windows firewall) but ports are open, measure TCP connect RTT!
    if open_ports:
        target_port = open_ports[0]
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        t0 = time.time()
        try:
            if s.connect_ex((ip, target_port)) == 0:
                rtt = (time.time() - t0) * 1000.0
                if 3389 in open_ports or 445 in open_ports:
                    return round(rtt, 2), None, "Windows (service hint)"
                elif 62078 in open_ports:
                    return round(rtt, 2), None, "Apple iOS / iPadOS (service hint)"
                return round(rtt, 2), None, "Unknown"
        except Exception:
            pass
        finally:
            s.close()

    return None, None, "Unknown"

def get_http_banner(ip: str, port: int = 80, timeout: float = 1.0) -> Dict[str, str]:
    """Fetches HTTP <title> and Server header from web service."""
    protocol = "https" if port in [443, 8443] else "http"
    url = f"{protocol}://{ip}:{port}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    info = {"title": "", "server": "", "url": url}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (OPorts-CLI)"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            info["server"] = resp.headers.get("Server", "").strip()
            content = resp.read(8192).decode("utf-8", errors="ignore")
            title_match = re.search(r"<title>(.*?)</title>", content, re.IGNORECASE | re.DOTALL)
            if title_match:
                info["title"] = " ".join(title_match.group(1).split()).strip()
    except Exception:
        pass
    return info

def get_ssh_banner(ip: str, port: int = 22, timeout: float = 1.0) -> str:
    """Reads SSH protocol identification banner."""
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        return banner
    except Exception:
        return ""
    finally:
        s.close()
