"""Windows network and process inspection through built-in PowerShell commands."""

import ipaddress
import json
import re
import socket
import subprocess


def _powershell(script, timeout=8):
    try:
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                                capture_output=True, text=True, timeout=timeout)
        if result.returncode or not result.stdout.strip():
            return []
        data = json.loads(result.stdout)
        return data if isinstance(data, list) else [data]
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return []


def get_computer_name():
    return socket.gethostname()


def get_active_interfaces():
    script = r"""
    $rows = foreach ($c in Get-NetIPConfiguration) {
      $a = $c.IPv4Address | Select-Object -First 1
      if ($null -eq $a) { continue }
      $adapter = Get-NetAdapter -InterfaceIndex $c.InterfaceIndex -ErrorAction SilentlyContinue
      [pscustomobject]@{
        interface=$c.InterfaceAlias; ip=$a.IPAddress; prefix=$a.PrefixLength
        mac=$adapter.MacAddress; gateway=($c.IPv4DefaultGateway | Select-Object -First 1).NextHop
      }
    }
    ConvertTo-Json -InputObject @($rows) -Compress
    """
    interfaces = []
    for item in _powershell(script):
        try:
            address = ipaddress.IPv4Address(item["ip"])
            if address.is_loopback or address.is_link_local:
                continue
            prefix = int(item["prefix"])
            netmask = str(ipaddress.IPv4Network("0.0.0.0/{}".format(prefix)).netmask)
            network = ipaddress.IPv4Network("{}/{}".format(address, prefix), strict=False)
            mac = (item.get("mac") or "").replace("-", ":").lower()
            interfaces.append({"interface": item["interface"], "ip": str(address),
                               "netmask": netmask, "broadcast": str(network.broadcast_address),
                               "mac": mac, "gateway": item.get("gateway") or ""})
        except (KeyError, ValueError, TypeError):
            continue
    return sorted(interfaces, key=lambda item: (not bool(item.get("gateway")), item["interface"]))


def get_default_gateway():
    return next((item["gateway"] for item in get_active_interfaces() if item.get("gateway")), None)


def get_arp_table(network):
    entries = {}
    script = """
    $rows = foreach ($n in Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue) {
      $adapter = Get-NetAdapter -InterfaceIndex $n.InterfaceIndex -ErrorAction SilentlyContinue
      [pscustomobject]@{ ip=$n.IPAddress; mac=$n.LinkLayerAddress
        interface=$adapter.Name; state=($n.State.ToString()) }
    }
    ConvertTo-Json -InputObject @($rows) -Compress
    """
    for item in _powershell(script):
        try:
            ip = item["ip"]
            if ipaddress.IPv4Address(ip) not in network:
                continue
            mac = (item.get("mac") or "").replace("-", ":").lower()
            if not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac):
                continue
        except (KeyError, ValueError):
            continue
        if mac == "ff:ff:ff:ff:ff:ff":
            continue
        permanent = item.get("state", "").lower() == "permanent"
        entries[ip] = {"ip": ip, "mac": mac, "iface": item.get("interface") or "",
                       "is_permanent": permanent, "arp_type": "Static" if permanent else "Dynamic",
                       "arp_expires_seconds": None}
    return entries


def ping_command(ip, count=1, timeout_ms=200):
    return ["ping", "-n", str(count), "-w", str(timeout_ms), ip]


def get_local_ports():
    script = r"""
    $names = @{}
    $rows = foreach ($c in Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue) {
      $pidNumber = $c.OwningProcess
      if (-not $names.ContainsKey($pidNumber)) {
        $p = Get-Process -Id $pidNumber -ErrorAction SilentlyContinue
        $names[$pidNumber] = if ($p) { $p.ProcessName } else { 'Unknown' }
      }
      [pscustomobject]@{ pid=$pidNumber; process=$names[$pidNumber]
        address=($c.LocalAddress + ':' + $c.LocalPort); port=$c.LocalPort }
    }
    ConvertTo-Json -InputObject @($rows) -Compress
    """
    rows = []
    for item in _powershell(script):
        try:
            rows.append({"pid": int(item["pid"]), "process": item["process"],
                         "address": item["address"], "port": int(item["port"])})
        except (KeyError, ValueError, TypeError):
            continue
    return sorted(rows, key=lambda row: (row["port"], row["pid"], row["address"]))


def get_active_connections():
    script = """
    $names = @{}
    $rows = foreach ($c in Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue) {
      $pidNumber = $c.OwningProcess
      if (-not $names.ContainsKey($pidNumber)) {
        $p = Get-Process -Id $pidNumber -ErrorAction SilentlyContinue
        $names[$pidNumber] = if ($p) { $p.ProcessName } else { 'Unknown' }
      }
      [pscustomobject]@{ pid=$pidNumber; process=$names[$pidNumber]
        connection=($c.LocalAddress + ':' + $c.LocalPort + ' -> ' + $c.RemoteAddress + ':' + $c.RemotePort) }
    }
    ConvertTo-Json -InputObject @($rows) -Compress
    """
    rows = []
    for item in _powershell(script):
        try:
            rows.append({"pid": int(item["pid"]), "process": item["process"],
                         "connection": item["connection"]})
        except (KeyError, ValueError, TypeError):
            continue
    return rows


def get_lease_servers(interfaces):
    script = r"""
    $rows = foreach ($c in Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True') {
      [pscustomobject]@{ ip=($c.IPAddress | Where-Object { $_ -match '^\d+\.' } | Select-Object -First 1)
        server=$c.DHCPServer }
    }
    ConvertTo-Json -InputObject @($rows) -Compress
    """
    names = {item["ip"]: item["interface"] for item in interfaces}
    servers = {}
    for item in _powershell(script):
        try:
            if item.get("ip") in names and item.get("server"):
                servers[names[item["ip"]]] = str(ipaddress.IPv4Address(item["server"]))
        except ValueError:
            continue
    return servers
