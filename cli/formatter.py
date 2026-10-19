"""
Table formatting, ANSI colors, and detailed host inspection cards for OPorts CLI.
"""

import sys
from typing import Dict, List

# ANSI Colors
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"
GRAY = "\033[90m"

def print_banner(use_color: bool = True):
    c_cyan = CYAN if use_color else ""
    c_bold = BOLD if use_color else ""
    c_reset = RESET if use_color else ""
    banner = f"""{c_bold}{c_cyan}╭────────────────────────────────────────────────────────╮
│                     OPORTS CLI                         │
│           Local Network Scanner & Inspector            │
╰────────────────────────────────────────────────────────╯{c_reset}"""
    print(banner)

def format_device_table(devices: list, subnet_info: str = "", use_color: bool = True, verbose: bool = False) -> str:
    """
    Renders devices in a clean Unicode box-drawing table with Latency (RTT) and status alerts.
    """
    headers = ["IP Address", "MAC Address", "Vendor / Type", "Device / Hostname", "RTT", "Status / Notes"]
    
    # Calculate column widths
    widths = [len(h) for h in headers]
    for d in devices:
        rtt_text = f"{d.get('rtt', 0):.1f}ms" if d.get("rtt") is not None else "-"
        widths[0] = max(widths[0], len(d.get("ip", "")))
        widths[1] = max(widths[1], len(d.get("mac", "")))
        widths[2] = max(widths[2], len(d.get("vendor", "")))
        widths[3] = max(widths[3], len(d.get("name", "")))
        widths[4] = max(widths[4], len(rtt_text))
        widths[5] = max(widths[5], len(d.get("notes", "")))

    # Extra padding
    widths = [w + 2 for w in widths]

    c_bold = BOLD if use_color else ""
    c_reset = RESET if use_color else ""
    c_cyan = CYAN if use_color else ""
    c_yellow = YELLOW if use_color else ""
    c_green = GREEN if use_color else ""
    c_magenta = MAGENTA if use_color else ""
    c_red = RED if use_color else ""
    c_dim = DIM if use_color else ""
    c_white = WHITE if use_color else ""

    top_border    = "┌" + "┬".join("─" * w for w in widths) + "┐"
    header_sep    = "├" + "┼".join("─" * w for w in widths) + "┤"
    bottom_border = "└" + "┴".join("─" * w for w in widths) + "┘"

    lines = []
    if subnet_info:
        lines.append(f"{c_dim}Subnet analyzed: {subnet_info} | Devices discovered: {len(devices)}{c_reset}\n")

    lines.append(top_border)
    
    # Header line
    header_cells = [f" {headers[i].ljust(widths[i] - 1)}" for i in range(len(headers))]
    lines.append("│" + "│".join(f"{c_bold}{c_white}{cell}{c_reset}" for cell in header_cells) + "│")
    lines.append(header_sep)

    # Rows
    for d in devices:
        ip_val = d.get("ip", "")
        mac_val = d.get("mac", "")
        vendor_val = d.get("vendor", "")
        name_val = d.get("name", "")
        notes_val = d.get("notes", "")

        rtt_raw = d.get("rtt")
        rtt_str_raw = f"{rtt_raw:.1f}ms" if rtt_raw is not None else "-"

        # Format RTT color: <5ms green, <50ms yellow, >=50ms magenta
        if rtt_raw is not None:
            if rtt_raw < 5.0:
                rtt_colored = f"{c_green}{rtt_str_raw.ljust(widths[4] - 1)}{c_reset}"
            elif rtt_raw < 50.0:
                rtt_colored = f"{c_yellow}{rtt_str_raw.ljust(widths[4] - 1)}{c_reset}"
            else:
                rtt_colored = f"{c_magenta}{rtt_str_raw.ljust(widths[4] - 1)}{c_reset}"
        else:
            rtt_colored = f"{c_dim}{rtt_str_raw.ljust(widths[4] - 1)}{c_reset}"

        ip_cell = f" {ip_val.ljust(widths[0] - 1)}"
        mac_cell = f" {mac_val.ljust(widths[1] - 1)}"
        vendor_cell = f" {vendor_val.ljust(widths[2] - 1)}"
        name_cell = f" {name_val.ljust(widths[3] - 1)}"
        notes_cell = f" {notes_val.ljust(widths[5] - 1)}"

        # Colors by role
        if d.get("is_local"):
            ip_col = f"{c_bold}{c_green}{ip_cell}{c_reset}"
            name_col = f"{c_bold}{c_green}{name_cell}{c_reset}"
        elif d.get("is_gateway"):
            ip_col = f"{c_bold}{c_cyan}{ip_cell}{c_reset}"
            name_col = f"{c_bold}{c_cyan}{name_cell}{c_reset}"
        else:
            ip_col = f"{c_cyan}{ip_cell}{c_reset}"
            name_col = f"{c_white}{name_cell}{c_reset}"

        mac_col = f"{c_yellow}{mac_cell}{c_reset}"
        vendor_col = f"{c_magenta}{vendor_cell}{c_reset}"

        # Anomaly highlight in notes
        if "[!] Duplicate MAC" in notes_cell:
            notes_col = f"{c_bold}{c_red}{notes_cell}{c_reset}"
        elif d.get("is_local"):
            notes_col = f"{c_green}{notes_cell}{c_reset}"
        else:
            notes_col = f"{c_dim}{notes_cell}{c_reset}"

        row_str = f"│{ip_col}│{mac_col}│{vendor_col}│{name_col}│ {rtt_colored}│{notes_col}│"
        lines.append(row_str)

    lines.append(bottom_border)
    return "\n".join(lines)

def format_host_inspection(data: Dict, use_color: bool = True) -> str:
    """
    Renders an in-depth forensic card for a single inspected host.
    """
    c_bold = BOLD if use_color else ""
    c_reset = RESET if use_color else ""
    c_cyan = CYAN if use_color else ""
    c_yellow = YELLOW if use_color else ""
    c_green = GREEN if use_color else ""
    c_magenta = MAGENTA if use_color else ""
    c_dim = DIM if use_color else ""
    c_white = WHITE if use_color else ""

    lines = []
    lines.append(f"{c_bold}{c_cyan}╔══════════════════════════════════════════════════════════════════╗{c_reset}")
    lines.append(f"{c_bold}{c_cyan}║                   HOST INSPECTION REPORT                         ║{c_reset}")
    lines.append(f"{c_bold}{c_cyan}╚══════════════════════════════════════════════════════════════════╝{c_reset}\n")

    lines.append(f"  {c_bold}Target IP:{c_reset}        {c_cyan}{data.get('ip')}{c_reset} {'(Gateway)' if data.get('is_gateway') else ''}")
    lines.append(f"  {c_bold}MAC Address:{c_reset}      {c_yellow}{data.get('mac')}{c_reset}")
    lines.append(f"  {c_bold}Hardware Vendor:{c_reset}  {c_magenta}{data.get('vendor')}{c_reset}")
    lines.append(f"  {c_bold}Interface / ARP:{c_reset}  {data.get('iface')} ({data.get('arp_type')})")
    lines.append(f"  {c_bold}OS Fingerprint:{c_reset}   {c_green}{data.get('os_detected')}{c_reset} (TTL: {data.get('ttl') or 'N/A'})")

    # Latency statistics
    rtts = data.get("rtts", [])
    if rtts:
        avg_rtt = sum(rtts) / len(rtts)
        jitter = max(rtts) - min(rtts)
        lines.append(f"  {c_bold}Latency (RTT):{c_reset}    avg={avg_rtt:.2f}ms (min={min(rtts):.2f}ms, max={max(rtts):.2f}ms, jitter={jitter:.2f}ms)")
    else:
        lines.append(f"  {c_bold}Latency (RTT):{c_reset}    {c_dim}ICMP dropped by firewall{c_reset}")

    # NetBIOS
    nb = data.get("netbios_info")
    if nb:
        lines.append(f"\n  {c_bold}NetBIOS Name:{c_reset}     {c_cyan}{nb.get('computer_name')}{c_reset} (Workgroup: {nb.get('workgroup')})")
    if data.get("llmnr_name"):
        lines.append(f"  {c_bold}LLMNR Name:{c_reset}       {c_cyan}{data['llmnr_name']}{c_reset}")

    # iOS Lockdown Sync
    if data.get("ios_sync"):
        lines.append(f"  {c_bold}Apple Service:{c_reset}    {c_green}Lockdown Wi-Fi Sync Verified (TCP :62078){c_reset}")

    # HTTP Banner
    http = data.get("http_info")
    if http and (http.get("title") or http.get("server")):
        lines.append(f"\n  {c_bold}Web Service:{c_reset}")
        if http.get("title"):
            lines.append(f"    • Page Title:   {c_white}\"{http.get('title')}\"{c_reset}")
        if http.get("server"):
            lines.append(f"    • Server Header: {c_dim}{http.get('server')}{c_reset}")
        lines.append(f"    • URL:          {http.get('url')}")

    # SSH Banner
    ssh = data.get("ssh_banner")
    if ssh:
        lines.append(f"\n  {c_bold}SSH Identification:{c_reset} {c_green}{ssh}{c_reset}")

    # Port table
    open_ports = data.get("open_ports", [])
    lines.append(f"\n  {c_bold}Open Ports Detected ({len(open_ports)}):{c_reset}")
    if open_ports:
        try:
            from .discovery import PORT_SERVICE_MAP
        except ImportError:
            from discovery import PORT_SERVICE_MAP
        lines.append(f"    ┌─────────┬──────────────┬────────────────────────────┐")
        lines.append(f"    │ Port    │ Protocol     │ Service Description        │")
        lines.append(f"    ├─────────┼──────────────┼────────────────────────────┤")
        for p in open_ports:
            svc = PORT_SERVICE_MAP.get(p, "Custom / Unknown")
            lines.append(f"    │ {str(p).ljust(7)} │ TCP          │ {svc.ljust(26)} │")
        lines.append(f"    └─────────┴──────────────┴────────────────────────────┘")
    else:
        lines.append(f"    {c_dim}No open common ports found.{c_reset}")

    return "\n".join(lines)
