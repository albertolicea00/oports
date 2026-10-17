"""
Table formatting and color utilities for OPorts CLI.
"""

import sys

# ANSI Colors
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
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

def format_device_table(devices: list, subnet_info: str = "", use_color: bool = True) -> str:
    """
    Renders devices in a clean Unicode box-drawing table.
    """
    headers = ["IP Address", "MAC Address", "Vendor / Type", "Device / Hostname", "Status / Notes"]
    
    # Calculate column widths
    widths = [len(h) for h in headers]
    for d in devices:
        widths[0] = max(widths[0], len(d.get("ip", "")))
        widths[1] = max(widths[1], len(d.get("mac", "")))
        widths[2] = max(widths[2], len(d.get("vendor", "")))
        widths[3] = max(widths[3], len(d.get("name", "")))
        widths[4] = max(widths[4], len(d.get("notes", "")))

    # Extra padding
    widths = [w + 2 for w in widths]

    c_bold = BOLD if use_color else ""
    c_reset = RESET if use_color else ""
    c_cyan = CYAN if use_color else ""
    c_yellow = YELLOW if use_color else ""
    c_green = GREEN if use_color else ""
    c_magenta = MAGENTA if use_color else ""
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
        ip_str = f" {d.get('ip', '').ljust(widths[0] - 1)}"
        mac_str = f" {d.get('mac', '').ljust(widths[1] - 1)}"
        vendor_str = f" {d.get('vendor', '').ljust(widths[2] - 1)}"
        name_str = f" {d.get('name', '').ljust(widths[3] - 1)}"
        notes_str = f" {d.get('notes', '').ljust(widths[4] - 1)}"

        # Apply row-level or cell-level coloring
        if d.get("is_local"):
            ip_col = f"{c_bold}{c_green}{ip_str}{c_reset}"
            name_col = f"{c_bold}{c_green}{name_str}{c_reset}"
        elif d.get("is_gateway"):
            ip_col = f"{c_bold}{c_cyan}{ip_str}{c_reset}"
            name_col = f"{c_bold}{c_cyan}{name_str}{c_reset}"
        else:
            ip_col = f"{c_cyan}{ip_str}{c_reset}"
            name_col = f"{c_white}{name_str}{c_reset}"

        mac_col = f"{c_yellow}{mac_str}{c_reset}"
        vendor_col = f"{c_magenta}{vendor_str}{c_reset}"
        notes_col = f"{c_dim}{notes_str}{c_reset}" if not d.get("is_local") else f"{c_green}{notes_str}{c_reset}"

        row_str = f"│{ip_col}│{mac_col}│{vendor_col}│{name_col}│{notes_col}│"
        lines.append(row_str)

    lines.append(bottom_border)
    return "\n".join(lines)
