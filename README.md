# OPorts 🌐

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform: macOS / Windows](https://img.shields.io/badge/platform-macOS%20%7C%20Windows-lightgrey.svg)]()

> A network inspector with CLI, terminal dashboard, system tray, and desktop interfaces.

---

## ⚡ Overview

**OPorts** scans your local network subnet in seconds using multi-threaded ICMP ping sweeps, ARP inspection, Bonjour/mDNS resolution, and rapid port profiling. It presents everything in a clean, colorized terminal table.

```text
╭────────────────────────────────────────────────────────╮
│                     OPORTS CLI                         │
│           Local Network Scanner & Inspector            │
╰────────────────────────────────────────────────────────╯

🔍 Scanning local network for active devices... (please wait a few seconds)

Subnet analyzed: 192.168.1.0/24 (en0) | Devices discovered: 7

┌───────────────┬───────────────────┬───────────────────────┬──────────────────────────────────┬───────────────────────────────┐
│ IP Address    │ MAC Address       │ Vendor / Type         │ Device / Hostname                │ Status / Notes                │
├───────────────┼───────────────────┼───────────────────────┼──────────────────────────────────┼───────────────────────────────┤
│ 192.168.1.1   │ 34:e8:94:f8:cc:b0 │ TP-Link Technologies  │ Router / Gateway                 │ Active (Web Admin Panel)      │
│ 192.168.1.100 │ 8c:04:ba:a1:4e:77 │ Dell Inc.             │ PC Dell Inc. (Windows)           │ Active (Remote Desktop / RDP) │
│ 192.168.1.101 │ 00:e0:4c:a0:e0:dd │ Realtek Semiconductor │ This Mac (Alberto’s MacBook Air) │ Current host (en6)            │
│ 192.168.1.102 │ c6:cc:36:dc:d5:85 │ Private / Randomized  │ Mobile Device (iOS / Android)    │ Active (Private MAC Address)  │
│ 192.168.1.103 │ 8c:04:ba:a1:4e:77 │ Dell Inc.             │ Dell Inc. Device                 │ Active                        │
│ 192.168.1.104 │ c2:e0:b9:73:af:4a │ Private / Randomized  │ This Mac (Alberto’s MacBook Air) │ Current host (en0)            │
│ 192.168.1.105 │ c6:cf:6e:2d:08:ad │ Private / Randomized  │ iPad Pink                        │ Active (Private / Randomized) │
└───────────────┴───────────────────┴───────────────────────┴──────────────────────────────────┴───────────────────────────────┘

✅ Total active devices found: 7
```

---

## ✨ Features

- 🚀 **Bounded Concurrent Discovery**: Subnet ping sweep across up to 254 IPs uses `ThreadPoolExecutor` with a per-host timeout; completion time depends on network and ARP behavior.
- 🏷️ **OUI Hardware Vendor Identification**: Built-in vendor database (Apple, Dell, TP-Link, Realtek, Samsung, Intel, Cisco, Raspberry Pi, etc.) with automatic local caching.
- 🔒 **Private & Randomized MAC Detection**: Automatically identifies randomized/private MAC addresses commonly used by iOS, iPadOS, Android, and Windows.
- 📡 **Local Hostname Resolution**: Resolves names via Bonjour/mDNS, NetBIOS, and LLMNR reverse PTR where supported; UPnP descriptions may add a friendly name and model.
- 🔍 **Signature Port Profiling**: Performs non-blocking probes on signature ports (RDP `3389`, Web `80`/`443`, SSH `22`, SMB `445`) to classify device roles (e.g., Windows PC with RDP, Web Router).
- 💻 **Self & Gateway Awareness**: Identifies and tags your own machine, active network interfaces (`en0`, `en6`), and the default router/gateway.
- 📦 **Shared scanning engine**: The CLI uses Python and native OS tools. The terminal dashboard uses optional Textual; the tray and desktop window use optional PySide6.
- 🖥️ **Interactive dashboard**: Navigate LAN devices, local listeners, active TCP connections, and gateway/interface information; filter devices, view live RTT trends, inspect a selected host with scan progress, and read UPnP port mappings when the router permits it.
- 🪟 **Desktop and tray**: A device list, local port list, and background refresh from the macOS menu bar or Windows notification area.

---

## 📥 Installation

### Option 1: Symlink to User Path (Instant)

Clone the repository and symlink the executable to `~/.local/bin`:

```bash
git clone https://github.com/albertolicea00/OPorts.git
cd OPorts
chmod +x cli/oports
ln -sf "$(pwd)/cli/oports" ~/.local/bin/oports
```

### Option 2: Pip Editable Install

```bash
cd OPorts
pip install -e .
```

For the interactive dashboard, install the optional dependency:

```bash
pip install -e '.[tui]'
```

For the desktop window and system tray, install PySide6:

```bash
pip install -e '.[desktop]'
```

On Windows, use PowerShell to install the same package; the CLI reads interfaces, neighbours, DHCP leases, and TCP listeners with Windows system commands. Bonjour discovery currently runs only on macOS.

---

## 🎯 Usage

Open the dashboard in a terminal:

```bash
oports
```

Open the desktop list or the tray app:

```bash
oports --desktop
oports --tray
```

The installed commands `oports-desktop` and `oports-tray` do the same. Closing the window hides it when the tray is available; use **Quit** in the tray menu to exit.

To make standalone apps, run `pyside6-deploy gui.py` for the desktop-first app or `pyside6-deploy tray_gui.py` for the tray-first app. Run the build on macOS for an `.app` bundle and on Windows for an `.exe`; the repository does not contain prebuilt installers.

Run the automated checks with `python -m unittest discover -s tests -t .`.

Scan your local network and print the table:

```bash
oports --ips
```

*(Or run `./cli/oports --ips` directly from inside the repository)*.

### Command-Line Options

| Option | Shorthand | Description |
| :--- | :--- | :--- |
| `--ips` | `ips` | Scan the local network and print the device discovery table. |
| `--local` | `local` | Print local listening TCP ports. |
| `--tui` | | Open the interactive dashboard. |
| `--desktop` | | Open the device and local port lists in a window. |
| `--tray` | | Run from the macOS menu bar or Windows notification area. |
| `--inspect <IP>` | | Inspect one IPv4 host, including common ports and service banners. |
| `--verbose` | | Print a detailed inspection for each discovered host with `--ips`. |
| `--json` | | Output discovered devices and network metadata in structured JSON. |
| `--interface <iface>` | `-i <iface>` | Specify a network interface (e.g., `en0`, `en6`). |
| `--no-color` | | Disable ANSI terminal colors (recommended for log files or plain output). |
| `--help` | `-h` | Display help and usage information. |

### Examples

**JSON Output for scripts or piping to `jq`:**
```bash
oports --ips --json
```

**Targeting a specific network interface:**
```bash
oports --ips -i en0
```

**Inspect one device:**
```bash
oports --inspect 192.168.1.100
```

**Dashboard keys:** `1`–`4` switch tabs, arrow keys select rows, `/` filters LAN devices, `s` inspects the selected device, `p` runs five ICMP latency probes, `r` refreshes, `k` opens a confirmation dialog for a selected local listener, and `q` quits. Stopping a process sends SIGTERM to its PID.

Device names, operating system hints, and private MAC labels are best-effort. TTL reflects the network path and cannot identify an exact OS version. TCP 62078 is a service hint, not proof of a device's identity.
The WAN tab queries [ipify](https://www.ipify.org/) for the public IP and shows “Unavailable” when offline.
On macOS, OPORTS reads the DHCP servers in accepted interface leases and flags different servers observed for the same subnet. This is a review hint, not a passive rogue-DHCP detector; seeing other offers would require packet capture access.

---

## ⚖️ How It Compares to Nmap

While both tools can discover active hosts and check open ports, they serve distinct purposes:

| Feature / Aspect | **Nmap** | **OPorts** |
| :--- | :--- | :--- |
| **Primary Focus** | Security auditing, penetration testing, and low-level network packet analysis. | Quick, user-friendly LAN visibility, friendly device identification, and local machine inspection. |
| **Privileges & System Impact** | Operates heavily via raw sockets (libpcap); requires `sudo` / root for most powerful scans (SYN scan `-sS`, OS fingerprinting `-O`, etc.). | Zero root/sudo required. Uses Python standard library and native OS utilities (`ping`, `arp`, `dns-sd`, `lsof`). |
| **Port Scanning Scope** | Scans anywhere from 1 to all 65,535 TCP/UDP ports with deep protocol version detection (`-sV`). | Rapid signature profiling of common ports (`22`, `80`, `443`, `445`, `3389`, etc.) to classify host roles in seconds. |
| **Device & Name Resolution** | Standard reverse DNS resolution or targeted NSE scripts. | Tailored for modern home/office LANs: resolves human-readable names via Apple Bonjour/mDNS (`dns-sd`), SSDP, and NetBIOS, plus flags randomized/private MAC addresses (iOS/Android). |
| **Local Machine Monitoring** | Primarily targets remote hosts across networks; doesn't inspect local listening processes. | Built-in local listener inspection (`oports --local`) to show which local processes and PIDs have open listening ports. |
| **User Interface** | CLI text output, XML/grepable output, or legacy GUI (Zenmap). | Colorized Unicode tables, structured JSON, and an interactive terminal dashboard (TUI) powered by Textual. |
| **Vulnerability / Exploit Engine** | Comprehensive Nmap Scripting Engine (NSE) with thousands of security scripts. | None. Focuses purely on fast, non-intrusive discovery and inventory. |

> **Summary:** Use **Nmap** when you need in-depth network security audits, vulnerability detection, or full port sweeps. Use **OPorts** when you want an instant, clean, zero-config view of what devices are connected to your Wi-Fi/LAN, what your own computer is hosting, and which devices are active.

---

## 📂 Project Structure

```text
OPorts/
├── cli/
│   └── oports           # Source checkout launcher
├── core/                # Shared scanner, discovery, models, and formatting
├── platforms/           # macOS and Windows system adapters
├── interfaces/
│   ├── cli.py           # Command line arguments and output
│   ├── tui/             # Textual terminal dashboard
│   ├── desktop/         # Device and port list window
│   └── tray/            # macOS menu bar and Windows tray
├── tests/               # Core, platform, and interface tests
├── __main__.py          # Source directory entry point
├── gui.py               # Standalone desktop build entry point
├── tray_gui.py          # Standalone tray build entry point
├── .gitignore           # Standard Python & macOS ignore rules
├── CONTRIBUTING.md      # Guidelines for contributors
├── LICENSE              # MIT License
├── pyproject.toml       # Python packaging configuration
└── README.md            # Project documentation
```

---

## 📄 License

This project is open source and available under the [MIT License](LICENSE).
