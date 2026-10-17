# OPorts 🌐

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform: macOS / POSIX](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey.svg)]()

> A lightning-fast, zero-dependency CLI tool to discover active IP addresses, MAC addresses, hardware vendors, and devices on your local network.

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

- 🚀 **High-Speed Concurrent Discovery**: Subnet ping sweep across 254 IPs using `ThreadPoolExecutor` completes in ~2–4 seconds.
- 🏷️ **OUI Hardware Vendor Identification**: Built-in vendor database (Apple, Dell, TP-Link, Realtek, Samsung, Intel, Cisco, Raspberry Pi, etc.) with automatic local caching.
- 🔒 **Private & Randomized MAC Detection**: Automatically identifies randomized/private MAC addresses commonly used by iOS, iPadOS, Android, and Windows.
- 📡 **mDNS / Bonjour Hostname Resolution**: Automatically resolves human-readable names announced across the network (e.g., *iPad Pink*, *MacBook Air*).
- 🔍 **Signature Port Profiling**: Performs non-blocking probes on signature ports (RDP `3389`, Web `80`/`443`, SSH `22`, SMB `445`) to classify device roles (e.g., Windows PC with RDP, Web Router).
- 💻 **Self & Gateway Awareness**: Identifies and tags your own machine, active network interfaces (`en0`, `en6`), and the default router/gateway.
- 📦 **Zero External Dependencies**: Powered purely by Python's standard library and native OS tools (`ping`, `arp`, `dns-sd`, `scutil`).

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

---

## 🎯 Usage

Scan your local network and display the table:

```bash
oports --ips
```

*(Or run `./cli/oports --ips` directly from inside the repository)*.

### Command-Line Options

| Option | Shorthand | Description |
| :--- | :--- | :--- |
| `--ips` | `ips` | Scan the local network and print the device discovery table. |
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

---

## 📂 Project Structure

```text
OPorts/
├── cli/
│   ├── __init__.py      # Package initialization
│   ├── oports           # Executable CLI entrypoint
│   ├── scanner.py       # Discovery engine (ping sweep, ARP, mDNS, ports)
│   ├── vendors.py       # MAC OUI database & private address detection
│   └── formatter.py     # ANSI styling and Unicode box-drawing table renderer
├── .gitignore           # Standard Python & macOS ignore rules
├── CONTRIBUTING.md      # Guidelines for contributors
├── LICENSE              # MIT License
├── pyproject.toml       # Python packaging configuration
└── README.md            # Project documentation
```

---

## 📄 License

This project is open source and available under the [MIT License](LICENSE).
