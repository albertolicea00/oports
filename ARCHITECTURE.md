# Architecture

OPorts has one scanning engine and four interfaces: CLI, terminal dashboard,
system tray, and desktop window. The repository root is `OPorts/`; there is no
nested `oports/` package.

```text
OPorts/
├── core/
│   ├── models.py          Shared result shapes
│   ├── scanner.py         LAN sweep, host enrichment, host inspection
│   ├── discovery.py       Port probes, names, SSDP, latency, banners
│   ├── dhcp.py            DHCP lease comparison
│   ├── local_ports.py     Shared local listener API
│   ├── upnp.py            Read-only router mapping queries
│   ├── vendors.py         MAC vendor lookup
│   └── formatter.py       Plain and ANSI terminal reports
├── platforms/
│   ├── base.py            Adapter contract
│   ├── macos.py           macOS commands and parsing
│   ├── windows.py         Windows PowerShell queries and parsing
│   └── posix.py           Limited fallback outside macOS and Windows
├── interfaces/
│   ├── cli.py             CLI argument handling
│   ├── tui/               Textual terminal dashboard
│   ├── desktop/           PySide6 device and port window
│   └── tray/              PySide6 menu bar / notification area app
├── tests/{core,platforms,interfaces}/
├── cli/oports             Source checkout launcher
├── __main__.py            `python .` launcher
├── gui.py                 Desktop-first standalone build entry point
└── tray_gui.py            Tray-first standalone build entry point
```

## Data flow

```text
CLI ───────────────┐
TUI ───────────────┼──> core.scanner / core.local_ports
Desktop window ────┤              │
System tray ───────┘              ├──> core.discovery / vendors / DHCP / UPnP
                                  └──> platforms (macOS or Windows)
```

The interfaces call Python functions in `core/`; they do not launch the CLI as a
subprocess. `scan_network(interface)` returns `(devices, subnet)`, and
`get_local_ports()` returns listener rows. These dictionaries are the current
shared data format. `core/models.py` records their principal fields; richer
inspection fields remain in the scanner results.

`scan_network` selects an interface, runs a bounded concurrent ping sweep,
reads the neighbour cache, and enriches discovered hosts with names, signature
ports, latency, vendor, and router hints. `inspect_host` performs a deeper scan
of one IPv4 address. Network names and OS labels are hints, not authoritative
identification. The scanner limits the sweep to 254 addresses even when the
selected subnet is larger.

## Platform boundary

`platforms/__init__.py` selects the adapter at runtime. Each adapter supplies
the operations described by `platforms/base.py`: computer name, gateway,
interfaces, neighbour table, ping command, local listeners, active TCP
connections, and accepted DHCP lease servers.

- macOS uses `ifconfig`, `netstat`, `arp`, `ping`, `lsof`, `scutil`, and
  `ipconfig getpacket`. Bonjour browsing uses `dns-sd` in `core/discovery.py`.
- Windows uses built-in PowerShell network cmdlets and Windows `ping`. The
  Bonjour-specific browser currently returns no names on Windows; NetBIOS,
  LLMNR, SSDP, port probes, and TCP inspection remain available.
- `posix.py` preserves a limited fallback. Linux is not a tested target for
  this desktop release.

If a new system capability is needed, add it to the adapter contract and both
target adapters, then call it from `core/`. Keep command output parsing out of
the interfaces. The CLI and TUI retain their existing public commands while
reading the same core modules as the graphical interfaces.

## Visual interfaces

The TUI uses Textual and runs scans in workers. The desktop window uses
PySide6 to show LAN devices, details, and local TCP listeners. The tray uses
`QSystemTrayIcon`: it appears in the macOS menu bar or Windows notification
area, shows device and port counts, and offers Open, Refresh, and Quit. A
`QThread` runs the scan so the window and menu remain responsive. Closing the
window hides it while a tray icon is available; Quit ends the application.

PySide6 is an optional dependency. Install `.[desktop]` for tray and desktop,
or `.[tui]` for the terminal dashboard. `pyside6-deploy gui.py` and
`pyside6-deploy tray_gui.py` are the two standalone build entry points; run
them on each target operating system. Windows launcher entries are declared
under `[project.gui-scripts]` so they do not open a console window.

## External actions and checks

Most inspection is read-only. The TUI can send SIGTERM to a selected local
process only after a confirmation dialog. The WAN tab queries ipify for the
public IP. UPnP code reads advertised mappings without changing router state.

Run `python -m unittest discover -s tests -t .` for parsing and CLI checks.
The macOS CLI and TUI have also been exercised against local system data.
Windows adapter tests use simulated PowerShell results; a native Windows run
is still required to validate the OS integration. The PySide6 window and tray
also require a runtime smoke test on macOS and Windows before release.
