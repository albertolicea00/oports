"""Textual dashboard backed by the same scanners as the CLI."""

import os
import ipaddress
import signal
import subprocess
import urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, ProgressBar, Static, TabbedContent, TabPane

from core.discovery import PORT_SERVICE_MAP, query_ssdp, measure_latency_and_ttl
from core.dhcp import get_lease_servers, multiple_servers_on_same_subnet
from core.upnp import get_port_mappings
from core.local_ports import get_local_ports
import platforms
from core.scanner import get_active_interfaces, get_default_gateway, inspect_host, scan_network


SPARK = "▁▂▃▄▅▆▇█"


def sparkline(samples):
    values = [sample for sample in samples if sample is not None]
    if not values:
        return "·" * len(samples)
    low, high = min(values), max(values)
    width = high - low
    return "".join("·" if sample is None else SPARK[3 if width == 0 else min(7, int((sample - low) * 7 / width))] for sample in samples)


class ConfirmKill(ModalScreen):
    """Require an explicit decision before sending SIGTERM."""

    def __init__(self, row):
        super().__init__()
        self.row = row

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm"):
            yield Label("Stop {process} (PID {pid}) on port {port}?".format(**self.row))
            with Horizontal():
                yield Button("Cancel", id="cancel")
                yield Button("Send SIGTERM", variant="error", id="kill")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "kill")


class OPortsApp(App):
    TITLE = "OPORTS"
    CSS_PATH = "styles.tcss"
    BINDINGS = [
        ("1", "tab('lan')", "LAN"), ("2", "tab('local')", "Local"),
        ("3", "tab('traffic')", "Traffic"), ("4", "tab('wan')", "WAN"),
        ("r", "refresh_data", "Refresh"), ("s", "inspect", "Inspect"),
        ("p", "ping", "Latency test"), ("slash", "filter", "Filter"),
        ("k", "kill", "Stop process"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, interface=None):
        super().__init__()
        self.interface = interface
        self.devices = []
        self.local_rows = []
        self.selected_ip = None
        self.selected_local = None
        self.pending_kill = None
        self.latency_samples = {}
        self.visible_ips = set()
        self.latency_busy = False

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(id="tabs"):
            with TabPane("1 LAN Devices", id="lan"):
                yield Static("Scanning local network...", id="subnet")
                yield Input(placeholder="Filter by IP, name, vendor or port", id="filter")
                with Horizontal(classes="split"):
                    yield DataTable(id="lan-table", cursor_type="row")
                    with Vertical(id="inspector-pane"):
                        yield Static("Select a device; press s for a deeper inspection.", id="inspector")
                        yield ProgressBar(total=23, show_eta=False, id="scan-progress")
            with TabPane("2 Local Ports", id="local"):
                with Horizontal(classes="split"):
                    yield DataTable(id="local-table", cursor_type="row")
                    yield Static("Select a listener; press k to stop its process.", id="local-detail")
            with TabPane("3 Active Traffic", id="traffic"):
                yield DataTable(id="traffic-table", cursor_type="row")
            with TabPane("4 WAN & Router", id="wan"):
                yield Static("Loading network information...", id="wan-info")
        yield Footer()

    def on_mount(self) -> None:
        lan = self.query_one("#lan-table", DataTable)
        lan.add_column("IP", key="ip")
        lan.add_column("Device / Hostname", key="name")
        lan.add_column("RTT", key="rtt")
        lan.add_column("Trend", key="trend")
        lan.add_column("Ports", key="ports")
        self.query_one("#local-table", DataTable).add_columns("Port", "PID", "Process", "Address")
        self.query_one("#traffic-table", DataTable).add_columns("PID", "Process", "Connection")
        self.query_one("#filter", Input).display = False
        self.query_one("#scan-progress", ProgressBar).display = False
        self.action_refresh_data()
        self.set_interval(3.0, self._refresh_rtts)

    def action_tab(self, tab):
        self.query_one("#tabs", TabbedContent).active = tab

    def action_filter(self):
        self.action_tab("lan")
        box = self.query_one("#filter", Input)
        box.display = True
        box.focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "filter":
            self._fill_lan()

    def action_refresh_data(self):
        self.query_one("#subnet", Static).update("Scanning local network...")
        self.query_one("#inspector", Static).update("Scanning... select a device when ready.")
        self._scan_lan()
        self._load_local()
        self._load_traffic()
        self._load_wan()

    @work(thread=True, exclusive=True, group="lan")
    def _scan_lan(self):
        try:
            devices, subnet = scan_network(self.interface)
            self.call_from_thread(self._show_lan, devices, subnet)
        except Exception as exc:
            self.call_from_thread(self.query_one("#subnet", Static).update, "Scan failed: {}".format(exc))

    def _show_lan(self, devices, subnet):
        self.devices = devices
        old = self.latency_samples
        self.latency_samples = {}
        for device in devices:
            samples = deque(old.get(device["ip"], []), maxlen=12)
            if device.get("rtt") is not None:
                samples.append(device["rtt"])
            self.latency_samples[device["ip"]] = samples
        self.query_one("#subnet", Static).update("Subnet: {}  |  Devices: {}".format(subnet, len(devices)))
        self._fill_lan()

    def _fill_lan(self):
        table = self.query_one("#lan-table", DataTable)
        term = self.query_one("#filter", Input).value.lower().strip()
        table.clear()
        self.visible_ips = set()
        for device in self.devices:
            haystack = " ".join(str(device.get(field, "")) for field in ("ip", "name", "vendor", "open_ports")).lower()
            if term and term not in haystack:
                continue
            rtt = device.get("rtt")
            self.visible_ips.add(device["ip"])
            table.add_row(device["ip"], device.get("name", ""), "{:.1f}ms".format(rtt) if rtt is not None else "–", sparkline(self.latency_samples.get(device["ip"], [])), str(len(device.get("open_ports", []))), key=device["ip"])
        if table.row_count:
            table.move_cursor(row=0)
        else:
            self.selected_ip = None

    def _refresh_rtts(self):
        if self.latency_busy or not self.devices or self.query_one("#tabs", TabbedContent).active != "lan":
            return
        ips = [device["ip"] for device in self.devices if device["ip"] in self.visible_ips][:16]
        if not ips:
            return
        self.latency_busy = True
        self._sample_rtts(ips)

    @work(thread=True, exclusive=True, group="latency")
    def _sample_rtts(self, ips):
        try:
            with ThreadPoolExecutor(max_workers=12) as executor:
                results = list(executor.map(lambda ip: measure_latency_and_ttl(ip, [])[0], ips))
            self.call_from_thread(self._show_rtts, dict(zip(ips, results)))
        finally:
            self.call_from_thread(self._finish_rtts)

    def _finish_rtts(self):
        self.latency_busy = False

    def _show_rtts(self, results):
        table = self.query_one("#lan-table", DataTable)
        current = {device["ip"]: device for device in self.devices}
        for ip, rtt in results.items():
            if ip not in current:
                continue
            current[ip]["rtt"] = rtt
            self.latency_samples.setdefault(ip, deque(maxlen=12)).append(rtt)
            if ip in self.visible_ips:
                table.update_cell(ip, "rtt", "{:.1f}ms".format(rtt) if rtt is not None else "–")
                table.update_cell(ip, "trend", sparkline(self.latency_samples[ip]))

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id == "lan-table":
            new_ip = str(event.row_key.value)
            if new_ip != self.selected_ip:
                self._hide_progress()
            self.selected_ip = new_ip
            device = next((d for d in self.devices if d["ip"] == self.selected_ip), None)
            if device:
                ports = ", ".join("{} ({})".format(p, PORT_SERVICE_MAP.get(p, "TCP")) for p in device.get("open_ports", [])) or "None detected"
                lines = [
                    "{}  {}".format(device["ip"], device.get("name", "")), "",
                    "MAC: {}  ({})".format(device.get("mac", "?"), device.get("vendor", "?")),
                    "Interface: {}  |  ARP: {}".format(device.get("interface", "?"), device.get("arp_type", "?")),
                    "ARP expiry: {}".format("{}s".format(device["arp_expires_seconds"]) if device.get("arp_expires_seconds") is not None else "–"),
                    "OS hint: {}  |  TTL: {}".format(device.get("os_guess", "Unknown"), device.get("ttl") or "?"),
                    "RTT: {} ms".format(device.get("rtt") if device.get("rtt") is not None else "?"),
                    "Open ports: {}".format(ports),
                    "Notes: {}".format(device.get("notes", "")), "", "Press s for HTTP, SSH and NetBIOS details.",
                ]
                self.query_one("#inspector", Static).update(Text("\n".join(lines)))
        elif event.data_table.id == "local-table":
            index = int(event.row_key.value)
            if index < len(self.local_rows):
                self.selected_local = self.local_rows[index]
                self.query_one("#local-detail", Static).update(Text("Port: {port}\nPID: {pid}\nProcess: {process}\nAddress: {address}\n\nPress k to send SIGTERM (confirmation required).".format(**self.selected_local)))

    def action_inspect(self):
        if self.query_one("#tabs", TabbedContent).active != "lan" or not self.selected_ip:
            return
        ip = self.selected_ip
        self.query_one("#inspector", Static).update("Inspecting {}...".format(ip))
        bar = self.query_one("#scan-progress", ProgressBar)
        bar.update(total=23, progress=0)
        bar.display = True
        self._inspect(ip)

    def action_ping(self):
        if self.query_one("#tabs", TabbedContent).active != "lan" or not self.selected_ip:
            return
        ip = self.selected_ip
        self.query_one("#inspector", Static).update("Measuring {} with 5 ICMP probes...".format(ip))
        self._ping_burst(ip)

    @work(thread=True, exclusive=True, group="ping")
    def _ping_burst(self, ip):
        samples = [measure_latency_and_ttl(ip, [])[0] for _ in range(5)]
        self.call_from_thread(self._show_ping_burst, ip, samples)

    def _show_ping_burst(self, ip, samples):
        if self.selected_ip != ip:
            return
        received = [value for value in samples if value is not None]
        if received:
            text = "{}: {}/5 replies\nRTT min {:.1f} ms | avg {:.1f} ms | max {:.1f} ms\nVariation {:.1f} ms".format(
                ip, len(received), min(received), sum(received) / len(received), max(received), max(received) - min(received))
        else:
            text = "{}: no ICMP replies (5 probes)".format(ip)
        self.query_one("#inspector", Static).update(Text(text))

    @work(thread=True, exclusive=True, group="inspect")
    def _inspect(self, ip):
        try:
            data = inspect_host(ip, progress=lambda done, total: self.call_from_thread(self._scan_progress, ip, done, total))
            self.call_from_thread(self._show_inspection, ip, data)
        except Exception as exc:
            self.call_from_thread(self.query_one("#inspector", Static).update, "Inspection failed: {}".format(exc))
            self.call_from_thread(self._hide_progress)

    def _scan_progress(self, ip, done, total):
        if self.selected_ip == ip:
            self.query_one("#scan-progress", ProgressBar).update(total=total, progress=done)

    def _hide_progress(self):
        self.query_one("#scan-progress", ProgressBar).display = False

    def _show_inspection(self, ip, data):
        if self.selected_ip != ip:
            return
        self._hide_progress()
        ports = ", ".join("{} {}".format(p, PORT_SERVICE_MAP.get(p, "TCP")) for p in data["open_ports"]) or "None detected"
        lines = [ip, "", "MAC: {} ({})".format(data["mac"], data["vendor"]),
                 "Interface: {} | ARP: {}".format(data["iface"], data["arp_type"]),
                 "OS hint: {} | TTL: {}".format(data["os_detected"], data["ttl"] or "?"),
                 "NetBIOS: {}".format(data["netbios_info"] or "–"),
                 "LLMNR: {}".format(data.get("llmnr_name") or "–"),
                 "iOS sync: {}".format("Yes" if data["ios_sync"] else "No response"),
                 "Ports: {}".format(ports)]
        if data["rtts"]:
            lines.append("RTT: {:.1f}ms average".format(sum(data["rtts"]) / len(data["rtts"])))
        if data["http_info"]:
            lines.append("Web title: {}".format(data["http_info"].get("title") or "–"))
            lines.append("Server: {}".format(data["http_info"].get("server") or "–"))
        if data["ssh_banner"]:
            lines.append("SSH: {}".format(data["ssh_banner"]))
        self.query_one("#inspector", Static).update(Text("\n".join(lines)))

    @work(thread=True, exclusive=True, group="local")
    def _load_local(self):
        self.call_from_thread(self._show_local, get_local_ports())

    def _show_local(self, rows):
        self.local_rows = rows
        table = self.query_one("#local-table", DataTable)
        table.clear()
        for index, row in enumerate(rows):
            table.add_row(str(row["port"]), str(row["pid"]), row["process"], row["address"], key=str(index))
        if rows:
            table.move_cursor(row=0)
        else:
            self.selected_local = None

    def action_kill(self):
        if self.query_one("#tabs", TabbedContent).active != "local" or not self.selected_local:
            return
        self.pending_kill = self.selected_local.copy()
        self.push_screen(ConfirmKill(self.pending_kill), self._confirm_kill)

    def _confirm_kill(self, confirmed):
        row = self.pending_kill
        self.pending_kill = None
        if not confirmed or not row:
            return
        if row["pid"] == os.getpid() or row["pid"] <= 1:
            self.notify("Refusing to stop this process", severity="error")
            return
        # Avoid signaling a reused PID when the original listener has exited.
        if row not in get_local_ports():
            self.notify("Listener changed; refresh and select it again", severity="warning")
            return
        try:
            os.kill(row["pid"], signal.SIGTERM)
            self.notify("Sent SIGTERM to PID {}".format(row["pid"]))
        except OSError as exc:
            self.notify(str(exc), severity="error")
        self._load_local()

    @work(thread=True, exclusive=True, group="traffic")
    def _load_traffic(self):
        try:
            rows = [(str(row["pid"]), row["process"], row["connection"])
                    for row in platforms.get_active_connections()]
            self.call_from_thread(self._show_traffic, rows)
        except (OSError, subprocess.TimeoutExpired, ValueError):
            self.call_from_thread(self._show_traffic, [])

    def _show_traffic(self, rows):
        table = self.query_one("#traffic-table", DataTable)
        table.clear()
        for row in rows:
            table.add_row(*row)

    @work(thread=True, exclusive=True, group="wan")
    def _load_wan(self):
        gateway = get_default_gateway() or "Unknown"
        interfaces = get_active_interfaces()
        dhcp_servers = get_lease_servers(interfaces)
        dhcp_alerts = multiple_servers_on_same_subnet(interfaces, dhcp_servers)
        public_ip = "Unavailable"
        try:
            with urllib.request.urlopen("https://api.ipify.org", timeout=2) as response:
                public_ip = str(ipaddress.ip_address(response.read(64).decode("ascii").strip()))
        except (OSError, ValueError, UnicodeError):
            pass
        lines = ["Default gateway: {}".format(gateway), "Public IP: {}".format(public_ip), "", "Active interfaces:"]
        for item in interfaces:
            lines.append("  {}  {} / {}".format(item["interface"], item["ip"], item["netmask"]))
            if item["interface"] in dhcp_servers:
                lines.append("    DHCP lease server: {}".format(dhcp_servers[item["interface"]]))
        for subnet, servers in dhcp_alerts.items():
            lines.append("[!] {} has multiple DHCP lease servers: {}".format(subnet, ", ".join(servers)))
        lines.extend(["", "UPnP port mappings:"])
        announcements = query_ssdp(timeout=0.7)
        mappings = get_port_mappings(gateway, announcements.get(gateway, {}).get("location", "")) if gateway != "Unknown" else []
        if mappings:
            for mapping in mappings:
                lines.append("  {external_port}/{protocol} -> {internal_client}:{internal_port}  {description}".format(**mapping))
        else:
            lines.append("  None advertised or access denied by router")
        self.call_from_thread(self.query_one("#wan-info", Static).update, Text("\n".join(lines)))
