"""Platform adapters parse native OS data into the shared shape."""

import ipaddress
import unittest
from unittest.mock import patch

from platforms import macos, windows


class PlatformTests(unittest.TestCase):
    def test_windows_interfaces_and_gateway(self):
        raw = [{"interface": "Wi-Fi", "ip": "192.168.1.20", "prefix": 24,
                "mac": "AA-BB-CC-DD-EE-FF", "gateway": "192.168.1.1"}]
        with patch("platforms.windows._powershell", return_value=raw):
            interfaces = windows.get_active_interfaces()
            gateway = windows.get_default_gateway()
        self.assertEqual(interfaces[0]["netmask"], "255.255.255.0")
        self.assertEqual(interfaces[0]["mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(gateway, "192.168.1.1")
        self.assertEqual(windows.ping_command("192.168.1.1"),
                         ["ping", "-n", "1", "-w", "200", "192.168.1.1"])

    def test_windows_neighbor_and_listener_parsing(self):
        neighbors = [{"ip": "192.168.1.1", "mac": "34-E8-94-F8-CC-B0",
                      "interface": "Wi-Fi", "state": "Reachable"},
                     {"ip": "10.0.0.1", "mac": "AA-BB-CC-DD-EE-FF",
                      "interface": "Wi-Fi", "state": "Reachable"}]
        with patch("platforms.windows._powershell", return_value=neighbors):
            entries = windows.get_arp_table(ipaddress.IPv4Network("192.168.1.0/24"))
        self.assertEqual(list(entries), ["192.168.1.1"])
        self.assertEqual(entries["192.168.1.1"]["iface"], "Wi-Fi")
        with patch("platforms.windows._powershell", return_value=[
            {"pid": 42, "process": "service", "address": "0.0.0.0:8080", "port": 8080}]):
            self.assertEqual(windows.get_local_ports()[0]["port"], 8080)

    def test_windows_lease_server_matches_interface(self):
        interfaces = [{"ip": "192.168.1.20", "interface": "Wi-Fi"}]
        with patch("platforms.windows._powershell", return_value=[
            {"ip": "192.168.1.20", "server": "192.168.1.1"}]):
            self.assertEqual(windows.get_lease_servers(interfaces), {"Wi-Fi": "192.168.1.1"})

    def test_macos_arp_excludes_broadcast(self):
        output = "\n".join([
            "? (192.168.1.1) at 34:e8:94:f8:cc:b0 on en0 ifscope [ethernet]",
            "? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]",
        ])
        with patch("platforms.macos.subprocess.run") as run:
            run.return_value.stdout = output
            entries = macos.get_arp_table(ipaddress.IPv4Network("192.168.1.0/24"))
        self.assertEqual(list(entries), ["192.168.1.1"])


if __name__ == "__main__":
    unittest.main()
