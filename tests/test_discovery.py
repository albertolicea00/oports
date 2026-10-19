"""Protocol parsing tests with local synthetic packets."""

import struct
import io
import unittest
from unittest.mock import patch

from cli.dhcp import get_lease_servers, multiple_servers_on_same_subnet
from cli.discovery import query_llmnr_ptr
from cli.upnp import get_port_mappings


class FakeSocket:
    def __init__(self, data):
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def settimeout(self, value):
        pass

    def sendall(self, data):
        pass

    def recv(self, count):
        part, self.data = self.data[:count], self.data[count:]
        return part


class DiscoveryTests(unittest.TestCase):
    def test_llmnr_reverse_ptr(self):
        qname = b"\x011\x011\x03168\x03192\x07in-addr\x04arpa\x00"
        question = qname + struct.pack(">HH", 12, 1)
        name = b"\x07DESKTOP\x00"
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 12, 1, 0, len(name)) + name
        packet = struct.pack(">HHHHHH", 0x4F50, 0x8000, 1, 1, 0, 0) + question + answer
        socket = FakeSocket(struct.pack(">H", len(packet)) + packet)
        with patch("cli.discovery.socket.create_connection", return_value=socket):
            self.assertEqual(query_llmnr_ptr("192.168.1.1"), "DESKTOP")

    def test_dhcp_lease_servers_same_subnet(self):
        interfaces = [
            {"interface": "en0", "ip": "192.168.1.100", "netmask": "255.255.255.0"},
            {"interface": "en6", "ip": "192.168.1.101", "netmask": "255.255.255.0"},
        ]

        def lease(command, **kwargs):
            server = "192.168.1.1" if command[-1] == "en0" else "192.168.1.254"
            return type("Result", (), {"stdout": "server_identifier (ip): {}\n".format(server)})()

        with patch("cli.dhcp.subprocess.run", side_effect=lease):
            servers = get_lease_servers(interfaces)
        self.assertEqual(multiple_servers_on_same_subnet(interfaces, servers),
                         {"192.168.1.0/24": ["192.168.1.1", "192.168.1.254"]})

    def test_upnp_mapping_is_read_from_gateway(self):
        descriptor = (b"<root><device><serviceList><service>"
                      b"<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>"
                      b"<controlURL>/control</controlURL>"
                      b"</service></serviceList></device></root>")
        mapping = (b"<Envelope><Body><GetGenericPortMappingEntryResponse>"
                   b"<NewExternalPort>8080</NewExternalPort><NewProtocol>TCP</NewProtocol>"
                   b"<NewInternalClient>192.168.1.100</NewInternalClient>"
                   b"<NewInternalPort>80</NewInternalPort>"
                   b"<NewPortMappingDescription>Web</NewPortMappingDescription>"
                   b"</GetGenericPortMappingEntryResponse></Body></Envelope>")

        class Opener:
            def __init__(self):
                self.calls = 0

            def open(self, request, timeout):
                self.calls += 1
                return io.BytesIO(descriptor if self.calls == 1 else mapping)

        with patch("cli.upnp.urllib.request.build_opener", return_value=Opener()):
            rows = get_port_mappings("192.168.1.1", "http://192.168.1.1/root.xml", limit=1)
        self.assertEqual(rows[0]["external_port"], "8080")
        self.assertEqual(rows[0]["internal_client"], "192.168.1.100")
        self.assertEqual(get_port_mappings("192.168.1.1", "http://example.com/root.xml"), [])


if __name__ == "__main__":
    unittest.main()
