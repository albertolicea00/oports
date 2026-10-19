"""Read existing UPnP IGD port mappings without changing router state."""

import ipaddress
import re
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _local_url(ip, url):
    parsed = urllib.parse.urlsplit(url)
    return parsed.scheme == "http" and ipaddress.ip_address(parsed.hostname) == ipaddress.ip_address(ip)


def get_port_mappings(ip, location, limit=12, timeout=0.7):
    """Return up to `limit` mappings from an IGD's WAN connection service."""
    try:
        if not _local_url(ip, location):
            return []
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
        with opener.open(location, timeout=timeout) as response:
            root = ET.fromstring(response.read(32768))
        service = next((entry for entry in root.findall(".//{*}service")
                        if re.fullmatch(r"urn:schemas-upnp-org:service:WAN(?:IP|PPP)Connection:[12]",
                                        entry.findtext("{*}serviceType", default=""))), None)
        if service is None:
            return []
        kind = service.findtext("{*}serviceType")
        path = service.findtext("{*}controlURL", default="")
        target = urllib.parse.urljoin(location, path)
        if not path or not _local_url(ip, target):
            return []
        mappings = []
        for index in range(max(0, min(limit, 30))):
            body = ('<?xml version="1.0"?>'
                    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                    's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
                    '<s:Body><u:GetGenericPortMappingEntry xmlns:u="{}">'
                    '<NewPortMappingIndex>{}</NewPortMappingIndex>'
                    '</u:GetGenericPortMappingEntry></s:Body></s:Envelope>').format(kind, index).encode("utf-8")
            request = urllib.request.Request(target, data=body, headers={
                "Content-Type": 'text/xml; charset="utf-8"',
                "SOAPAction": '"{}#GetGenericPortMappingEntry"'.format(kind),
            })
            try:
                with opener.open(request, timeout=timeout) as response:
                    answer = ET.fromstring(response.read(16384))
            except (OSError, ET.ParseError):
                break
            fields = {}
            for name in ("NewExternalPort", "NewProtocol", "NewInternalClient", "NewInternalPort", "NewPortMappingDescription"):
                value = answer.findtext(".//{*}" + name, default="")
                fields[name] = " ".join(value.split())[:100]
            if not fields["NewExternalPort"]:
                break
            mappings.append({
                "external_port": fields["NewExternalPort"],
                "protocol": fields["NewProtocol"],
                "internal_client": fields["NewInternalClient"],
                "internal_port": fields["NewInternalPort"],
                "description": fields["NewPortMappingDescription"],
            })
        return mappings
    except (OSError, ValueError, TypeError, ET.ParseError):
        return []
