"""
OUI Vendor lookup module for OPorts.
Includes built-in common vendors, private MAC detection, and local caching.
"""

import json
import os
import urllib.request
import urllib.error

CACHE_DIR = os.path.expanduser("~/.cache/oports")
CACHE_FILE = os.path.join(CACHE_DIR, "vendors.json")

COMMON_VENDORS = {
    # Routers & Networking
    "34:E8:94": "TP-Link Technologies",
    "50:C7:BF": "TP-Link Technologies",
    "C0:25:E9": "TP-Link Technologies",
    "E8:48:B8": "TP-Link Technologies",
    "14:EB:B6": "TP-Link Technologies",
    "00:1D:AA": "TP-Link Technologies",
    "F4:F2:6D": "TP-Link Technologies",
    "70:4F:57": "TP-Link Technologies",
    "00:14:D1": "Trends / Netgear",
    "20:E5:2A": "Netgear",
    "00:1F:33": "Netgear",
    "B0:7F:B9": "Netgear",
    "00:18:0A": "Cisco Meraki",
    "00:00:0C": "Cisco Systems",
    "00:01:42": "Cisco Systems",
    "00:26:88": "Huawei Technologies",
    "70:7B:E8": "Huawei Technologies",
    "00:1E:10": "Huawei Technologies",
    "00:22:93": "ZTE Corporation",
    "00:19:70": "ZTE Corporation",
    "00:15:70": "ZTE Corporation",
    "78:11:DC": "Xiaomi Communications",
    "04:CF:8C": "Xiaomi Communications",
    "64:09:80": "Xiaomi Communications",
    "00:1A:2B": "ASUSTek Computer",
    "AC:9E:17": "ASUSTek Computer",
    "04:D4:C4": "ASUSTek Computer",
    "00:0C:43": "Ralink Technology",
    "00:E0:4C": "Realtek Semiconductor",
    "52:54:00": "QEMU Virtual NIC",
    "08:00:27": "PCS Systemtechnik (VirtualBox)",
    "00:05:69": "VMware, Inc.",
    "00:0C:29": "VMware, Inc.",

    # PCs & Laptops
    "8C:04:BA": "Dell Inc.",
    "18:66:DA": "Dell Inc.",
    "34:17:EB": "Dell Inc.",
    "B8:85:84": "Dell Inc.",
    "48:4D:7E": "Dell Inc.",
    "D4:81:D7": "Dell Inc.",
    "00:14:22": "Dell Inc.",
    "00:1E:4F": "Dell Inc.",
    "00:23:7D": "HP Inc.",
    "3C:D9:2B": "HP Inc.",
    "B4:B5:2F": "HP Inc.",
    "AC:16:2D": "HP Inc.",
    "00:21:5C": "Intel Corporate",
    "00:1E:64": "Intel Corporate",
    "3C:F8:62": "Intel Corporate",
    "DC:71:96": "Intel Corporate",
    "F4:4D:30": "Intel Corporate",
    "00:1A:64": "Lenovo Mobile",
    "00:23:18": "Lenovo",
    "54:EE:75": "Lenovo",
    "00:50:56": "VMware",

    # Apple
    "00:17:F2": "Apple, Inc.",
    "00:1C:B3": "Apple, Inc.",
    "00:1E:52": "Apple, Inc.",
    "00:23:12": "Apple, Inc.",
    "00:25:00": "Apple, Inc.",
    "00:26:08": "Apple, Inc.",
    "00:26:B0": "Apple, Inc.",
    "28:CF:E9": "Apple, Inc.",
    "3C:07:54": "Apple, Inc.",
    "40:6C:8F": "Apple, Inc.",
    "48:43:7C": "Apple, Inc.",
    "5C:95:AE": "Apple, Inc.",
    "60:C5:47": "Apple, Inc.",
    "70:70:8B": "Apple, Inc.",
    "88:66:A5": "Apple, Inc.",
    "90:B2:1F": "Apple, Inc.",
    "A4:5E:60": "Apple, Inc.",
    "AC:BC:32": "Apple, Inc.",
    "C8:69:CD": "Apple, Inc.",
    "DC:2B:61": "Apple, Inc.",
    "F0:18:98": "Apple, Inc.",
    "F4:34:F0": "Apple, Inc.",
    "F8:FF:C2": "Apple, Inc.",

    # Mobile & IoT
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading",
    "E4:5F:01": "Raspberry Pi Trading",
    "28:CD:C1": "Raspberry Pi Trading",
    "30:AE:A4": "Espressif Inc.",
    "24:6F:28": "Espressif Inc.",
    "A4:CF:12": "Espressif Inc.",
    "3C:71:BF": "Espressif Inc.",
    "44:17:93": "Samsung Electronics",
    "50:85:69": "Samsung Electronics",
    "AC:5F:3E": "Samsung Electronics",
    "00:1A:11": "Google, Inc.",
    "F4:F5:D8": "Google, Inc.",
    "54:60:09": "Google, Inc.",
    "FC:65:DE": "Amazon Technologies",
    "44:65:0D": "Amazon Technologies",
}

def is_private_mac(mac: str) -> bool:
    """
    Returns True if the MAC address has the locally administered bit set (bit 1 of octet 0).
    Modern operating systems (iOS, iPadOS, Android, Windows 10/11, macOS) use this for MAC randomization.
    """
    try:
        first_byte = int(mac.split(":")[0], 16)
        return bool(first_byte & 2)
    except Exception:
        return False

def _load_cache() -> dict:
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def _save_cache(cache: dict):
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
    except Exception:
        pass

def lookup_vendor(mac: str, allow_online: bool = True) -> str:
    """
    Identifies the hardware vendor or privacy status of a MAC address.
    """
    if not mac or mac == "(incomplete)" or mac.lower() == "ff:ff:ff:ff:ff:ff":
        return "N/A"

    parts = mac.upper().split(":")
    if len(parts) < 3:
        return "Unknown"

    # Standardize MAC format
    mac_upper = ":".join(f"{int(x, 16):02X}" for x in parts)
    oui = ":".join(mac_upper.split(":")[:3])

    if is_private_mac(mac_upper):
        return "Private / Randomized"

    if oui in COMMON_VENDORS:
        return COMMON_VENDORS[oui]

    cache = _load_cache()
    if oui in cache:
        return cache[oui]

    if allow_online:
        try:
            url = f"https://api.macvendors.com/{oui}"
            req = urllib.request.Request(url, headers={"User-Agent": "OPorts-CLI/1.0"})
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                vendor = resp.read().decode("utf-8").strip()
                if vendor:
                    cache[oui] = vendor
                    _save_cache(cache)
                    return vendor
        except Exception:
            pass

    return "Unknown"
