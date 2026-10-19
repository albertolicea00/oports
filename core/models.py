"""Shared data shapes returned by the scanning engine."""

from typing import Dict, List, Optional, TypedDict


class Interface(TypedDict):
    interface: str
    ip: str
    netmask: str
    broadcast: str
    mac: str


class Port(TypedDict):
    pid: int
    process: str
    address: str
    port: int


class Device(TypedDict):
    ip: str
    mac: str
    vendor: str
    name: str
    notes: str
    rtt: Optional[float]
    open_ports: List[int]


class ScanResult(TypedDict):
    subnet: str
    total_devices: int
    devices: List[Device]
