from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class PacketKind(StrEnum):
    ARP = 'arp'
    DHCPV4 = 'dhcpv4'
    DHCPV6 = 'dhcpv6'
    DNS = 'dns'
    MDNS = 'mdns'
    SSDP = 'ssdp'
    LLMNR = 'llmnr'
    NBNS = 'nbns'
    ICMPV6_ND = 'icmpv6_nd'
    TLS_CLIENT_HELLO = 'tls_client_hello'
    TLS_SERVER_HELLO = 'tls_server_hello'
    TLS_CERTIFICATE = 'tls_certificate'


@dataclass(slots=True, frozen=True)
class Endpoint:
    address: str | None = None
    port: int | None = None
    mac: str | None = None

    @property
    def label(self) -> str:
        value = self.address or self.mac or '<unknown>'
        return f'{value}:{self.port}' if self.port is not None else value


@dataclass(slots=True, frozen=True)
class PacketContext:
    timestamp: float
    frame_number: int | None
    interface_name: str | None
    ether_type: int | None
    ip_version: int | None
    src: Endpoint
    dst: Endpoint
    transport: str | None
    payload_bytes: bytes
    raw_packet: Any

    @property
    def is_udp(self) -> bool:
        return self.transport == 'udp'

    @property
    def is_tcp(self) -> bool:
        return self.transport == 'tcp'


@dataclass(slots=True, frozen=True)
class ParsedEvent:
    kind: PacketKind
    summary: str
    data: Any


@dataclass(slots=True)
class HostInventory:
    ipv4_addresses: set[str] = field(default_factory=set)
    ipv6_addresses: set[str] = field(default_factory=set)
    mac_addresses: set[str] = field(default_factory=set)
    hostnames: set[str] = field(default_factory=set)
    service_names: set[str] = field(default_factory=set)
    ssdp_locations: set[str] = field(default_factory=set)
    tls_names: set[str] = field(default_factory=set)
