
import dataclasses as dc
from enum import StrEnum
from typing import Any


class PacketKind(StrEnum):
    ARP = 'arp'
    DHCPV4 = 'dhcpv4'
    DHCPV6 = 'dhcpv6'
    MDNS = 'mdns'
    SSDP = 'ssdp'
    LLMNR = 'llmnr'
    NBNS = 'nbns'
    ICMPV6_ND = 'icmpv6_nd'
    DNS = 'dns'
    TLS_CLIENT_HELLO = 'tls_client_hello'
    TLS_SERVER_HELLO = 'tls_server_hello'
    TLS_CERTIFICATE = 'tls_certificate'


@dc.dataclass(slots=True, frozen=True)
class Endpoint:
    address: str | None = None
    port: int | None = None
    mac: str | None = None

    @property
    def label(self) -> str:
        address = self.address or self.mac or '<unknown>'
        return f'{address}:{self.port}' if self.port is not None else address


@dc.dataclass(slots=True, frozen=True)
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


@dc.dataclass(slots=True, frozen=True)
class ParsedEvent:
    kind: PacketKind
    summary: str
    data: Any

@dc.dataclass(slots=True, frozen=True)
class ArpRecord:
    operation: int
    sender_mac: str
    sender_ipv4: str
    target_mac: str
    target_ipv4: str
    is_probe: bool
    is_announcement: bool


@dc.dataclass(slots=True, frozen=True)
class Dhcpv4Record:
    message_type: str | None
    transaction_id: int
    client_mac: str | None
    client_ip: str | None
    your_ip: str | None
    server_ip: str | None
    relay_ip: str | None
    hostname: str | None
    requested_ip: str | None
    server_identifier: str | None
    parameter_request_list: tuple[int, ...]
    vendor_class_id: str | None
    domain_name: str | None
    router_list: tuple[str, ...]
    dns_servers: tuple[str, ...]
    lease_time_seconds: int | None


@dc.dataclass(slots=True, frozen=True)
class Dhcpv6Record:
    message_type: int
    transaction_id: int | None
    client_duid: str | None
    server_duid: str | None
    ia_na_addresses: tuple[str, ...]
    ia_pd_prefixes: tuple[str, ...]
    dns_servers: tuple[str, ...]
    domain_search_list: tuple[str, ...]
    elapsed_time: int | None
    fqdn: str | None
    vendor_class: tuple[str, ...]


@dc.dataclass(slots=True, frozen=True)
class DnsQuestion:
    name: str
    qtype: int
    qclass: int


@dc.dataclass(slots=True, frozen=True)
class DnsResourceRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int | None
    rdata_text: str


@dc.dataclass(slots=True, frozen=True)
class DnsRecord:
    transaction_id: int
    is_response: bool
    opcode: int
    rcode: int
    aa: bool
    tc: bool
    rd: bool
    ra: bool
    questions: tuple[DnsQuestion, ...]
    answers: tuple[DnsResourceRecord, ...]
    authorities: tuple[DnsResourceRecord, ...]
    additionals: tuple[DnsResourceRecord, ...]


@dc.dataclass(slots=True, frozen=True)
class MdnsRecord:
    dns: DnsRecord
    service_instance_names: tuple[str, ...]
    service_types: tuple[str, ...]
    hostnames: tuple[str, ...]
    advertised_addresses: tuple[str, ...]


@dc.dataclass(slots=True, frozen=True)
class SsdpRecord:
    start_line: str
    method_or_status: str
    host: str | None
    location: str | None
    server: str | None
    user_agent: str | None
    usn: str | None
    st: str | None
    nt: str | None
    nts: str | None
    man: str | None
    mx: int | None
    cache_control: str | None
    bootid_upnp_org: str | None
    configid_upnp_org: str | None
    raw_headers: dict[str, str]


@dc.dataclass(slots=True, frozen=True)
class LlmnrRecord:
    dns: DnsRecord
    queried_names: tuple[str, ...]


@dc.dataclass(slots=True, frozen=True)
class NbnsQuestion:
    encoded_name: str
    qtype: int
    qclass: int


@dc.dataclass(slots=True, frozen=True)
class NbnsRecord:
    transaction_id: int
    is_response: bool
    opcode: int
    rcode: int
    questions: tuple[NbnsQuestion, ...]
    answers: tuple[str, ...]
    node_status_names: tuple[str, ...]


@dc.dataclass(slots=True, frozen=True)
class Icmpv6NdOption:
    option_type: int
    value_text: str


@dc.dataclass(slots=True, frozen=True)
class Icmpv6NdRecord:
    icmpv6_type: int
    code: int
    source_ipv6: str | None
    target_ipv6: str | None
    source_link_layer_address: str | None
    target_link_layer_address: str | None
    router_lifetime: int | None
    reachable_time_ms: int | None
    retrans_timer_ms: int | None
    prefix_info: tuple[str, ...]
    mtu: int | None
    flags: dict[str, bool]
    options: tuple[Icmpv6NdOption, ...]


@dc.dataclass(slots=True, frozen=True)
class TlsClientHelloRecord:
    record_version: str | None
    client_version: str | None
    sni: str | None
    alpn_protocols: tuple[str, ...]
    cipher_suites: tuple[int, ...]
    supported_groups: tuple[int, ...]
    signature_algorithms: tuple[int, ...]
    ja3_input: str | None


@dc.dataclass(slots=True, frozen=True)
class TlsServerHelloRecord:
    selected_version: str | None
    selected_cipher_suite: int | None
    selected_alpn: str | None
    ja3s_input: str | None


@dc.dataclass(slots=True, frozen=True)
class TlsCertificateRecord:
    subject: str | None
    issuer: str | None
    serial_number: str | None
    not_before: str | None
    not_after: str | None
    san_dns_names: tuple[str, ...]
    san_ip_addresses: tuple[str, ...]
