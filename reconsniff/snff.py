import dataclasses as dc
from collections.abc import Callable
from contextlib import suppress
from typing import Any

from scapy.sendrecv import AsyncSniffer

from reconsniff.models.core import PacketContext, ParsedEvent
from reconsniff.protocols.arp import ArpParser
from reconsniff.protocols.dhcp import Dhcpv4Parser, Dhcpv6Parser
from reconsniff.protocols.dns import DnsParser
from reconsniff.protocols.icmpv6_nd import Icmpv6NdParser
from reconsniff.protocols.llmnr import LlmnrParser
from reconsniff.protocols.mdns import MdnsParser
from reconsniff.protocols.nbns import NbnsParser
from reconsniff.protocols.normalize import packet_to_context
from reconsniff.protocols.ssdp import SsdpParser
from reconsniff.protocols.tls import (
    TlsCertificateParser,
    TlsClientHelloParser,
    TlsServerHelloParser,
)

EventCallback = Callable[[PacketContext, ParsedEvent], None]

_PARSER_TABLE: tuple[tuple[str, type], ...] = (
    ('arp', ArpParser),
    ('dhcp', Dhcpv4Parser),
    ('dhcpv6', Dhcpv6Parser),
    ('mdns', MdnsParser),
    ('llmnr', LlmnrParser),
    ('nbns', NbnsParser),
    ('ssdp', SsdpParser),
    ('icmpv6nd', Icmpv6NdParser),
    ('dns', DnsParser),
    ('tls', TlsClientHelloParser),
    ('tls', TlsServerHelloParser),
    ('tls', TlsCertificateParser),
)


@dc.dataclass(slots=True)
class _ProtocolRegistry:
    _adapters: list[Any] = dc.field(default_factory=list, init=False)

    def register(self, parser: Any) -> None:
        self._adapters.append(parser)

    def parse_all(self, context: PacketContext) -> list[ParsedEvent]:
        events: list[ParsedEvent] = []
        for parser in self._adapters:
            if parser.matches(context):
                events.append(parser.parse(context))
        return events


@dc.dataclass(slots=True)
class CaptureEngine:
    registry: _ProtocolRegistry
    on_event: EventCallback
    interface: str | None
    bpf_filter: str
    store_packets: bool = False
    _sniffer: AsyncSniffer | None = dc.field(default=None, init=False)

    def start(self) -> None:
        def _handle(packet: Any) -> None:
            context = packet_to_context(packet)
            for event in self.registry.parse_all(context):
                self.on_event(context, event)

        self._sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=_handle,
            store=self.store_packets,
        )
        self._sniffer.start()

    def stop(self) -> None:
        if self._sniffer is None:
            return
        with suppress(Exception):
            self._sniffer.stop()


def create_protocol_registry(excluded: frozenset[str]) -> _ProtocolRegistry:
    registry = _ProtocolRegistry()
    for proto_key, parser_cls in _PARSER_TABLE:
        if proto_key not in excluded:
            registry.register(parser_cls())
    return registry


def build_bpf_filter(
    excluded: frozenset[str],
    dns_port: int = 53,
    mdns_port: int = 5353,
    ssdp_port: int = 1900,
) -> str:
    clauses: list[str] = []

    if 'arp' not in excluded:
        clauses.append('arp')
    if 'dhcp' not in excluded:
        clauses.extend(['udp port 67', 'udp port 68'])
    if 'dhcpv6' not in excluded:
        clauses.extend(['udp port 546', 'udp port 547'])
    if 'dns' not in excluded:
        clauses.append(f'udp port {dns_port}')
    if 'mdns' not in excluded:
        clauses.append(f'udp port {mdns_port}')
    if 'llmnr' not in excluded:
        clauses.append('udp port 5355')
    if 'nbns' not in excluded:
        clauses.append('udp port 137')
    if 'ssdp' not in excluded:
        clauses.append(f'udp port {ssdp_port}')
    if 'icmpv6nd' not in excluded:
        clauses.append('icmp6')
    if 'tls' not in excluded:
        clauses.extend(['tcp port 443', 'tcp port 8443'])

    return ' or '.join(clauses) if clauses else 'udp port 0'
