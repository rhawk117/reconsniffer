import dataclasses as dc
from collections.abc import Callable
from typing import TYPE_CHECKING

from scapy.sendrecv import AsyncSniffer

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

if TYPE_CHECKING:
    from reconsniff.protocols.base import PacketContext, ParsedEvent, ProtocolAdapter

@dc.dataclass(slots=True)
class RuntimeConfig:
    interface: str | None
    bpf_filter: str
    store_packets: bool = False


@dc.dataclass(slots=True)
class CaptureRuntime:
    config: RuntimeConfig
    registry: _ProtocolRegistry
    events_seen: int = 0
    sniffer: AsyncSniffer | None = None
    emitted_events: list[ParsedEvent] = dc.field(default_factory=list)

    def on_event(self, event: ParsedEvent) -> None:
        self.events_seen += 1
        self.emitted_events.append(event)

    def start(self) -> None:
        self.sniffer = build_sniffer(
            self.registry,
            self.on_event,
            iface=self.config.interface,
            bpf_filter=self.config.bpf_filter,
            store=self.config.store_packets,
        )
        self.sniffer.start()

    def stop(self) -> None:
        if self.sniffer is None:
            return
        self.sniffer.stop()



@dc.dataclass(slots=True)
class _ProtocolRegistry:
    adapters: list[ProtocolAdapter] = dc.field(default_factory=list)

    def register(self, parser: ProtocolAdapter) -> None:
        self.adapters.append(parser)

    def register_all(self, *adapters: ProtocolAdapter) -> None:
        self.adapters.extend(adapters)

    def parse_first(self, context: PacketContext) -> ParsedEvent | None:
        for parser in self.adapters:
            if not parser.matches(context):
                continue
            return parser.parse(context)
        return None

    def parse_all(self, context: PacketContext) -> list[ParsedEvent]:
        events: list[ParsedEvent] = []
        for parser in self.adapters:
            if not parser.matches(context):
                continue
            events.append(parser.parse(context))

        return events





def build_sniffer(
    registry: _ProtocolRegistry,
    on_event: Callable[[ParsedEvent], None],
    *,
    iface: str | None,
    bpf_filter: str,
    store: bool = False,
) -> AsyncSniffer:

    def handle_packet(packet: object) -> None:
        context = packet_to_context(packet)  # type: ignore[arg-type]
        for event in registry.parse_all(context):
            on_event(event)

    return AsyncSniffer(
        iface=iface,
        filter=bpf_filter,
        prn=handle_packet,
        store=store,
    )


def create_protocol_registry() -> _ProtocolRegistry:
    registry = _ProtocolRegistry()
    registry.register_all(
        ArpParser(),
        Dhcpv4Parser(),
        Dhcpv6Parser(),
        MdnsParser(),
        LlmnrParser(),
        NbnsParser(),
        SsdpParser(),
        Icmpv6NdParser(),
        DnsParser(),
        TlsClientHelloParser(),
        TlsServerHelloParser(),
        TlsCertificateParser()
    )
    return registry
