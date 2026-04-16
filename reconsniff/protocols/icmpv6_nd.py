from scapy.layers.inet6 import (
    ICMPv6ND_NA,
    ICMPv6ND_NS,
    ICMPv6ND_RA,
    ICMPv6ND_RS,
    ICMPv6NDOptDstLLAddr,
    ICMPv6NDOptMTU,
    ICMPv6NDOptPrefixInfo,
    ICMPv6NDOptSrcLLAddr,
)

from reconsniff.models.core import PacketContext, PacketKind, ParsedEvent
from reconsniff.models.discovery import Icmpv6NdOption, Icmpv6NdRecord
from reconsniff.protocols.base import BaseParser


class Icmpv6NdParser(BaseParser):
    kind = PacketKind.ICMPV6_ND

    def matches(self, context: PacketContext) -> bool:
        packet = context.raw_packet
        return context.ip_version == 6 and (
            ICMPv6ND_NS in packet
            or ICMPv6ND_NA in packet
            or ICMPv6ND_RS in packet
            or ICMPv6ND_RA in packet
        )

    def parse(self, context: PacketContext) -> ParsedEvent:
        packet = context.raw_packet

        icmpv6_type = 0
        code = 0
        target_ipv6: str | None = None
        source_ll: str | None = None
        target_ll: str | None = None
        router_lifetime: int | None = None
        reachable_time_ms: int | None = None
        retrans_timer_ms: int | None = None
        prefix_info: list[str] = []
        mtu: int | None = None
        flags: dict[str, bool] = {}
        options: list[Icmpv6NdOption] = []

        if ICMPv6ND_NS in packet:
            layer = packet[ICMPv6ND_NS]
            icmpv6_type = 135
            code = int(getattr(layer, 'code', 0))
            target_ipv6 = str(getattr(layer, 'tgt', ''))
        elif ICMPv6ND_NA in packet:
            layer = packet[ICMPv6ND_NA]
            icmpv6_type = 136
            code = int(getattr(layer, 'code', 0))
            target_ipv6 = str(getattr(layer, 'tgt', ''))
            flags = {
                'router': bool(int(getattr(layer, 'R', 0))),
                'solicited': bool(int(getattr(layer, 'S', 0))),
                'override': bool(int(getattr(layer, 'O', 0))),
            }
        elif ICMPv6ND_RS in packet:
            layer = packet[ICMPv6ND_RS]
            icmpv6_type = 133
            code = int(getattr(layer, 'code', 0))
        else:
            layer = packet[ICMPv6ND_RA]
            icmpv6_type = 134
            code = int(getattr(layer, 'code', 0))
            router_lifetime = int(getattr(layer, 'routerlifetime', 0))
            reachable_time_ms = int(getattr(layer, 'reachabletime', 0))
            retrans_timer_ms = int(getattr(layer, 'retranstimer', 0))

        if ICMPv6NDOptSrcLLAddr in packet:
            source_ll = str(packet[ICMPv6NDOptSrcLLAddr].lladdr)
            options.append(Icmpv6NdOption(option_type=1, value_text=source_ll))

        if ICMPv6NDOptDstLLAddr in packet:
            target_ll = str(packet[ICMPv6NDOptDstLLAddr].lladdr)
            options.append(Icmpv6NdOption(option_type=2, value_text=target_ll))

        if ICMPv6NDOptPrefixInfo in packet:
            prefix_option = packet[ICMPv6NDOptPrefixInfo]
            prefix_value = f'{prefix_option.prefix}/{prefix_option.prefixlen}'
            prefix_info.append(prefix_value)
            options.append(Icmpv6NdOption(option_type=3, value_text=prefix_value))

        if ICMPv6NDOptMTU in packet:
            mtu = int(packet[ICMPv6NDOptMTU].mtu)
            options.append(Icmpv6NdOption(option_type=5, value_text=str(mtu)))

        record = Icmpv6NdRecord(
            icmpv6_type=icmpv6_type,
            code=code,
            source_ipv6=context.src.address,
            target_ipv6=target_ipv6,
            source_link_layer_address=source_ll,
            target_link_layer_address=target_ll,
            router_lifetime=router_lifetime,
            reachable_time_ms=reachable_time_ms,
            retrans_timer_ms=retrans_timer_ms,
            prefix_info=tuple(prefix_info),
            mtu=mtu,
            flags=flags,
            options=tuple(options),
        )

        return ParsedEvent(
            kind=self.kind,
            summary=f'ICMPv6 ND type={record.icmpv6_type} src={record.source_ipv6} target={record.target_ipv6}',
            data=record,
        )
