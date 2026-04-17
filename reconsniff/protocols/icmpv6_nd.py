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
from scapy.packet import Packet

from reconsniff.models.core import PacketContext, PacketKind, ParsedEvent
from reconsniff.models.discovery import Icmpv6NdOption, Icmpv6NdRecord
from reconsniff.protocols.base import BaseParser

_ND_TYPE_NAMES: dict[int, str] = {
    133: 'RS',  # Router Solicitation
    134: 'RA',  # Router Advertisement
    135: 'NS',  # Neighbor Solicitation
    136: 'NA',  # Neighbor Advertisement
}


def _collect_options(packet: Packet) -> tuple[Icmpv6NdOption, ...]:
    options: list[Icmpv6NdOption] = []
    if ICMPv6NDOptSrcLLAddr in packet:
        options.append(
            Icmpv6NdOption(
                option_type=1, value_text=str(packet[ICMPv6NDOptSrcLLAddr].lladdr)
            )
        )
    if ICMPv6NDOptDstLLAddr in packet:
        options.append(
            Icmpv6NdOption(
                option_type=2, value_text=str(packet[ICMPv6NDOptDstLLAddr].lladdr)
            )
        )
    if ICMPv6NDOptPrefixInfo in packet:
        opt = packet[ICMPv6NDOptPrefixInfo]
        options.append(
            Icmpv6NdOption(option_type=3, value_text=f'{opt.prefix}/{opt.prefixlen}')
        )
    if ICMPv6NDOptMTU in packet:
        options.append(
            Icmpv6NdOption(option_type=5, value_text=str(packet[ICMPv6NDOptMTU].mtu))
        )
    return tuple(options)


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

        if ICMPv6ND_NS in packet:
            nd_type, flags, target, lifetime, reach, retrans, prefixes = _parse_ns(packet)
        elif ICMPv6ND_NA in packet:
            nd_type, flags, target, lifetime, reach, retrans, prefixes = _parse_na(packet)
        elif ICMPv6ND_RS in packet:
            nd_type, flags, target, lifetime, reach, retrans, prefixes = _parse_rs()
        else:
            nd_type, flags, target, lifetime, reach, retrans, prefixes = _parse_ra(packet)

        source_ll = (
            str(packet[ICMPv6NDOptSrcLLAddr].lladdr)
            if ICMPv6NDOptSrcLLAddr in packet
            else None
        )
        target_ll = (
            str(packet[ICMPv6NDOptDstLLAddr].lladdr)
            if ICMPv6NDOptDstLLAddr in packet
            else None
        )
        mtu = int(packet[ICMPv6NDOptMTU].mtu) if ICMPv6NDOptMTU in packet else None

        record = Icmpv6NdRecord(
            icmpv6_type=nd_type,
            code=0,
            source_ipv6=context.src.address,
            target_ipv6=target,
            source_link_layer_address=source_ll,
            target_link_layer_address=target_ll,
            router_lifetime=lifetime,
            reachable_time_ms=reach,
            retrans_timer_ms=retrans,
            prefix_info=tuple(prefixes),
            mtu=mtu,
            flags=flags,
            options=_collect_options(packet),
        )

        type_name = _ND_TYPE_NAMES.get(nd_type, str(nd_type))
        parts = [f'ICMPv6 ND {type_name} src={context.src.address}']
        if target:
            parts.append(f'target={target}')
        if prefixes:
            parts.append(f'prefix={prefixes[0]}')
        if source_ll:
            parts.append(f'mac={source_ll}')

        return ParsedEvent(kind=self.kind, summary=' '.join(parts), data=record)


def _parse_ns(packet: Packet) -> tuple:
    layer = packet[ICMPv6ND_NS]
    return (
        135,
        {},
        str(getattr(layer, 'tgt', '')),
        None,
        None,
        None,
        [],
    )


def _parse_na(packet: Packet) -> tuple:
    layer = packet[ICMPv6ND_NA]
    flags = {
        'router': bool(int(getattr(layer, 'R', 0))),
        'solicited': bool(int(getattr(layer, 'S', 0))),
        'override': bool(int(getattr(layer, 'O', 0))),
    }
    return (
        136,
        flags,
        str(getattr(layer, 'tgt', '')),
        None,
        None,
        None,
        [],
    )


def _parse_rs() -> tuple:
    return (133, {}, None, None, None, None, [])


def _parse_ra(packet: Packet) -> tuple:
    layer = packet[ICMPv6ND_RA]
    flags = {
        'managed': bool(int(getattr(layer, 'M', 0))),  # M: use DHCPv6 for addresses
        'other': bool(int(getattr(layer, 'O', 0))),  # O: use DHCPv6 for other config
        'home': bool(int(getattr(layer, 'H', 0))),  # H: mobile IPv6 home agent
    }
    prefixes: list[str] = []
    if ICMPv6NDOptPrefixInfo in packet:
        opt = packet[ICMPv6NDOptPrefixInfo]
        prefixes.append(f'{opt.prefix}/{opt.prefixlen}')

    return (
        134,
        flags,
        None,
        int(getattr(layer, 'routerlifetime', 0)),
        int(getattr(layer, 'reachabletime', 0)),
        int(getattr(layer, 'retranstimer', 0)),
        prefixes,
    )
