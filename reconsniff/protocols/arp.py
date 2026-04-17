from scapy.layers.l2 import ARP

from reconsniff.models.core import PacketContext, PacketKind, ParsedEvent
from reconsniff.models.discovery import ArpRecord
from reconsniff.protocols.base import BaseParser

_ARP_ETHERTYPE = 0x0806

_ARP_OP_NAMES: dict[int, str] = {
    1: 'request',
    2: 'reply',
    3: 'rarp-request',
    4: 'rarp-reply',
    8: 'drarp-request',
    9: 'drarp-reply',
    10: 'drarp-error',
    11: 'inarp-request',
    12: 'inarp-reply',
}


class ArpParser(BaseParser):
    kind = PacketKind.ARP

    def matches(self, context: PacketContext) -> bool:
        return context.ether_type == _ARP_ETHERTYPE and ARP in context.raw_packet

    def parse(self, context: PacketContext) -> ParsedEvent:
        layer = context.raw_packet[ARP]
        op = int(layer.op)
        sender_ip = str(layer.psrc)
        sender_mac = str(layer.hwsrc)
        target_ip = str(layer.pdst)
        target_mac = str(layer.hwdst)

        is_probe = sender_ip == '0.0.0.0'
        is_announcement = (
            sender_ip == target_ip or target_mac.lower() == 'ff:ff:ff:ff:ff:ff'
        )

        record = ArpRecord(
            operation=op,
            sender_mac=sender_mac,
            sender_ipv4=sender_ip,
            target_mac=target_mac,
            target_ipv4=target_ip,
            is_probe=is_probe,
            is_announcement=is_announcement,
        )

        op_name = _ARP_OP_NAMES.get(op, f'op={op}')
        hint = ' [probe]' if is_probe else ' [announcement]' if is_announcement else ''
        summary = f'ARP {op_name}: {sender_ip} ({sender_mac}) -> {target_ip}{hint}'

        return ParsedEvent(kind=self.kind, summary=summary, data=record)
