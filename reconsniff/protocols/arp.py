from scapy.layers.l2 import ARP

from reconsniff.models.core import PacketContext, PacketKind, ParsedEvent
from reconsniff.models.discovery import ArpRecord
from reconsniff.protocols.base import BaseParser

MAGIC_ETHER_TYPE = 0x0806

class ArpParser(BaseParser):
    kind = PacketKind.ARP

    def matches(self, context: PacketContext) -> bool:
        return context.ether_type == MAGIC_ETHER_TYPE  and ARP in context.raw_packet

    def parse(self, context: PacketContext) -> ParsedEvent:
        arp_layer = context.raw_packet[ARP]

        record = ArpRecord(
            operation=int(arp_layer.op),
            sender_mac=str(arp_layer.hwsrc),
            sender_ipv4=str(arp_layer.psrc),
            target_mac=str(arp_layer.hwdst),
            target_ipv4=str(arp_layer.pdst),
            is_probe=str(arp_layer.psrc) == '0.0.0.0',
            is_announcement=(
                str(arp_layer.psrc) == str(arp_layer.pdst)
                or str(arp_layer.hwdst).lower() == 'ff:ff:ff:ff:ff:ff'
            ),
        )

        summary = (
            f'ARP op={record.operation} {record.sender_ipv4} is-at {record.sender_mac}'
        )

        return ParsedEvent(
            kind=self.kind,
            summary=summary,
            data=record,
        )
