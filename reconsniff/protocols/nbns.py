from scapy.layers.netbios import NBNSHeader

from reconsniff.models.core import PacketContext, PacketKind, ParsedEvent
from reconsniff.models.dns import NbnsRecord
from reconsniff.protocols.base import BaseParser


class NbnsParser(BaseParser):
    kind = PacketKind.NBNS

    def matches(self, context: PacketContext) -> bool:
        return (
            context.is_udp
            and (context.src.port == 137 or context.dst.port == 137)
            and NBNSHeader in context.raw_packet
        )

    def parse(self, context: PacketContext) -> ParsedEvent:
        header = context.raw_packet[NBNSHeader]

        record = NbnsRecord(
            transaction_id=int(getattr(header, 'NAME_TRN_ID', 0)),
            is_response=bool(int(getattr(header, 'RESPONSE', 0))),
            opcode=int(getattr(header, 'OPCODE', 0)),
            rcode=int(getattr(header, 'RCODE', 0)),
            questions=(),
            answers=(),
            node_status_names=(),
        )

        return ParsedEvent(
            kind=self.kind,
            summary=f'NBNS response={record.is_response} opcode={record.opcode} rcode={record.rcode}',
            data=record,
        )
