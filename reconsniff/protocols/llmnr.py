from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse

from reconsniff.models.core import PacketContext, PacketKind, ParsedEvent
from reconsniff.models.dns import LlmnrRecord
from reconsniff.protocols.base import BaseParser
from reconsniff.protocols.dns import parse_dns_like_record


class LlmnrParser(BaseParser):
    kind = PacketKind.LLMNR

    def matches(self, context: PacketContext) -> bool:
        packet = context.raw_packet
        return (
            context.transport in {'udp', 'tcp'}
            and (context.src.port == 5355 or context.dst.port == 5355)
            and (LLMNRQuery in packet or LLMNRResponse in packet)
        )

    def parse(self, context: PacketContext) -> ParsedEvent:
        dns_record = parse_dns_like_record(context.raw_packet)
        queried_names = tuple(question.name for question in dns_record.questions)

        record = LlmnrRecord(
            dns=dns_record,
            queried_names=queried_names,
        )

        first_name = queried_names[0] if queried_names else '<none>'
        summary = f'LLMNR q={first_name} response={dns_record.is_response} rcode={dns_record.rcode}'

        return ParsedEvent(
            kind=self.kind,
            summary=summary,
            data=record,
        )
