from scapy.layers.dns import DNS
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse

from reconsniff.models.core import PacketContext, PacketKind, ParsedEvent
from reconsniff.models.dns import LlmnrRecord
from reconsniff.protocols.base import BaseParser
from reconsniff.protocols.dns import DNS_QTYPES, DNS_RCODES, parse_dns_like_record


class LlmnrParser(BaseParser):
    kind = PacketKind.LLMNR

    def matches(self, context: PacketContext) -> bool:
        packet = context.raw_packet
        return (
            context.transport in {'udp', 'tcp'}
            and (context.src.port == 5355 or context.dst.port == 5355)
            and (LLMNRQuery in packet or LLMNRResponse in packet)
            and DNS in packet
        )

    def parse(self, context: PacketContext) -> ParsedEvent:
        dns = parse_dns_like_record(context.raw_packet)
        queried_names = tuple(q.name for q in dns.questions)

        record = LlmnrRecord(dns=dns, queried_names=queried_names)

        first_q = dns.questions[0] if dns.questions else None
        qname = first_q.name if first_q else '(none)'
        qtype = DNS_QTYPES.get(first_q.qtype, str(first_q.qtype)) if first_q else ''
        rcode = DNS_RCODES.get(dns.rcode, str(dns.rcode))
        direction = 'response' if dns.is_response else 'query'

        summary = f'LLMNR {direction} {qname} {qtype} rcode={rcode}'
        return ParsedEvent(kind=self.kind, summary=summary, data=record)
