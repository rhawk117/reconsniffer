from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.packet import Packet

from reconsniff.models.core import PacketContext, PacketKind, ParsedEvent
from reconsniff.models.dns import DnsQuestion, DnsRecord, DnsResourceRecord
from reconsniff.protocols.base import BaseParser

DNS_RCODES: dict[int, str] = {
    0: 'NOERROR',
    1: 'FORMERR',
    2: 'SERVFAIL',
    3: 'NXDOMAIN',
    4: 'NOTIMP',
    5: 'REFUSED',
    6: 'YXDOMAIN',
    7: 'YXRRSET',
    8: 'NXRRSET',
    9: 'NOTAUTH',
    10: 'NOTZONE',
}

DNS_QTYPES: dict[int, str] = {
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    6: 'SOA',
    12: 'PTR',
    15: 'MX',
    16: 'TXT',
    28: 'AAAA',
    33: 'SRV',
    43: 'DS',
    46: 'RRSIG',
    47: 'NSEC',
    48: 'DNSKEY',
    255: 'ANY',
}


def safe_decode(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode('utf-8', errors='replace')
    return str(value)


def normalize_name(value: object) -> str:
    return safe_decode(value).rstrip('.')


def iter_dns_records(head: DNSRR | None, count: int) -> tuple[DnsResourceRecord, ...]:
    records: list[DnsResourceRecord] = []
    current = head

    for _ in range(count):
        if not isinstance(current, DNSRR):
            break
        records.append(
            DnsResourceRecord(
                name=normalize_name(getattr(current, 'rrname', b'')),
                rtype=int(getattr(current, 'type', 0)),
                rclass=int(getattr(current, 'rclass', 0)),
                ttl=int(getattr(current, 'ttl', 0))
                if getattr(current, 'ttl', None) is not None
                else None,
                rdata_text=safe_decode(getattr(current, 'rdata', '')),
            )
        )
        next_layer = getattr(current, 'payload', None)
        current = next_layer if isinstance(next_layer, DNSRR) else None

    return tuple(records)


def parse_dns_like_record(packet: Packet) -> DnsRecord:
    layer = packet[DNS]

    questions: list[DnsQuestion] = []
    qdcount = int(getattr(layer, 'qdcount', 0) or 0)
    current_q = getattr(layer, 'qd', None)

    for _ in range(qdcount):
        if not isinstance(current_q, DNSQR):
            break
        questions.append(
            DnsQuestion(
                name=normalize_name(getattr(current_q, 'qname', b'')),
                qtype=int(getattr(current_q, 'qtype', 0)),
                qclass=int(getattr(current_q, 'qclass', 0)),
            )
        )
        next_q = getattr(current_q, 'payload', None)
        current_q = next_q if isinstance(next_q, DNSQR) else None

    return DnsRecord(
        transaction_id=int(getattr(layer, 'id', 0)),
        is_response=bool(int(getattr(layer, 'qr', 0))),
        opcode=int(getattr(layer, 'opcode', 0)),
        rcode=int(getattr(layer, 'rcode', 0)),
        aa=bool(int(getattr(layer, 'aa', 0))),
        tc=bool(int(getattr(layer, 'tc', 0))),
        rd=bool(int(getattr(layer, 'rd', 0))),
        ra=bool(int(getattr(layer, 'ra', 0))),
        questions=tuple(questions),
        answers=iter_dns_records(
            getattr(layer, 'an', None), int(getattr(layer, 'ancount', 0) or 0)
        ),
        authorities=iter_dns_records(
            getattr(layer, 'ns', None), int(getattr(layer, 'nscount', 0) or 0)
        ),
        additionals=iter_dns_records(
            getattr(layer, 'ar', None), int(getattr(layer, 'arcount', 0) or 0)
        ),
    )


class DnsParser(BaseParser):
    kind = PacketKind.DNS

    def matches(self, context: PacketContext) -> bool:
        return (
            context.is_udp
            and DNS in context.raw_packet
            and (context.src.port == 53 or context.dst.port == 53)
        )

    def parse(self, context: PacketContext) -> ParsedEvent:
        record = parse_dns_like_record(context.raw_packet)

        first_q = record.questions[0] if record.questions else None
        qname = first_q.name if first_q else '(none)'
        qtype = DNS_QTYPES.get(first_q.qtype, str(first_q.qtype)) if first_q else ''
        rcode = DNS_RCODES.get(record.rcode, str(record.rcode))
        direction = 'response' if record.is_response else 'query'

        summary = (
            f'DNS {direction} {qname} {qtype} rcode={rcode} answers={len(record.answers)}'
        )
        return ParsedEvent(kind=self.kind, summary=summary, data=record)
