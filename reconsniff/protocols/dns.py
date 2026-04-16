from __future__ import annotations

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.packet import Packet

from reconsniff.models.core import PacketContext, PacketKind, ParsedEvent
from reconsniff.models.dns import DnsQuestion, DnsRecord, DnsResourceRecord
from reconsniff.protocols.base import BaseParser


def safe_decode(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode('utf-8', errors='replace')
    return str(value)


def normalize_dns_name(value: object) -> str:
    return safe_decode(value).rstrip('.')


def iter_dns_records(
    record_head: DNSRR | None,
    count: int,
) -> tuple[DnsResourceRecord, ...]:
    records: list[DnsResourceRecord] = []
    current: DNSRR | None = record_head

    for _ in range(count):
        if current is None:
            break

        records.append(
            DnsResourceRecord(
                name=normalize_dns_name(getattr(current, 'rrname', b'')),
                rtype=int(getattr(current, 'type', 0)),
                rclass=int(getattr(current, 'rclass', 0)),
                ttl=int(getattr(current, 'ttl', 0))
                if getattr(current, 'ttl', None) is not None
                else None,
                rdata_text=safe_decode(getattr(current, 'rdata', '')),
            )
        )

        next_payload = getattr(current, 'payload', None)
        current = next_payload if isinstance(next_payload, DNSRR) else None

    return tuple(records)


def parse_dns_like_record(packet: Packet) -> DnsRecord:
    dns_layer = packet[DNS]

    questions: list[DnsQuestion] = []
    question_count = int(getattr(dns_layer, 'qdcount', 0) or 0)
    current_question = getattr(dns_layer, 'qd', None)

    for _ in range(question_count):
        if not isinstance(current_question, DNSQR):
            break

        questions.append(
            DnsQuestion(
                name=normalize_dns_name(getattr(current_question, 'qname', b'')),
                qtype=int(getattr(current_question, 'qtype', 0)),
                qclass=int(getattr(current_question, 'qclass', 0)),
            )
        )

        next_payload = getattr(current_question, 'payload', None)
        current_question = next_payload if isinstance(next_payload, DNSQR) else None

    return DnsRecord(
        transaction_id=int(getattr(dns_layer, 'id', 0)),
        is_response=bool(int(getattr(dns_layer, 'qr', 0))),
        opcode=int(getattr(dns_layer, 'opcode', 0)),
        rcode=int(getattr(dns_layer, 'rcode', 0)),
        aa=bool(int(getattr(dns_layer, 'aa', 0))),
        tc=bool(int(getattr(dns_layer, 'tc', 0))),
        rd=bool(int(getattr(dns_layer, 'rd', 0))),
        ra=bool(int(getattr(dns_layer, 'ra', 0))),
        questions=tuple(questions),
        answers=iter_dns_records(
            getattr(dns_layer, 'an', None), int(getattr(dns_layer, 'ancount', 0) or 0)
        ),
        authorities=iter_dns_records(
            getattr(dns_layer, 'ns', None), int(getattr(dns_layer, 'nscount', 0) or 0)
        ),
        additionals=iter_dns_records(
            getattr(dns_layer, 'ar', None), int(getattr(dns_layer, 'arcount', 0) or 0)
        ),
    )


class DnsParser(BaseParser):
    kind = PacketKind.DNS

    def matches(self, context: PacketContext) -> bool:
        packet = context.raw_packet
        return (
            context.is_udp
            and DNS in packet
            and (context.src.port == 53 or context.dst.port == 53)
        )

    def parse(self, context: PacketContext) -> ParsedEvent:
        record = parse_dns_like_record(context.raw_packet)
        first_question = record.questions[0].name if record.questions else '<none>'
        summary = (
            f'DNS q={first_question} response={record.is_response} rcode={record.rcode}'
        )
        return ParsedEvent(
            kind=self.kind,
            summary=summary,
            data=record,
        )
