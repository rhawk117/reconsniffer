from __future__ import annotations

from scapy.layers.dns import DNS

from reconsniff.models.core import PacketContext, PacketKind, ParsedEvent
from reconsniff.models.dns import MdnsRecord
from reconsniff.protocols.base import BaseParser
from reconsniff.protocols.dns import parse_dns_like_record


class MdnsParser(BaseParser):
    kind = PacketKind.MDNS

    def matches(self, context: PacketContext) -> bool:
        packet = context.raw_packet
        return (
            context.is_udp
            and DNS in packet
            and (context.src.port == 5353 or context.dst.port == 5353)
        )

    def parse(self, context: PacketContext) -> ParsedEvent:
        dns_record = parse_dns_like_record(context.raw_packet)

        service_instance_names: set[str] = set()
        service_types: set[str] = set()
        hostnames: set[str] = set()
        advertised_addresses: set[str] = set()

        for record in (
            *dns_record.answers,
            *dns_record.authorities,
            *dns_record.additionals,
        ):
            lower_name = record.name.lower()

            if '._tcp.local' in lower_name or '._udp.local' in lower_name:
                service_instance_names.add(record.name)

            if lower_name.startswith('_') and (
                lower_name.endswith(('._tcp.local', '._udp.local'))
            ):
                service_types.add(record.name)

            if record.rtype in {1, 28}:
                hostnames.add(record.name)
                advertised_addresses.add(record.rdata_text)

            if record.rtype == 33:
                hostnames.add(record.rdata_text)

        mdns_record = MdnsRecord(
            dns=dns_record,
            service_instance_names=tuple(sorted(service_instance_names)),
            service_types=tuple(sorted(service_types)),
            hostnames=tuple(sorted(hostnames)),
            advertised_addresses=tuple(sorted(advertised_addresses)),
        )

        return ParsedEvent(
            kind=self.kind,
            summary=(
                f'mDNS questions={len(dns_record.questions)} '
                f'answers={len(dns_record.answers)} '
                f'services={len(mdns_record.service_instance_names)}'
            ),
            data=mdns_record,
        )
