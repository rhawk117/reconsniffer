from __future__ import annotations

from scapy.layers.dns import DNS

from reconsniff.models.core import PacketContext, PacketKind, ParsedEvent
from reconsniff.models.dns import MdnsRecord
from reconsniff.protocols.base import BaseParser
from reconsniff.protocols.dns import parse_dns_like_record

# DNS record types we care about for mDNS service discovery
_RTYPE_A     = 1
_RTYPE_PTR   = 12
_RTYPE_SRV   = 33
_RTYPE_AAAA  = 28


class MdnsParser(BaseParser):
    kind = PacketKind.MDNS

    def matches(self, context: PacketContext) -> bool:
        return (
            context.is_udp
            and DNS in context.raw_packet
            and (context.src.port == 5353 or context.dst.port == 5353)
        )

    def parse(self, context: PacketContext) -> ParsedEvent:
        dns = parse_dns_like_record(context.raw_packet)

        service_types: set[str] = set()
        instance_names: set[str] = set()
        hostnames: set[str] = set()
        addresses: set[str] = set()

        for rr in (*dns.answers, *dns.authorities, *dns.additionals):
            name_lower = rr.name.lower()

            if rr.rtype == _RTYPE_PTR:
                # PTR rrname is the service type (_http._tcp.local),
                # rdata is the service instance name (My Device._http._tcp.local)
                if name_lower.endswith(('._tcp.local', '._udp.local')):
                    service_types.add(rr.name)
                    instance = rr.rdata_text.rstrip('.')
                    if instance:
                        instance_names.add(instance)

            elif rr.rtype in (_RTYPE_A, _RTYPE_AAAA):
                hostnames.add(rr.name)
                if rr.rdata_text:
                    addresses.add(rr.rdata_text)

            elif rr.rtype == _RTYPE_SRV:
                # rdata_text is "priority weight port target"
                parts = rr.rdata_text.split()
                if len(parts) >= 4:
                    hostnames.add(parts[3].rstrip('.'))

        record = MdnsRecord(
            dns=dns,
            service_instance_names=tuple(sorted(instance_names)),
            service_types=tuple(sorted(service_types)),
            hostnames=tuple(sorted(hostnames)),
            advertised_addresses=tuple(sorted(addresses)),
        )

        direction = 'response' if dns.is_response else 'query'
        first_q = dns.questions[0].name if dns.questions else None

        parts = [f'mDNS {direction}']
        if first_q:
            parts.append(f'q={first_q}')
        if record.service_types:
            parts.append(f'services={len(record.service_types)}')
        if record.hostnames:
            parts.append(f'hosts={len(record.hostnames)}')
        if record.advertised_addresses:
            parts.append(f'addrs={len(record.advertised_addresses)}')

        return ParsedEvent(kind=self.kind, summary=' '.join(parts), data=record)
