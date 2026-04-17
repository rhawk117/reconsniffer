from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dhcp6 import (
    DHCP6,
    DHCP6OptClientFQDN,
    DHCP6OptClientId,
    DHCP6OptDNSDomains,
    DHCP6OptDNSServers,
    DHCP6OptElapsedTime,
    DHCP6OptIA_NA,
    DHCP6OptIA_PD,
    DHCP6OptIAAddress,
    DHCP6OptIAPrefix,
    DHCP6OptServerId,
    DHCP6OptVendorClass,
)

from reconsniff.models.core import PacketContext, PacketKind, ParsedEvent
from reconsniff.models.dhcp import Dhcpv4Record, Dhcpv6Record
from reconsniff.protocols.base import BaseParser

_DHCPV4_MSG_TYPES: dict[int, str] = {
    1: 'DISCOVER',
    2: 'OFFER',
    3: 'REQUEST',
    4: 'DECLINE',
    5: 'ACK',
    6: 'NAK',
    7: 'RELEASE',
    8: 'INFORM',
}


def _parse_dhcpv4_options(dhcp_layer: object) -> dict[str, object]:
    opts: dict[str, object] = {}
    for opt in getattr(dhcp_layer, 'options', []):
        if isinstance(opt, tuple) and len(opt) >= 2:
            opts[str(opt[0])] = opt[1]
    return opts


def _ip_list(value: object) -> tuple[str, ...]:
    if isinstance(value, list):
        return tuple(str(v) for v in value if v)
    return ()


def _int_list(value: object) -> tuple[int, ...]:
    if isinstance(value, (list, tuple)):
        return tuple(int(v) for v in value if isinstance(v, int))
    return ()


class Dhcpv4Parser(BaseParser):
    kind = PacketKind.DHCPV4

    def matches(self, context: PacketContext) -> bool:
        return (
            context.is_udp and BOOTP in context.raw_packet and DHCP in context.raw_packet
        )

    def parse(self, context: PacketContext) -> ParsedEvent:
        bootp = context.raw_packet[BOOTP]
        opts = _parse_dhcpv4_options(context.raw_packet[DHCP])

        raw_msg_type = opts.get('message-type')
        msg_type_int = int(raw_msg_type) if isinstance(raw_msg_type, int) else None
        msg_type = (
            _DHCPV4_MSG_TYPES.get(msg_type_int, str(msg_type_int))
            if msg_type_int is not None
            else None
        )

        record = Dhcpv4Record(
            message_type=msg_type,
            transaction_id=int(bootp.xid),
            client_mac=context.src.mac,
            client_ip=str(bootp.ciaddr),
            your_ip=str(bootp.yiaddr),
            server_ip=str(bootp.siaddr),
            relay_ip=str(bootp.giaddr),
            hostname=str(opts['hostname']) if opts.get('hostname') is not None else None,
            requested_ip=str(opts['requested_addr'])
            if opts.get('requested_addr') is not None
            else None,
            server_identifier=str(opts['server_id'])
            if opts.get('server_id') is not None
            else None,
            parameter_request_list=_int_list(opts.get('param_req_list')),
            vendor_class_id=str(opts['vendor_class_id'])
            if opts.get('vendor_class_id') is not None
            else None,
            domain_name=str(opts['domain']) if opts.get('domain') is not None else None,
            router_list=_ip_list(opts.get('router')),
            dns_servers=_ip_list(opts.get('name_server')),
            lease_time_seconds=int(opts['lease_time'])
            if isinstance(opts.get('lease_time'), int)
            else None,
        )

        xid = f'0x{record.transaction_id:08x}'
        parts = [f'DHCPv4 {record.message_type or "unknown"} xid={xid}']
        if record.client_mac:
            parts.append(f'mac={record.client_mac}')
        if record.hostname:
            parts.append(f'host={record.hostname}')
        if record.your_ip and record.your_ip != '0.0.0.0':
            parts.append(f'offered={record.your_ip}')

        return ParsedEvent(kind=self.kind, summary=' '.join(parts), data=record)


_DHCPV6_MSG_TYPES: dict[int, str] = {
    1: 'SOLICIT',
    2: 'ADVERTISE',
    3: 'REQUEST',
    4: 'CONFIRM',
    5: 'RENEW',
    6: 'REBIND',
    7: 'REPLY',
    8: 'RELEASE',
    9: 'DECLINE',
    10: 'RECONFIGURE',
    11: 'INFORMATION-REQUEST',
    12: 'RELAY-FORW',
    13: 'RELAY-REPL',
}


def _duid_to_str(duid: object) -> str | None:
    if duid is None:
        return None
    ll = getattr(duid, 'lladdr', None)
    if ll:
        return f'LL:{ll}'
    en = getattr(duid, 'enterprisenum', None)
    if en is not None:
        raw_id = getattr(duid, 'id', b'')
        hex_id = raw_id.hex() if isinstance(raw_id, bytes) else str(raw_id)
        return f'EN:{en}:{hex_id}'
    return str(duid)


def _walk_payload(start: object, layer_type: type) -> list:
    """Collect all consecutive layers of layer_type in a payload chain."""
    results = []
    current = start
    while current is not None and current.__class__.__name__ != 'NoPayload':
        if isinstance(current, layer_type):
            results.append(current)
        current = getattr(current, 'payload', None)
    return results


class Dhcpv6Parser(BaseParser):
    kind = PacketKind.DHCPV6

    def matches(self, context: PacketContext) -> bool:
        return context.is_udp and DHCP6 in context.raw_packet

    def parse(self, context: PacketContext) -> ParsedEvent:
        packet = context.raw_packet
        base = packet[DHCP6]

        msg_type_int = int(getattr(base, 'msgtype', 0))
        transaction_id = (
            int(getattr(base, 'trid', 0))
            if getattr(base, 'trid', None) is not None
            else None
        )

        client_duid = _duid_to_str(
            getattr(packet[DHCP6OptClientId], 'duid', None)
            if DHCP6OptClientId in packet
            else None
        )
        server_duid = _duid_to_str(
            getattr(packet[DHCP6OptServerId], 'duid', None)
            if DHCP6OptServerId in packet
            else None
        )

        ia_na_addresses: list[str] = []
        for ia_na in _walk_payload(base, DHCP6OptIA_NA):
            for ia_addr in getattr(ia_na, 'ianaopts', []):
                if isinstance(ia_addr, DHCP6OptIAAddress):
                    addr = getattr(ia_addr, 'addr', None)
                    if addr:
                        ia_na_addresses.append(str(addr))

        ia_pd_prefixes: list[str] = []
        for ia_pd in _walk_payload(base, DHCP6OptIA_PD):
            for ia_pfx in getattr(ia_pd, 'iapdopts', []):
                if isinstance(ia_pfx, DHCP6OptIAPrefix):
                    prefix = getattr(ia_pfx, 'prefix', None)
                    plen = getattr(ia_pfx, 'plen', None)
                    if prefix and plen is not None:
                        ia_pd_prefixes.append(f'{prefix}/{plen}')

        dns_servers: tuple[str, ...] = ()
        if DHCP6OptDNSServers in packet:
            raw = getattr(packet[DHCP6OptDNSServers], 'dnsservers', [])
            dns_servers = tuple(str(a) for a in raw if a)

        domain_search: tuple[str, ...] = ()
        if DHCP6OptDNSDomains in packet:
            raw = getattr(packet[DHCP6OptDNSDomains], 'dnsdomains', [])
            domain_search = tuple(str(d).rstrip('.') for d in raw if d)

        elapsed_time: int | None = None
        if DHCP6OptElapsedTime in packet:
            elapsed_time = int(getattr(packet[DHCP6OptElapsedTime], 'elapsedtime', 0))

        fqdn: str | None = None
        if DHCP6OptClientFQDN in packet:
            raw_fqdn = getattr(packet[DHCP6OptClientFQDN], 'fqdn', None)
            if raw_fqdn:
                fqdn = str(raw_fqdn).rstrip('.')

        vendor_class: tuple[str, ...] = ()
        if DHCP6OptVendorClass in packet:
            raw = getattr(packet[DHCP6OptVendorClass], 'vcdata', [])
            vendor_class = tuple(
                v.decode('utf-8', errors='replace') if isinstance(v, bytes) else str(v)
                for v in raw
                if v
            )

        record = Dhcpv6Record(
            message_type=msg_type_int,
            transaction_id=transaction_id,
            client_duid=client_duid,
            server_duid=server_duid,
            ia_na_addresses=tuple(ia_na_addresses),
            ia_pd_prefixes=tuple(ia_pd_prefixes),
            dns_servers=dns_servers,
            domain_search_list=domain_search,
            elapsed_time=elapsed_time,
            fqdn=fqdn,
            vendor_class=vendor_class,
        )

        msg_name = _DHCPV6_MSG_TYPES.get(msg_type_int, f'type={msg_type_int}')
        trx = f'0x{transaction_id:06x}' if transaction_id is not None else '(none)'
        parts = [f'DHCPv6 {msg_name} trx={trx}']
        if record.client_duid:
            parts.append(f'client={record.client_duid}')
        if record.ia_na_addresses:
            parts.append(f'addrs={",".join(record.ia_na_addresses)}')
        if record.ia_pd_prefixes:
            parts.append(f'prefixes={",".join(record.ia_pd_prefixes)}')

        return ParsedEvent(kind=self.kind, summary=' '.join(parts), data=record)
