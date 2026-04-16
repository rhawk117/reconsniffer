from typing import Any

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dhcp6 import DHCP6

from reconsniff.models.core import PacketContext, PacketKind, ParsedEvent
from reconsniff.models.dhcp import Dhcpv4Record, Dhcpv6Record
from reconsniff.protocols.base import BaseParser


class Dhcpv4Parser(BaseParser):
    kind = PacketKind.DHCPV4

    def matches(self, context: PacketContext) -> bool:
        return (
            context.is_udp and BOOTP in context.raw_packet and DHCP in context.raw_packet
        )

    def parse(self, context: PacketContext) -> ParsedEvent:
        bootp_layer = context.raw_packet[BOOTP]
        dhcp_layer = context.raw_packet[DHCP]

        options: dict[str, Any] = {}
        for option in getattr(dhcp_layer, 'options', []):
            if isinstance(option, tuple) and len(option) >= 2:
                options[str(option[0])] = option[1]

        router_list = (
            tuple(str(value) for value in options.get('router', []) if value)
            if isinstance(options.get('router'), list)
            else ()
        )
        dns_servers = (
            tuple(str(value) for value in options.get('name_server', []) if value)
            if isinstance(options.get('name_server'), list)
            else ()
        )
        parameter_request_list = (
            tuple(int(value) for value in options.get('param_req_list', []))
            if isinstance(options.get('param_req_list'), list)
            else ()
        )

        record = Dhcpv4Record(
            message_type=str(options.get('message-type'))
            if options.get('message-type') is not None
            else None,
            transaction_id=int(bootp_layer.xid),
            client_mac=context.src.mac,
            client_ip=str(bootp_layer.ciaddr),
            your_ip=str(bootp_layer.yiaddr),
            server_ip=str(bootp_layer.siaddr),
            relay_ip=str(bootp_layer.giaddr),
            hostname=str(options.get('hostname'))
            if options.get('hostname') is not None
            else None,
            requested_ip=str(options.get('requested_addr'))
            if options.get('requested_addr') is not None
            else None,
            server_identifier=str(options.get('server_id'))
            if options.get('server_id') is not None
            else None,
            parameter_request_list=parameter_request_list,
            vendor_class_id=str(options.get('vendor_class_id'))
            if options.get('vendor_class_id') is not None
            else None,
            domain_name=str(options.get('domain'))
            if options.get('domain') is not None
            else None,
            router_list=router_list,
            dns_servers=dns_servers,
            lease_time_seconds=int(options['lease_time'])
            if isinstance(options.get('lease_time'), int)
            else None,
        )

        return ParsedEvent(
            kind=self.kind,
            summary=f'DHCPv4 type={record.message_type} xid=0x{record.transaction_id:08x}',
            data=record,
        )


class Dhcpv6Parser(BaseParser):
    kind = PacketKind.DHCPV6

    def matches(self, context: PacketContext) -> bool:
        return context.is_udp and DHCP6 in context.raw_packet

    def parse(self, context: PacketContext) -> ParsedEvent:
        dhcpv6_layer = context.raw_packet[DHCP6]

        record = Dhcpv6Record(
            message_type=int(getattr(dhcpv6_layer, 'msgtype', 0)),
            transaction_id=int(getattr(dhcpv6_layer, 'trid', 0))
            if getattr(dhcpv6_layer, 'trid', None) is not None
            else None,
            client_duid=None,
            server_duid=None,
            ia_na_addresses=(),
            ia_pd_prefixes=(),
            dns_servers=(),
            domain_search_list=(),
            elapsed_time=None,
            fqdn=None,
            vendor_class=(),
        )

        return ParsedEvent(
            kind=self.kind,
            summary=f'DHCPv6 msgtype={record.message_type} trx={record.transaction_id}',
            data=record,
        )
