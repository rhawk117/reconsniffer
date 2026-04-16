import dataclasses as dc
from enum import StrEnum
import json
from pathlib import Path
from typing import Any, TypedDict

from reconsniff.schemas.mixins import DataclassMixin
from reconsniff.schemas.validators import (
    LogLevelNames,
    validate_ip_address,
    validate_log_level,
    validate_port_number,
)


@dc.dataclass(slots=True)
class CapturePort(DataclassMixin):
    dns: int = 53
    mdns: int = 5353
    ssdp: int = 1900

    def validate(self) -> None:
        for ports in self.to_tuple():
            validate_port_number(ports)

    @property
    def bpf_filter(self) -> str:
        return f'udp port {self.dns} or udp port {self.mdns} or udp port {self.ssdp}'


@dc.dataclass(slots=True)
class MulticastTargets(DataclassMixin):
    mdns_ipv4: str = '224.0.0.251'
    ssdp_ipv4: str = '239.255.255.250'
    ssdp_ipv6: str = 'ff02::c'

    def validate(self) -> None:
        for ipaddr in self.to_tuple():
            validate_ip_address(ipaddr)

    @property
    def ssdpaddrs(self) -> set[str]:
        return {self.ssdp_ipv4, self.ssdp_ipv6}

@dc.dataclass(slots=True)
class LANEndpoint:
    """network endpoint container.

    Parameters
    ----------
    address : str
        source or destination address.
    port : int | None
        source or destination port.
    """

    address: str
    port: int | None = None

    def socket_label(self) -> str:
        portlabel = self.port if self.port is not None else '-'
        return f'{self.address}:{portlabel}'

    def __str__(self) -> str:
        return self.socket_label()


class CaptureStatisticSnapshot(TypedDict):
    errors: dict[str, int]
    protocols: dict[str, int]


@dc.dataclass(slots=True)
class CaptureStatistics:
    """
    Records errors that occur alongside protocol totals
    """

    _error_totals: dict[str, int] = dc.field(
        default_factory=dict,
        init=False,
        doc='Exception Names mapped by a total number of times they have occured',
    )
    _protocol_totals: dict[str, int] = dc.field(
        default_factory=dict,
        init=False,
        doc='Protocol names and the number of times they have occured',
    )

    def record_protocol(self, protocol: str) -> None:
        self._protocol_totals.setdefault(protocol, 0)
        self._protocol_totals[protocol] += 1

    def record_error(self, exception: Exception) -> None:
        exception_name = type(exception).__name__
        self._error_totals.setdefault(exception_name, 0)
        self._error_totals[exception_name] += 1

    @property
    def snapshot(self) -> CaptureStatisticSnapshot:
        return {
            'errors': dict(self._error_totals),
            'protocols': dict(self._protocol_totals),
        }

    @property
    def protocols(self) -> set[str]:
        return set(self._protocol_totals.keys())

    @property
    def errors(self) -> set[str]:
        return set(self._error_totals.keys())


@dc.dataclass(slots=True)
class CaptureOptions:
    output_path: Path
    interface: str | None = dc.field(default=None, doc='the interface to use')
    log_level: LogLevelNames = dc.field(
        default='INFO',
        doc='the log level name for the logger'
    )
    multicast: MulticastTargets = dc.field(default_factory=MulticastTargets)
    ports: CapturePort = dc.field(default_factory=CapturePort)
    show_filter: bool = dc.field(
        default=False,
        doc='print the computed bpf filter and exit',
    )
    show_options: bool = dc.field(default=False, doc='display the options on startup')
    store_packets: bool = dc.field(
        default=False,
        doc='keep sniffed packets in memory for debugging; normally leave this off',
    )

    def validate(self) -> None:
        validate_log_level(self.log_level)
        self.multicast.validate()
        self.ports.validate()


@dc.dataclass(slots=True)
class CaptureRuntime:
    ports: CapturePort
    multicast: MulticastTargets

    def is_mdns_packet(self, src: LANEndpoint, dst: LANEndpoint) -> bool:
        return (
            src.port == self.ports.mdns
            or dst.port == self.ports.mdns
            or dst.address == self.multicast.mdns_ipv4
        )

    def is_ssdp_packet(self, src: LANEndpoint, dst: LANEndpoint) -> bool:
        return (
            src.port == self.ports.ssdp
            or dst.port == self.ports.ssdp
            or dst.address in self.multicast.ssdpaddrs
        )



@dc.dataclass(slots=True)
class PacketEvent(DataclassMixin):
    timestamp: str
    protocol: str
    source: LANEndpoint
    destination: LANEndpoint
    summary: str
    metadata: dict[str, Any]

    @property
    def protocol_key(self) -> str:
        """return a normalized lowercase protocol key."""
        return self.protocol.lower()

    @property
    def title(self) -> str:
        return f'{self.protocol}  {self.timestamp}'

    @property
    def direction(self) -> str:
        """return a display-oriented direction string."""
        return f"{self.source} -> {self.destination}"

    def json_dumps(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)

class PacketKind(StrEnum):
    ARP = 'arp'
    DHCPV4 = 'dhcpv4'
    DHCPV6 = 'dhcpv6'
    MDNS = 'mdns'
    SSDP = 'ssdp'
    LLMNR = 'llmnr'
    NBNS = 'nbns'
    ICMPV6_ND = 'icmpv6_nd'
    DNS = 'dns'
    TLS_CLIENT_HELLO = 'tls_client_hello'
    TLS_SERVER_HELLO = 'tls_server_hello'
    TLS_CERTIFICATE = 'tls_certificate'