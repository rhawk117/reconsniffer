import dataclasses as dc
from pathlib import Path
from typing import TypedDict

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
        for port in (self.dns, self.mdns, self.ssdp):
            validate_port_number(str(port))


@dc.dataclass(slots=True)
class MulticastTargets(DataclassMixin):
    mdns_ipv4: str = '224.0.0.251'
    ssdp_ipv4: str = '239.255.255.250'
    ssdp_ipv6: str = 'ff02::c'

    def validate(self) -> None:
        for ipaddr in (self.mdns_ipv4, self.ssdp_ipv4):
            validate_ip_address(ipaddr)

    @property
    def ssdpaddrs(self) -> set[str]:
        return {self.ssdp_ipv4, self.ssdp_ipv6}


@dc.dataclass(slots=True)
class LANEndpoint:
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
    _error_totals: dict[str, int] = dc.field(default_factory=dict, init=False)
    _protocol_totals: dict[str, int] = dc.field(default_factory=dict, init=False)

    def record_protocol(self, protocol: str) -> None:
        self._protocol_totals.setdefault(protocol, 0)
        self._protocol_totals[protocol] += 1

    def record_error(self, exception: Exception) -> None:
        name = type(exception).__name__
        self._error_totals.setdefault(name, 0)
        self._error_totals[name] += 1

    @property
    def snapshot(self) -> CaptureStatisticSnapshot:
        return {
            'errors': dict(self._error_totals),
            'protocols': dict(self._protocol_totals),
        }


@dc.dataclass(slots=True)
class CaptureOptions:
    output_path: Path
    interface: str | None = dc.field(default=None)
    log_level: LogLevelNames = dc.field(default='INFO')
    multicast: MulticastTargets = dc.field(default_factory=MulticastTargets)
    ports: CapturePort = dc.field(default_factory=CapturePort)
    excluded_protocols: frozenset[str] = dc.field(default_factory=frozenset)
    show_filter: bool = dc.field(default=False)
    show_options: bool = dc.field(default=False)
    store_packets: bool = dc.field(default=False)

    def validate(self) -> None:
        validate_log_level(self.log_level)
        self.multicast.validate()
        self.ports.validate()
