from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class Dhcpv4Record:
    message_type: str | None
    transaction_id: int
    client_mac: str | None
    client_ip: str | None
    your_ip: str | None
    server_ip: str | None
    relay_ip: str | None
    hostname: str | None
    requested_ip: str | None
    server_identifier: str | None
    parameter_request_list: tuple[int, ...]
    vendor_class_id: str | None
    domain_name: str | None
    router_list: tuple[str, ...]
    dns_servers: tuple[str, ...]
    lease_time_seconds: int | None


@dataclass(slots=True, frozen=True)
class Dhcpv6Record:
    message_type: int
    transaction_id: int | None
    client_duid: str | None
    server_duid: str | None
    ia_na_addresses: tuple[str, ...]
    ia_pd_prefixes: tuple[str, ...]
    dns_servers: tuple[str, ...]
    domain_search_list: tuple[str, ...]
    elapsed_time: int | None
    fqdn: str | None
    vendor_class: tuple[str, ...]
