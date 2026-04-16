from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class ArpRecord:
    operation: int
    sender_mac: str
    sender_ipv4: str
    target_mac: str
    target_ipv4: str
    is_probe: bool
    is_announcement: bool


@dataclass(slots=True, frozen=True)
class SsdpRecord:
    start_line: str
    method_or_status: str
    host: str | None
    location: str | None
    server: str | None
    user_agent: str | None
    usn: str | None
    st: str | None
    nt: str | None
    nts: str | None
    man: str | None
    mx: int | None
    cache_control: str | None
    bootid_upnp_org: str | None
    configid_upnp_org: str | None
    raw_headers: dict[str, str]


@dataclass(slots=True, frozen=True)
class Icmpv6NdOption:
    option_type: int
    value_text: str


@dataclass(slots=True, frozen=True)
class Icmpv6NdRecord:
    icmpv6_type: int
    code: int
    source_ipv6: str | None
    target_ipv6: str | None
    source_link_layer_address: str | None
    target_link_layer_address: str | None
    router_lifetime: int | None
    reachable_time_ms: int | None
    retrans_timer_ms: int | None
    prefix_info: tuple[str, ...]
    mtu: int | None
    flags: dict[str, bool]
    options: tuple[Icmpv6NdOption, ...]
