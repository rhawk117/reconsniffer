from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class DnsQuestion:
    name: str
    qtype: int
    qclass: int


@dataclass(slots=True, frozen=True)
class DnsResourceRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int | None
    rdata_text: str


@dataclass(slots=True, frozen=True)
class DnsRecord:
    transaction_id: int
    is_response: bool
    opcode: int
    rcode: int
    aa: bool
    tc: bool
    rd: bool
    ra: bool
    questions: tuple[DnsQuestion, ...]
    answers: tuple[DnsResourceRecord, ...]
    authorities: tuple[DnsResourceRecord, ...]
    additionals: tuple[DnsResourceRecord, ...]


@dataclass(slots=True, frozen=True)
class MdnsRecord:
    dns: DnsRecord
    service_instance_names: tuple[str, ...]
    service_types: tuple[str, ...]
    hostnames: tuple[str, ...]
    advertised_addresses: tuple[str, ...]


@dataclass(slots=True, frozen=True)
class LlmnrRecord:
    dns: DnsRecord
    queried_names: tuple[str, ...]


@dataclass(slots=True, frozen=True)
class NbnsQuestion:
    decoded_name: str
    name_type: int  # last byte of the encoded name — indicates service type
    qtype: int
    qclass: int


@dataclass(slots=True, frozen=True)
class NbnsRecord:
    transaction_id: int
    is_response: bool
    opcode: int
    rcode: int
    nm_flags: dict[str, bool]  # aa, tc, rd, ra, broadcast
    questions: tuple[NbnsQuestion, ...]
    answers: tuple[str, ...]  # resolved IP addresses from answer records
    node_status_names: tuple[str, ...]
