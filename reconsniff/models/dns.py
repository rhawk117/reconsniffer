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
    encoded_name: str
    qtype: int
    qclass: int


@dataclass(slots=True, frozen=True)
class NbnsRecord:
    transaction_id: int
    is_response: bool
    opcode: int
    rcode: int
    questions: tuple[NbnsQuestion, ...]
    answers: tuple[str, ...]
    node_status_names: tuple[str, ...]
