from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class TlsClientHelloRecord:
    record_version: str | None
    client_version: str | None
    sni: str | None
    alpn_protocols: tuple[str, ...]
    cipher_suites: tuple[int, ...]
    supported_groups: tuple[int, ...]
    signature_algorithms: tuple[int, ...]
    ja3_input: str | None


@dataclass(slots=True, frozen=True)
class TlsServerHelloRecord:
    selected_version: str | None
    selected_cipher_suite: int | None
    selected_alpn: str | None
    ja3s_input: str | None


@dataclass(slots=True, frozen=True)
class TlsCertificateRecord:
    subject: str | None
    issuer: str | None
    serial_number: str | None
    not_before: str | None
    not_after: str | None
    san_dns_names: tuple[str, ...]
    san_ip_addresses: tuple[str, ...]
