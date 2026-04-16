from __future__ import annotations

from reconsniff.models.core import PacketContext, PacketKind, ParsedEvent
from reconsniff.models.tls import (
    TlsCertificateRecord,
    TlsClientHelloRecord,
    TlsServerHelloRecord,
)
from reconsniff.protocols.base import BaseParser


def parse_tls_record_header(payload_bytes: bytes) -> tuple[int, int, int] | None:
    if len(payload_bytes) < 5:
        return None
    content_type = payload_bytes[0]
    version = int.from_bytes(payload_bytes[1:3], byteorder='big')
    record_length = int.from_bytes(payload_bytes[3:5], byteorder='big')
    return content_type, version, record_length


def parse_tls_handshake_header(payload_bytes: bytes) -> tuple[int, int] | None:
    if len(payload_bytes) < 4:
        return None
    handshake_type = payload_bytes[0]
    handshake_length = int.from_bytes(payload_bytes[1:4], byteorder='big')
    return handshake_type, handshake_length


def is_tls_candidate(context: PacketContext) -> bool:
    if not context.is_tcp or len(context.payload_bytes) < 6:
        return False

    header = parse_tls_record_header(context.payload_bytes)
    if header is None:
        return False

    content_type, version, _ = header
    return content_type == 0x16 and version in {0x0301, 0x0302, 0x0303, 0x0304}


class TlsClientHelloParser(BaseParser):
    kind = PacketKind.TLS_CLIENT_HELLO

    def matches(self, context: PacketContext) -> bool:
        if not is_tls_candidate(context):
            return False

        header = parse_tls_record_header(context.payload_bytes)
        if header is None:
            return False

        _, _, record_length = header
        handshake_header = parse_tls_handshake_header(
            context.payload_bytes[5 : 5 + record_length]
        )
        return handshake_header is not None and handshake_header[0] == 0x01

    def parse(self, context: PacketContext) -> ParsedEvent:
        record = TlsClientHelloRecord(
            record_version=None,
            client_version=None,
            sni=None,
            alpn_protocols=(),
            cipher_suites=(),
            supported_groups=(),
            signature_algorithms=(),
            ja3_input=None,
        )

        return ParsedEvent(
            kind=self.kind,
            summary='TLS ClientHello',
            data=record,
        )


class TlsServerHelloParser(BaseParser):
    kind = PacketKind.TLS_SERVER_HELLO

    def matches(self, context: PacketContext) -> bool:
        if not is_tls_candidate(context):
            return False

        header = parse_tls_record_header(context.payload_bytes)
        if header is None:
            return False

        _, _, record_length = header
        handshake_header = parse_tls_handshake_header(
            context.payload_bytes[5 : 5 + record_length]
        )
        return handshake_header is not None and handshake_header[0] == 0x02

    def parse(self, context: PacketContext) -> ParsedEvent:
        record = TlsServerHelloRecord(
            selected_version=None,
            selected_cipher_suite=None,
            selected_alpn=None,
            ja3s_input=None,
        )

        return ParsedEvent(
            kind=self.kind,
            summary='TLS ServerHello',
            data=record,
        )


class TlsCertificateParser(BaseParser):
    kind = PacketKind.TLS_CERTIFICATE

    def matches(self, context: PacketContext) -> bool:
        if not is_tls_candidate(context):
            return False

        header = parse_tls_record_header(context.payload_bytes)
        if header is None:
            return False

        _, _, record_length = header
        handshake_header = parse_tls_handshake_header(
            context.payload_bytes[5 : 5 + record_length]
        )
        return handshake_header is not None and handshake_header[0] == 0x0B

    def parse(self, context: PacketContext) -> ParsedEvent:
        record = TlsCertificateRecord(
            subject=None,
            issuer=None,
            serial_number=None,
            not_before=None,
            not_after=None,
            san_dns_names=(),
            san_ip_addresses=(),
        )

        return ParsedEvent(
            kind=self.kind,
            summary='TLS Certificate',
            data=record,
        )
