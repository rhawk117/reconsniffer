"""TLS handshake parsers.

All parsing operates directly on the raw TCP payload bytes — no third-party
crypto library is required. Certificate field extraction (subject/issuer/SAN)
is left as None; it requires a DER/ASN.1 library such as `cryptography`.
"""

from __future__ import annotations

from reconsniff.models.core import PacketContext, PacketKind, ParsedEvent
from reconsniff.models.tls import (
    TlsCertificateRecord,
    TlsClientHelloRecord,
    TlsServerHelloRecord,
)
from reconsniff.protocols.base import BaseParser

# ── Constants ─────────────────────────────────────────────────────────────────

_CONTENT_HANDSHAKE = 0x16

_HS_CLIENT_HELLO = 0x01
_HS_SERVER_HELLO = 0x02
_HS_CERTIFICATE = 0x0B

_TLS_VERSIONS: dict[int, str] = {
    0x0301: 'TLS 1.0',
    0x0302: 'TLS 1.1',
    0x0303: 'TLS 1.2',
    0x0304: 'TLS 1.3',
}

_EXT_SNI = 0x0000
_EXT_SUPPORTED_GROUPS = 0x000A
_EXT_SIGNATURE_ALGORITHMS = 0x000D
_EXT_ALPN = 0x0010

# ── Byte reading helpers ──────────────────────────────────────────────────────


def _u8(data: bytes, off: int) -> int:
    return data[off]


def _u16(data: bytes, off: int) -> int:
    return int.from_bytes(data[off : off + 2], 'big')


def _u24(data: bytes, off: int) -> int:
    return int.from_bytes(data[off : off + 3], 'big')


# ── Shared TLS record detection ───────────────────────────────────────────────


def _get_handshake_type(payload: bytes) -> int | None:
    """Return the TLS handshake message type byte, or None if the payload is
    not a valid TLS Handshake record."""
    if len(payload) < 9:
        return None
    if payload[0] != _CONTENT_HANDSHAKE:
        return None
    if _u16(payload, 1) not in _TLS_VERSIONS:
        return None
    return payload[5]


# ── Extension parsing ─────────────────────────────────────────────────────────


def _parse_extensions(data: bytes) -> dict[int, bytes]:
    exts: dict[int, bytes] = {}
    off = 0
    while off + 4 <= len(data):
        ext_type = _u16(data, off)
        ext_len = _u16(data, off + 2)
        off += 4
        if off + ext_len > len(data):
            break
        exts[ext_type] = data[off : off + ext_len]
        off += ext_len
    return exts


def _extract_sni(ext_data: bytes) -> str | None:
    # server_name_list_length(2) + name_type(1) + name_length(2) + name
    if len(ext_data) < 5 or ext_data[2] != 0:  # 0 = host_name
        return None
    name_len = _u16(ext_data, 3)
    if 5 + name_len > len(ext_data):
        return None
    return ext_data[5 : 5 + name_len].decode('ascii', errors='replace')


def _extract_alpn(ext_data: bytes) -> tuple[str, ...]:
    if len(ext_data) < 2:
        return ()
    list_len = _u16(ext_data, 0)
    protos: list[str] = []
    off, end = 2, 2 + list_len
    while off < end and off + 1 <= len(ext_data):
        proto_len = _u8(ext_data, off)
        off += 1
        if off + proto_len > len(ext_data):
            break
        protos.append(ext_data[off : off + proto_len].decode('ascii', errors='replace'))
        off += proto_len
    return tuple(protos)


def _extract_u16_list(ext_data: bytes) -> tuple[int, ...]:
    if len(ext_data) < 2:
        return ()
    list_len = _u16(ext_data, 0)
    values: list[int] = []
    off, end = 2, 2 + list_len
    while off + 2 <= end and off + 2 <= len(ext_data):
        values.append(_u16(ext_data, off))
        off += 2
    return tuple(values)


def _read_extensions(
    payload: bytes, pos: int
) -> tuple[str | None, tuple[str, ...], tuple[int, ...], tuple[int, ...]]:
    """Parse the extensions block at pos and return
    (sni, alpn_protocols, supported_groups, signature_algorithms)."""
    if pos + 2 > len(payload):
        return None, (), (), ()

    ext_total = _u16(payload, pos)
    pos += 2
    exts = _parse_extensions(payload[pos : pos + ext_total])

    sni = _extract_sni(exts[_EXT_SNI]) if _EXT_SNI in exts else None
    alpn = _extract_alpn(exts[_EXT_ALPN]) if _EXT_ALPN in exts else ()
    groups = (
        _extract_u16_list(exts[_EXT_SUPPORTED_GROUPS])
        if _EXT_SUPPORTED_GROUPS in exts
        else ()
    )
    sig_algs = (
        _extract_u16_list(exts[_EXT_SIGNATURE_ALGORITHMS])
        if _EXT_SIGNATURE_ALGORITHMS in exts
        else ()
    )

    return sni, alpn, groups, sig_algs


# ── ClientHello ───────────────────────────────────────────────────────────────


def _parse_client_hello(payload: bytes) -> TlsClientHelloRecord:
    # Payload layout:
    #   [0]   content_type
    #   [1-2] record_version
    #   [3-4] record_length
    #   [5]   handshake_type (0x01)
    #   [6-8] handshake_length (3 bytes)
    #   [9-10] client_version
    #   [11-42] random (32 bytes)
    #   [43]   session_id_length
    #   [44…]  session_id
    #   …      cipher_suites_length(2) + cipher_suites
    #   …      compression_methods_length(1) + compression_methods
    #   …      extensions_length(2) + extensions  [optional]

    record_version = _TLS_VERSIONS.get(_u16(payload, 1))
    pos = 9

    if len(payload) < pos + 34:
        return TlsClientHelloRecord(
            record_version=record_version,
            client_version=None,
            sni=None,
            alpn_protocols=(),
            cipher_suites=(),
            supported_groups=(),
            signature_algorithms=(),
            ja3_input=None,
        )

    client_version = _TLS_VERSIONS.get(_u16(payload, pos))
    pos += 2 + 32  # version + random

    if pos + 1 > len(payload):
        return TlsClientHelloRecord(
            record_version=record_version,
            client_version=client_version,
            sni=None,
            alpn_protocols=(),
            cipher_suites=(),
            supported_groups=(),
            signature_algorithms=(),
            ja3_input=None,
        )

    session_id_len = _u8(payload, pos)
    pos += 1 + session_id_len

    if pos + 2 > len(payload):
        return TlsClientHelloRecord(
            record_version=record_version,
            client_version=client_version,
            sni=None,
            alpn_protocols=(),
            cipher_suites=(),
            supported_groups=(),
            signature_algorithms=(),
            ja3_input=None,
        )

    cs_len = _u16(payload, pos)
    pos += 2
    cipher_suites = tuple(
        _u16(payload, pos + i * 2)
        for i in range(cs_len // 2)
        if pos + i * 2 + 2 <= len(payload)
    )
    pos += cs_len

    if pos + 1 > len(payload):
        return TlsClientHelloRecord(
            record_version=record_version,
            client_version=client_version,
            sni=None,
            alpn_protocols=(),
            cipher_suites=cipher_suites,
            supported_groups=(),
            signature_algorithms=(),
            ja3_input=None,
        )

    comp_len = _u8(payload, pos)
    pos += 1 + comp_len

    sni, alpn, groups, sig_algs = _read_extensions(payload, pos)

    return TlsClientHelloRecord(
        record_version=record_version,
        client_version=client_version,
        sni=sni,
        alpn_protocols=alpn,
        cipher_suites=cipher_suites,
        supported_groups=groups,
        signature_algorithms=sig_algs,
        ja3_input=None,
    )


# ── ServerHello ───────────────────────────────────────────────────────────────


def _parse_server_hello(payload: bytes) -> TlsServerHelloRecord:
    record_version = _TLS_VERSIONS.get(_u16(payload, 1))
    pos = 9

    if len(payload) < pos + 34:
        return TlsServerHelloRecord(
            selected_version=record_version,
            selected_cipher_suite=None,
            selected_alpn=None,
            ja3s_input=None,
        )

    server_version = _TLS_VERSIONS.get(_u16(payload, pos))
    pos += 2 + 32  # version + random

    if pos + 1 > len(payload):
        return TlsServerHelloRecord(
            selected_version=server_version or record_version,
            selected_cipher_suite=None,
            selected_alpn=None,
            ja3s_input=None,
        )

    session_id_len = _u8(payload, pos)
    pos += 1 + session_id_len

    if pos + 3 > len(payload):
        return TlsServerHelloRecord(
            selected_version=server_version or record_version,
            selected_cipher_suite=None,
            selected_alpn=None,
            ja3s_input=None,
        )

    cipher_suite = _u16(payload, pos)
    pos += 2
    pos += 1  # compression method

    _, alpn, _, _ = _read_extensions(payload, pos)
    selected_alpn = alpn[0] if alpn else None

    return TlsServerHelloRecord(
        selected_version=server_version or record_version,
        selected_cipher_suite=cipher_suite,
        selected_alpn=selected_alpn,
        ja3s_input=None,
    )


# ── Certificate ───────────────────────────────────────────────────────────────


def _parse_certificate(payload: bytes) -> TlsCertificateRecord:
    # Body: 3-byte total list length, then per-cert: 3-byte length + DER data
    pos = 9
    if len(payload) < pos + 3:
        return TlsCertificateRecord(
            certificate_count=0,
            subject=None,
            issuer=None,
            serial_number=None,
            not_before=None,
            not_after=None,
            san_dns_names=(),
            san_ip_addresses=(),
        )

    cert_list_len = _u24(payload, pos)
    pos += 3
    cert_end = pos + cert_list_len
    cert_count = 0

    while pos + 3 <= cert_end and pos + 3 <= len(payload):
        cert_len = _u24(payload, pos)
        pos += 3 + cert_len
        cert_count += 1
        if cert_count >= 20:
            break

    return TlsCertificateRecord(
        certificate_count=cert_count,
        subject=None,  # requires an ASN.1/DER library to decode
        issuer=None,
        serial_number=None,
        not_before=None,
        not_after=None,
        san_dns_names=(),
        san_ip_addresses=(),
    )


# ── Parser classes ────────────────────────────────────────────────────────────


class TlsClientHelloParser(BaseParser):
    kind = PacketKind.TLS_CLIENT_HELLO

    def matches(self, context: PacketContext) -> bool:
        return _get_handshake_type(context.payload_bytes) == _HS_CLIENT_HELLO

    def parse(self, context: PacketContext) -> ParsedEvent:
        record = _parse_client_hello(context.payload_bytes)
        version = record.client_version or record.record_version or 'TLS ?'

        parts = [f'TLS ClientHello {version}']
        if record.sni:
            parts.append(f'sni={record.sni}')
        if record.alpn_protocols:
            parts.append(f'alpn={",".join(record.alpn_protocols)}')
        parts.append(f'ciphers={len(record.cipher_suites)}')

        return ParsedEvent(kind=self.kind, summary=' '.join(parts), data=record)


class TlsServerHelloParser(BaseParser):
    kind = PacketKind.TLS_SERVER_HELLO

    def matches(self, context: PacketContext) -> bool:
        return _get_handshake_type(context.payload_bytes) == _HS_SERVER_HELLO

    def parse(self, context: PacketContext) -> ParsedEvent:
        record = _parse_server_hello(context.payload_bytes)
        version = record.selected_version or 'TLS ?'

        parts = [f'TLS ServerHello {version}']
        if record.selected_cipher_suite is not None:
            parts.append(f'cipher=0x{record.selected_cipher_suite:04x}')
        if record.selected_alpn:
            parts.append(f'alpn={record.selected_alpn}')

        return ParsedEvent(kind=self.kind, summary=' '.join(parts), data=record)


class TlsCertificateParser(BaseParser):
    kind = PacketKind.TLS_CERTIFICATE

    def matches(self, context: PacketContext) -> bool:
        return _get_handshake_type(context.payload_bytes) == _HS_CERTIFICATE

    def parse(self, context: PacketContext) -> ParsedEvent:
        record = _parse_certificate(context.payload_bytes)
        summary = f'TLS Certificate count={record.certificate_count}'
        return ParsedEvent(kind=self.kind, summary=summary, data=record)
