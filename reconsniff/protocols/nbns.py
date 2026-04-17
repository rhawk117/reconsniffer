from __future__ import annotations

from scapy.layers.netbios import NBNSHeader, NBNSQueryRequest, NBNSQueryResponse

from reconsniff.models.core import PacketContext, PacketKind, ParsedEvent
from reconsniff.models.dns import NbnsQuestion, NbnsRecord
from reconsniff.protocols.base import BaseParser

_OPCODE_NAMES: dict[int, str] = {
    0: 'QUERY',
    5: 'REGISTRATION',
    6: 'RELEASE',
    7: 'WACK',
    8: 'REFRESH',
}

_NAME_TYPE_LABELS: dict[int, str] = {
    0x00: 'workstation',
    0x03: 'messenger',
    0x06: 'ras-server',
    0x1B: 'domain-master-browser',
    0x1C: 'domain-controllers',
    0x1D: 'master-browser',
    0x1E: 'browser-elections',
    0x20: 'file-server',
    0x21: 'ras-client',
}


def _decode_netbios_name(raw: bytes) -> tuple[str, int]:
    """Decode a Level-1 encoded NetBIOS name.

    Returns (decoded_name, name_type) where name_type is the last byte of
    the 16-character decoded name, which indicates the service type.
    """
    if len(raw) < 33 or raw[0] != 0x20:
        return raw.decode('utf-8', errors='replace').strip('\x00'), 0

    encoded = raw[1:33]
    decoded: list[int] = []
    for i in range(0, 32, 2):
        high = encoded[i] - 0x41
        low = encoded[i + 1] - 0x41
        decoded.append((high << 4) | low)

    name_type = decoded[15]
    name = bytes(decoded[:15]).decode('ascii', errors='replace').rstrip()
    return name, name_type


def _extract_nm_flags(nm_flags_raw: int) -> dict[str, bool]:
    return {
        'aa': bool(nm_flags_raw & 0x40),  # Authoritative Answer
        'tc': bool(nm_flags_raw & 0x20),  # Truncated
        'rd': bool(nm_flags_raw & 0x10),  # Recursion Desired
        'ra': bool(nm_flags_raw & 0x08),  # Recursion Available
        'broadcast': bool(nm_flags_raw & 0x01),
    }


class NbnsParser(BaseParser):
    kind = PacketKind.NBNS

    def matches(self, context: PacketContext) -> bool:
        return (
            context.is_udp
            and (context.src.port == 137 or context.dst.port == 137)
            and NBNSHeader in context.raw_packet
        )

    def parse(self, context: PacketContext) -> ParsedEvent:
        header = context.raw_packet[NBNSHeader]

        is_response = bool(int(getattr(header, 'RESPONSE', 0)))
        opcode = int(getattr(header, 'OPCODE', 0))
        rcode = int(getattr(header, 'RCODE', 0))
        nm_flags = _extract_nm_flags(int(getattr(header, 'NM_FLAGS', 0)))
        qdcount = int(getattr(header, 'QDCOUNT', 0))
        ancount = int(getattr(header, 'ANCOUNT', 0))

        questions: list[NbnsQuestion] = []
        answers: list[str] = []
        current = getattr(header, 'payload', None)

        for _ in range(qdcount):
            if not isinstance(current, NBNSQueryRequest):
                break
            raw_name = getattr(current, 'QUESTION_NAME', b'')
            if isinstance(raw_name, str):
                raw_name = raw_name.encode('latin-1', errors='replace')
            name, name_type = _decode_netbios_name(raw_name)
            questions.append(
                NbnsQuestion(
                    decoded_name=name,
                    name_type=name_type,
                    qtype=int(getattr(current, 'QUESTION_TYPE', 0)),
                    qclass=int(getattr(current, 'QUESTION_CLASS', 0)),
                )
            )
            current = getattr(current, 'payload', None)

        for _ in range(ancount):
            if not isinstance(current, NBNSQueryResponse):
                break
            nb_addr = getattr(current, 'NB_ADDRESS', None)
            if nb_addr:
                answers.append(str(nb_addr))
            current = getattr(current, 'payload', None)

        record = NbnsRecord(
            transaction_id=int(getattr(header, 'NAME_TRN_ID', 0)),
            is_response=is_response,
            opcode=opcode,
            rcode=rcode,
            nm_flags=nm_flags,
            questions=tuple(questions),
            answers=tuple(answers),
            node_status_names=(),
        )

        opcode_name = _OPCODE_NAMES.get(opcode, f'opcode={opcode}')
        direction = 'response' if is_response else 'request'
        first_name = questions[0].decoded_name if questions else None

        parts = [f'NBNS {opcode_name} {direction}']
        if first_name:
            name_type_label = _NAME_TYPE_LABELS.get(
                questions[0].name_type, f'0x{questions[0].name_type:02x}'
            )
            parts.append(f'name={first_name!r} ({name_type_label})')
        if answers:
            parts.append(f'-> {", ".join(answers)}')

        return ParsedEvent(kind=self.kind, summary=' '.join(parts), data=record)
