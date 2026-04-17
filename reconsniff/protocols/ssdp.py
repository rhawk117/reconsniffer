from __future__ import annotations

from reconsniff.models.core import PacketContext, PacketKind, ParsedEvent
from reconsniff.models.discovery import SsdpRecord
from reconsniff.protocols.base import BaseParser

_SSDP_PORT = 1900
_SSDP_PREFIXES = (b'M-SEARCH', b'NOTIFY', b'HTTP/1.1')


def _parse_headers(payload_text: str) -> tuple[str, dict[str, str]]:
    """Split an HTTP-like SSDP payload into (start_line, headers)."""
    lines = payload_text.splitlines()
    start_line = lines[0].strip() if lines else '<empty>'
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ':' not in line:
            continue
        name, _, value = line.partition(':')
        headers[name.strip().upper()] = value.strip()
    return start_line, headers


class SsdpParser(BaseParser):
    kind = PacketKind.SSDP

    def matches(self, context: PacketContext) -> bool:
        if not context.is_udp:
            return False
        if context.src.port == _SSDP_PORT or context.dst.port == _SSDP_PORT:
            return True
        prefix = context.payload_bytes[:16].upper()
        return any(prefix.startswith(p) for p in _SSDP_PREFIXES)

    def parse(self, context: PacketContext) -> ParsedEvent:
        payload_text = context.payload_bytes.decode('utf-8', errors='replace').strip()
        start_line, headers = _parse_headers(payload_text)
        method_or_status = start_line.split(' ', 1)[0] if start_line else '<empty>'

        try:
            mx = int(headers['MX']) if 'MX' in headers else None
        except ValueError:
            mx = None

        record = SsdpRecord(
            start_line=start_line,
            method_or_status=method_or_status,
            host=headers.get('HOST'),
            location=headers.get('LOCATION'),
            server=headers.get('SERVER'),
            user_agent=headers.get('USER-AGENT'),
            usn=headers.get('USN'),
            st=headers.get('ST'),
            nt=headers.get('NT'),
            nts=headers.get('NTS'),
            man=headers.get('MAN'),
            mx=mx,
            cache_control=headers.get('CACHE-CONTROL'),
            bootid_upnp_org=headers.get('BOOTID.UPNP.ORG'),
            configid_upnp_org=headers.get('CONFIGID.UPNP.ORG'),
            raw_headers=headers,
        )

        parts = [f'SSDP {method_or_status}']
        for label, value in [
            ('st', record.st),
            ('nt', record.nt),
            ('usn', record.usn),
            ('location', record.location),
            ('server', record.server),
        ]:
            if value:
                parts.append(f'{label}={value}')

        return ParsedEvent(kind=self.kind, summary=' '.join(parts), data=record)
