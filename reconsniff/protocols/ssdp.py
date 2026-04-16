from reconsniff.models.core import PacketContext, PacketKind, ParsedEvent
from reconsniff.models.discovery import SsdpRecord
from reconsniff.protocols.base import BaseParser


def parse_httpish_headers(payload_text: str) -> tuple[str, dict[str, str]]:
    lines = payload_text.splitlines()
    start_line = lines[0].strip() if lines else '<empty>'
    headers: dict[str, str] = {}

    for line in lines[1:]:
        if ':' not in line:
            continue
        name, value = line.split(':', 1)
        headers[name.strip().upper()] = value.strip()

    return start_line, headers


class SsdpParser(BaseParser):
    kind = PacketKind.SSDP

    def matches(self, context: PacketContext) -> bool:
        if not context.is_udp:
            return False

        if context.src.port == 1900 or context.dst.port == 1900:
            return True

        prefix = context.payload_bytes[:16].upper()
        return (
            prefix.startswith((b'M-SEARCH', b'NOTIFY', b'HTTP/1.1 200'))
        )

    def parse(self, context: PacketContext) -> ParsedEvent:
        payload_text = context.payload_bytes.decode('utf-8', errors='replace').strip()
        start_line, headers = parse_httpish_headers(payload_text)

        try:
            mx_value = int(headers['MX']) if 'MX' in headers else None
        except ValueError:
            mx_value = None

        method_or_status = start_line.split(' ', 1)[0] if start_line else '<empty>'

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
            mx=mx_value,
            cache_control=headers.get('CACHE-CONTROL'),
            bootid_upnp_org=headers.get('BOOTID.UPNP.ORG'),
            configid_upnp_org=headers.get('CONFIGID.UPNP.ORG'),
            raw_headers=headers,
        )

        return ParsedEvent(
            kind=self.kind,
            summary=f'SSDP {record.method_or_status} location={record.location} server={record.server}',
            data=record,
        )
