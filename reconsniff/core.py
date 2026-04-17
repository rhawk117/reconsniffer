"""reconsniff CLI and capture orchestration."""

import argparse
import dataclasses as dc
import json
import signal
import time
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from loguru import logger
from rich.console import Console, Group
from rich.panel import Panel
from rich.pretty import Pretty
from rich.text import Text

from reconsniff import constant
from reconsniff.schemas.models import (
    CaptureOptions,
    CapturePort,
    CaptureStatistics,
    MulticastTargets,
)
from reconsniff.schemas.validators import validate_ip_address, validate_port_number
from reconsniff.snff import CaptureEngine, build_bpf_filter, create_protocol_registry

if TYPE_CHECKING:
    from reconsniff.models.core import PacketContext, ParsedEvent


def _json_format(record: Any) -> str:
    entry: dict[str, Any] = {
        'ts': record['time'].isoformat(),
        'level': record['level'].name,
        'message': record['message'],
    }
    entry.update(record['extra'])
    if record['exception'] is not None:
        exc_type, exc_value, _ = record['exception']
        entry['exception'] = {
            'type': exc_type.__name__ if exc_type else None,
            'value': str(exc_value) if exc_value else None,
        }
    return json.dumps(entry, default=str).replace('{', '{{').replace('}', '}}') + '\n'


def configure_logging(options: CaptureOptions) -> None:
    logger.remove()
    logger.add(
        options.output_path,
        format=_json_format,
        level=options.log_level,
        rotation='25 MB',
        retention=10,
        compression='gz',
        enqueue=True,
        backtrace=False,
        diagnose=False,
    )


def log_event(context: PacketContext, event: ParsedEvent) -> None:
    data = dc.asdict(event.data) if dc.is_dataclass(event.data) else None  # type: ignore[arg-type]
    logger.bind(
        event_type='packet',
        protocol=event.kind.value,
        src=context.src.label,
        dst=context.dst.label,
        data=data,
    ).info(event.summary)


def render_event(console: Console, context: PacketContext, event: ParsedEvent) -> None:
    ts = (
        datetime
        .fromtimestamp(context.timestamp, UTC)
        .astimezone()
        .isoformat(timespec='seconds')
    )
    title = Text()
    title.append(f'{event.kind.value.upper()}  {ts}', style='bold cyan')
    title.append('\n')
    title.append(f'{context.src.label} -> {context.dst.label}', style='green')

    data_dict = (
        dc.asdict(event.data)  # type: ignore[arg-type]
        if dc.is_dataclass(event.data)
        else {'raw': str(event.data)}
    )
    body = Group(
        Text(event.summary, style='white'),
        Pretty(data_dict, expand_all=False, indent_guides=True),
    )
    console.print(Panel(body, title=title, border_style='blue'))


def _valid_port(value: str) -> int:
    return validate_port_number(value)


def _valid_ip(value: str) -> str:
    return validate_ip_address(value)


def create_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=constant.TOOL_NAME,
        description=constant.TOOL_DESCRIPTION,
        epilog=constant.TOOL_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        '--version',
        action='version',
        version=f'{constant.TOOL_NAME} {constant.TOOL_VERSION}',
    )

    capture = parser.add_argument_group('capture options')
    capture.add_argument(
        '--interface',
        '-i',
        default=None,
        metavar='IFACE',
        help='network interface to sniff on; uses scapy default when omitted',
    )
    capture.add_argument(
        '--store-packets',
        action='store_true',
        help='keep sniffed packets in memory (debug only)',
    )

    logging_grp = parser.add_argument_group('logging options')
    logging_grp.add_argument(
        '--output',
        '-o',
        default='reconsniff.log',
        metavar='FILE',
        help='path to the json log output file (default: reconsniff.log)',
    )
    logging_grp.add_argument(
        '--log-level',
        default='INFO',
        choices=('TRACE', 'DEBUG', 'INFO', 'SUCCESS', 'WARNING', 'ERROR', 'CRITICAL'),
        type=str.upper,
        help='minimum level written to the log file (default: INFO)',
    )

    ports = parser.add_argument_group('port overrides')
    ports.add_argument('--dns-port', type=_valid_port, default=53, metavar='PORT')
    ports.add_argument('--mdns-port', type=_valid_port, default=5353, metavar='PORT')
    ports.add_argument('--ssdp-port', type=_valid_port, default=1900, metavar='PORT')

    mc = parser.add_argument_group('multicast overrides')
    mc.add_argument(
        '--mdns-multicast-ipv4', type=_valid_ip, default='224.0.0.251', metavar='ADDR'
    )
    mc.add_argument(
        '--ssdp-multicast-ipv4', type=_valid_ip, default='239.255.255.250', metavar='ADDR'
    )
    mc.add_argument('--ssdp-multicast-ipv6', default='ff02::c', metavar='ADDR')

    filters = parser.add_argument_group(
        'protocol filters',
        'pass --no-<protocol> to exclude a protocol from capture and parsing',
    )
    for proto in constant.PROTOCOL_KEYS:
        filters.add_argument(
            f'--no-{proto}',
            action='store_true',
            default=False,
            help=f'exclude {proto} traffic',
        )

    info = parser.add_argument_group('information')
    info.add_argument(
        '--show-filter',
        action='store_true',
        help='print the computed bpf filter string and exit',
    )
    info.add_argument(
        '--show-config',
        action='store_true',
        help='print the resolved startup configuration as json and exit',
    )

    return parser


def build_capture_options() -> CaptureOptions:
    parser = create_argparser()
    args = parser.parse_args()

    excluded: set[str] = {
        proto for proto in constant.PROTOCOL_KEYS if getattr(args, f'no_{proto}', False)
    }

    options = CaptureOptions(
        interface=args.interface,
        output_path=Path(args.output),
        log_level=args.log_level,
        store_packets=args.store_packets,
        ports=CapturePort(dns=args.dns_port, mdns=args.mdns_port, ssdp=args.ssdp_port),
        multicast=MulticastTargets(
            mdns_ipv4=args.mdns_multicast_ipv4,
            ssdp_ipv4=args.ssdp_multicast_ipv4,
            ssdp_ipv6=args.ssdp_multicast_ipv6,
        ),
        excluded_protocols=frozenset(excluded),
        show_filter=args.show_filter,
        show_options=args.show_config,
    )
    options.validate()

    bpf = build_bpf_filter(
        options.excluded_protocols,
        dns_port=options.ports.dns,
        mdns_port=options.ports.mdns,
        ssdp_port=options.ports.ssdp,
    )

    if args.show_filter:
        print(bpf)
        raise SystemExit(0)

    if args.show_config:
        print(
            json.dumps(
                {
                    'interface': options.interface or '(default)',
                    'output': str(options.output_path),
                    'log_level': options.log_level,
                    'excluded_protocols': sorted(options.excluded_protocols),
                    'bpf_filter': bpf,
                    'ports': dc.asdict(options.ports),
                    'multicast': dc.asdict(options.multicast),
                },
                indent=2,
            )
        )
        raise SystemExit(0)

    return options


def run_capture(options: CaptureOptions) -> int:
    configure_logging(options)
    console = Console(soft_wrap=True)
    stats = CaptureStatistics()
    stop_flag: list[bool] = [False]

    bpf = build_bpf_filter(
        options.excluded_protocols,
        dns_port=options.ports.dns,
        mdns_port=options.ports.mdns,
        ssdp_port=options.ports.ssdp,
    )

    def on_event(context: PacketContext, event: ParsedEvent) -> None:
        try:
            stats.record_protocol(event.kind.value)
            render_event(console, context, event)
            log_event(context, event)
        except Exception as exc:
            stats.record_error(exc)
            console.print(f'[bold red]render error:[/] {exc!r}')
            logger.bind(event_type='error').exception('render error')

    registry = create_protocol_registry(options.excluded_protocols)
    engine = CaptureEngine(
        registry=registry,
        on_event=on_event,
        interface=options.interface,
        bpf_filter=bpf,
        store_packets=options.store_packets,
    )

    def _handle_signal(signum: int, _frame: Any) -> None:
        stop_flag[0] = True
        console.print(f'[yellow]signal {signum} received, stopping...[/]')

    for sig_name in ('SIGINT', 'SIGTERM'):
        sig_val = getattr(signal, sig_name, None)
        if sig_val is not None:
            with suppress(Exception):
                signal.signal(sig_val, _handle_signal)

    startup_meta: dict[str, Any] = {
        'interface': options.interface or '(default)',
        'output': str(options.output_path),
        'log_level': options.log_level,
        'excluded_protocols': sorted(options.excluded_protocols),
        'bpf_filter': bpf,
    }
    console.print(
        Panel(Pretty(startup_meta), title='capture startup', border_style='green')
    )
    logger.bind(event_type='startup', **startup_meta).info('capture started')

    engine.start()
    try:
        while not stop_flag[0]:
            time.sleep(0.25)
    finally:
        engine.stop()
        snapshot = stats.snapshot
        console.print(
            Panel(Pretty(snapshot), title='capture stopped', border_style='red')
        )
        logger.bind(event_type='shutdown', **snapshot).info('capture stopped')

    return 0


def run_tool() -> int:
    options = build_capture_options()
    return run_capture(options)
