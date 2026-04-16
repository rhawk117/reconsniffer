"""core runtime and protocol handling for reconsniff."""

import argparse
import json
import signal
import time
from contextlib import suppress
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Any

from loguru import logger
from rich.console import Console, Group
from rich.panel import Panel
from rich.pretty import Pretty
from rich.text import Text
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw
from scapy.sendrecv import AsyncSniffer

from reconsniff import constant


TOOL_NAME = "reconsniff"
TOOL_DESCRIPTION = (
    "capture dns, mdns, and ssdp discovery traffic with rich console output "
    "and structured loguru file logging."
)
TOOL_AUTHOR = "rhawk117"


@dataclass(slots=True, frozen=True)
class CaptureConfig:
    """configuration for a capture session.

    Parameters
    ----------
    interface : str | None
        network interface to sniff on.
    output_path : Path
        file path for log output.
    log_level : str
        logging level for file sink output.
    store_packets : bool
        whether to keep packets in memory in the sniffer.
    dns_port : int
        udp port used for classic dns.
    mdns_port : int
        udp port used for mdns.
    ssdp_port : int
        udp port used for ssdp.
    mdns_multicast_ipv4 : str
        ipv4 multicast destination for mdns.
    ssdp_multicast_ipv4 : str
        ipv4 multicast destination for ssdp.
    ssdp_multicast_ipv6 : str
        ipv6 multicast destination for ssdp.
    """

    interface: str | None
    output_path: Path
    log_level: str
    store_packets: bool
    dns_port: int
    mdns_port: int
    ssdp_port: int
    mdns_multicast_ipv4: str
    ssdp_multicast_ipv4: str
    ssdp_multicast_ipv6: str

    @property
    def capture_ports(self) -> tuple[int, int, int]:
        """return the ports monitored by the capture."""
        return self.dns_port, self.mdns_port, self.ssdp_port

    @property
    def multicast_targets(self) -> dict[str, str]:
        """return configured multicast targets."""
        return {
            "mdns_ipv4": self.mdns_multicast_ipv4,
            "ssdp_ipv4": self.ssdp_multicast_ipv4,
            "ssdp_ipv6": self.ssdp_multicast_ipv6,
        }

    @property
    def bpf_filter(self) -> str:
        """return the bpf filter string for discovery traffic."""
        return (
            f"udp port {self.dns_port} or "
            f"udp port {self.mdns_port} or "
            f"udp port {self.ssdp_port}"
        )

    @property
    def startup_metadata(self) -> dict[str, Any]:
        """return startup metadata for console and file logging."""
        return {
            "interface": self.interface or "<default>",
            "output": str(self.output_path),
            "log_level": self.log_level,
            "store_packets": self.store_packets,
            "bpf_filter": self.bpf_filter,
            "capture_ports": {
                "dns": self.dns_port,
                "mdns": self.mdns_port,
                "ssdp": self.ssdp_port,
            },
            "multicast_targets": self.multicast_targets,
        }


@dataclass(slots=True, frozen=True)
class Endpoint:
    """network endpoint container.

    Parameters
    ----------
    address : str
        source or destination address.
    port : int | None
        source or destination port.
    """

    address: str
    port: int | None

    @property
    def label(self) -> str:
        """return a human-readable endpoint label."""
        return f"{self.address}:{self.port if self.port is not None else '-'}"


@dataclass(slots=True, frozen=True)
class PacketEvent:
    """normalized event emitted by protocol parsers.

    Parameters
    ----------
    timestamp : str
        iso-formatted local timestamp.
    protocol : str
        normalized protocol name.
    source : Endpoint
        packet source endpoint.
    destination : Endpoint
        packet destination endpoint.
    summary : str
        concise human-readable summary.
    metadata : dict[str, Any]
        structured protocol-specific details.
    """

    timestamp: str
    protocol: str
    source: Endpoint
    destination: Endpoint
    summary: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def protocol_key(self) -> str:
        """return a normalized lowercase protocol key."""
        return self.protocol.lower()

    @property
    def direction(self) -> str:
        """return a display-oriented direction string."""
        return f"{self.source.label} -> {self.destination.label}"

    @property
    def title(self) -> str:
        """return a title suitable for rich panels."""
        return f"{self.protocol}  {self.timestamp}"

    @property
    def flow(self) -> str:
        """return a compact source to destination flow label."""
        return self.direction

    @property
    def file_record(self) -> dict[str, Any]:
        """return a structured record for file logging."""
        return asdict(self)

    def to_json(self) -> str:
        """serialize the event as a json string."""
        return json.dumps(self.file_record, ensure_ascii=False, sort_keys=True)


@dataclass(slots=True)
class CaptureStats:
    """running statistics for a capture session."""

    dns_events: int = 0
    mdns_events: int = 0
    ssdp_events: int = 0
    parse_errors: int = 0

    def record(self, protocol: str) -> None:
        """increment a protocol counter.

        Parameters
        ----------
        protocol : str
            normalized protocol name.
        """
        match protocol:
            case "DNS":
                self.dns_events += 1
            case "MDNS":
                self.mdns_events += 1
            case "SSDP":
                self.ssdp_events += 1

    @property
    def snapshot(self) -> dict[str, int]:
        """return a current stats snapshot."""
        return {
            "dns_events": self.dns_events,
            "mdns_events": self.mdns_events,
            "ssdp_events": self.ssdp_events,
            "parse_errors": self.parse_errors,
        }


@dataclass(slots=True)
class CaptureRuntime:
    """mutable runtime state container for the capture loop.

    Parameters
    ----------
    config : CaptureConfig
        capture configuration.
    console : Console
        rich console used for output.
    stats : CaptureStats
        running event counters.
    stop_requested : bool
        termination flag set by signals or interrupts.
    sniffer : AsyncSniffer | None
        active scapy sniffer instance.
    """

    config: CaptureConfig
    console: Console = field(default_factory=lambda: Console(soft_wrap=True))
    stats: CaptureStats = field(default_factory=CaptureStats)
    stop_requested: bool = False
    sniffer: AsyncSniffer | None = None

    @property
    def is_running(self) -> bool:
        """return whether the capture loop should continue."""
        return not self.stop_requested

    @property
    def startup_panel(self) -> Panel:
        """build the startup panel for console output."""
        return Panel(
            Pretty(self.config.startup_metadata, expand_all=False),
            title="capture startup",
            border_style="green",
        )

    @property
    def shutdown_panel(self) -> Panel:
        """build the shutdown panel for console output."""
        return Panel(
            Pretty(self.stats.snapshot, expand_all=False),
            title="capture stopped",
            border_style="red",
        )


def create_argparser() -> argparse.ArgumentParser:
    """build the command-line parser.

    Returns
    -------
    argparse.ArgumentParser
        configured argument parser.
    """
    parser = argparse.ArgumentParser(
        prog=constant.TOOL_NAME,
        description=constant.TOOL_DESCRIPTION,
        epilog=constant.TOOL_EPILOG,
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0",
    )

    capture_group = parser.add_argument_group("capture options")
    capture_group.add_argument(
        "--interface",
        "-i",
        default=None,
        help="network interface to sniff on; uses scapy default when omitted",
    )
    capture_group.add_argument(
        "--store-packets",
        action="store_true",
        help="keep sniffed packets in memory for debugging; normally leave this off",
    )

    logging_group = parser.add_argument_group("logging options")
    logging_group.add_argument(
        "--output",
        "-o",
        default="reconsniff.log",
        help="path to the rotating output log file",
    )
    logging_group.add_argument(
        "--log-level",
        default="INFO",
        choices=("TRACE", "DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"),
        type=str.upper,
        help="file logging level",
    )

    port_group = parser.add_argument_group("protocol port options")
    port_group.add_argument(
        "--dns-port",
        type=valid_port,
        default=53,
        help="udp port used for classic dns",
    )
    port_group.add_argument(
        "--mdns-port",
        type=valid_port,
        default=5353,
        help="udp port used for multicast dns",
    )
    port_group.add_argument(
        "--ssdp-port",
        type=valid_port,
        default=1900,
        help="udp port used for ssdp discovery traffic",
    )

    multicast_group = parser.add_argument_group("multicast target options")
    multicast_group.add_argument(
        "--mdns-multicast-ipv4",
        type=valid_ip,
        default="224.0.0.251",
        help="ipv4 multicast target used for mdns",
    )
    multicast_group.add_argument(
        "--ssdp-multicast-ipv4",
        type=valid_ip,
        default="239.255.255.250",
        help="ipv4 multicast target used for ssdp",
    )
    multicast_group.add_argument(
        "--ssdp-multicast-ipv6",
        default="ff02::c",
        help="ipv6 multicast target used for ssdp",
    )

    info_group = parser.add_argument_group("information")
    info_group.add_argument(
        "--show-filter",
        action="store_true",
        help="print the computed bpf filter and exit",
    )
    info_group.add_argument(
        "--show-config",
        action="store_true",
        help="print the validated startup configuration as json and exit",
    )

    return parser


def build_capture_config() -> CaptureConfig:
    """parse cli arguments into a capture configuration.

    Returns
    -------
    CaptureConfig
        validated capture configuration.
    """
    parser = create_argparser()
    args = parser.parse_args()

    config = CaptureConfig(
        interface=args.interface,
        output_path=Path(args.output),
        log_level=args.log_level,
        store_packets=args.store_packets,
        dns_port=args.dns_port,
        mdns_port=args.mdns_port,
        ssdp_port=args.ssdp_port,
        mdns_multicast_ipv4=args.mdns_multicast_ipv4,
        ssdp_multicast_ipv4=args.ssdp_multicast_ipv4,
        ssdp_multicast_ipv6=args.ssdp_multicast_ipv6,
    )

    if args.show_filter:
        print(config.bpf_filter)
        raise SystemExit(0)

    if args.show_config:
        print(json.dumps(config.startup_metadata, indent=2, sort_keys=True))
        raise SystemExit(0)

    return config

def valid_port(value: str) -> int:
    """validate a port value.

    Parameters
    ----------
    value : str
        raw cli value.

    Returns
    -------
    int
        validated port number.
    """
    port = int(value)
    if not (1 <= port <= 65535):
        raise argparse.ArgumentTypeError(f"invalid port: {value}")
    return port


def valid_ip(value: str) -> str:
    """validate an ip address string.

    Parameters
    ----------
    value : str
        raw cli value.

    Returns
    -------
    str
        validated ip address string.
    """
    try:
        ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid ip address: {value}") from exc
    return value


def configure_logging(config: CaptureConfig) -> None:
    """configure file logging.

    Parameters
    ----------
    config : CaptureConfig
        active capture configuration.
    """
    logger.remove()
    logger.add(
        config.output_path,
        level=config.log_level,
        rotation="25 MB",
        retention=10,
        compression="gz",
        enqueue=True,
        backtrace=False,
        diagnose=False,
        format="{time:YYYY-MM-DD HH:mm:ss.SSS ZZ} | {level:<8} | {message}",
    )


def install_signal_handlers(runtime: CaptureRuntime) -> None:
    """install signal handlers for graceful shutdown.

    Parameters
    ----------
    runtime : CaptureRuntime
        active runtime state.
    """

    def handle_signal(signum: int, _frame: Any) -> None:
        runtime.stop_requested = True
        runtime.console.print(f"[yellow]signal received:[/] {signum}")

    for signal_name in ("SIGINT", "SIGTERM"):
        signal_value = getattr(signal, signal_name, None)
        if signal_value is None:
            continue
        with suppress(Exception):
            signal.signal(signal_value, handle_signal)


def run_capture(runtime: CaptureRuntime) -> int:
    """run the packet capture lifecycle.

    Parameters
    ----------
    runtime : CaptureRuntime
        active runtime state.

    Returns
    -------
    int
        process exit code.
    """
    configure_logging(runtime.config)
    install_signal_handlers(runtime)
    log_startup(runtime)
    start_sniffer(runtime)

    try:
        while runtime.is_running:
            time.sleep(0.25)
    finally:
        stop_sniffer(runtime)
        log_shutdown(runtime)

    return 0


def log_startup(runtime: CaptureRuntime) -> None:
    """log startup metadata to console and file.

    Parameters
    ----------
    runtime : CaptureRuntime
        active runtime state.
    """
    runtime.console.print(runtime.startup_panel)
    logger.info(json.dumps(runtime.config.startup_metadata, sort_keys=True))


def log_shutdown(runtime: CaptureRuntime) -> None:
    """log shutdown statistics to console and file.

    Parameters
    ----------
    runtime : CaptureRuntime
        active runtime state.
    """
    runtime.console.print(runtime.shutdown_panel)
    logger.info(json.dumps(runtime.stats.snapshot, sort_keys=True))


def start_sniffer(runtime: CaptureRuntime) -> None:
    """start the async scapy sniffer.

    Parameters
    ----------
    runtime : CaptureRuntime
        active runtime state.
    """
    runtime.sniffer = AsyncSniffer(
        iface=runtime.config.interface,
        filter=runtime.config.bpf_filter,
        prn=lambda packet: handle_packet(runtime, packet),
        store=runtime.config.store_packets,
    )
    runtime.sniffer.start()


def stop_sniffer(runtime: CaptureRuntime) -> None:
    """stop the async scapy sniffer.

    Parameters
    ----------
    runtime : CaptureRuntime
        active runtime state.
    """
    if runtime.sniffer is None:
        return

    with suppress(Exception):
        runtime.sniffer.stop()


def handle_packet(runtime: CaptureRuntime, packet: Any) -> None:
    """handle a single packet from the sniffer callback.

    Parameters
    ----------
    runtime : CaptureRuntime
        active runtime state.
    packet : Any
        scapy packet instance.
    """
    try:
        event = packet_to_event(runtime.config, packet)
        if event is None:
            return

        runtime.stats.record(event.protocol)
        render_event(runtime.console, event)
        log_event(event)
    except Exception as exc:
        runtime.stats.parse_errors += 1
        runtime.console.print(f"[bold red]packet parse failure:[/] {exc!r}")
        logger.exception("packet parse failure")


def packet_to_event(config: CaptureConfig, packet: Any) -> PacketEvent | None:
    """convert a packet into a normalized event.

    Parameters
    ----------
    config : CaptureConfig
        active capture configuration.
    packet : Any
        scapy packet instance.

    Returns
    -------
    PacketEvent | None
        normalized event if supported, otherwise none.
    """
    if UDP not in packet:
        return None

    source, destination = endpoint_pair(packet)
    protocol = classify_protocol(config, packet, source, destination)

    if protocol is None:
        return None

    if protocol in {"DNS", "MDNS"}:
        return parse_dns_event(config, packet, protocol, source, destination)

    return parse_ssdp_event(config, packet, source, destination)


def classify_protocol(
    config: CaptureConfig,
    packet: Any,
    source: Endpoint,
    destination: Endpoint,
) -> str | None:
    """classify a packet into a supported protocol.

    Parameters
    ----------
    config : CaptureConfig
        active capture configuration.
    packet : Any
        scapy packet instance.
    source : Endpoint
        packet source endpoint.
    destination : Endpoint
        packet destination endpoint.

    Returns
    -------
    str | None
        normalized protocol name or none if unsupported.
    """
    if DNS in packet:
        return "MDNS" if is_mdns_packet(config, source, destination) else "DNS"

    if is_ssdp_packet(config, source, destination):
        return "SSDP"

    return None


def endpoint_pair(packet: Any) -> tuple[Endpoint, Endpoint]:
    """extract normalized endpoints from a packet.

    Parameters
    ----------
    packet : Any
        scapy packet instance.

    Returns
    -------
    tuple[Endpoint, Endpoint]
        source and destination endpoints.
    """
    source_ip = "unknown"
    destination_ip = "unknown"

    if IP in packet:
        source_ip = str(packet[IP].src)
        destination_ip = str(packet[IP].dst)
    elif IPv6 in packet:
        source_ip = str(packet[IPv6].src)
        destination_ip = str(packet[IPv6].dst)

    source_port = int(packet[UDP].sport) if UDP in packet else None
    destination_port = int(packet[UDP].dport) if UDP in packet else None

    return Endpoint(source_ip, source_port), Endpoint(destination_ip, destination_port)


def is_mdns_packet(
    config: CaptureConfig,
    source: Endpoint,
    destination: Endpoint,
) -> bool:
    """determine whether a packet should be treated as mdns.

    Parameters
    ----------
    config : CaptureConfig
        active capture configuration.
    source : Endpoint
        packet source endpoint.
    destination : Endpoint
        packet destination endpoint.

    Returns
    -------
    bool
        true if the packet matches mdns heuristics.
    """
    return (
        source.port == config.mdns_port
        or destination.port == config.mdns_port
        or destination.address == config.mdns_multicast_ipv4
    )


def is_ssdp_packet(
    config: CaptureConfig,
    source: Endpoint,
    destination: Endpoint,
) -> bool:
    """determine whether a packet should be treated as ssdp.

    Parameters
    ----------
    config : CaptureConfig
        active capture configuration.
    source : Endpoint
        packet source endpoint.
    destination : Endpoint
        packet destination endpoint.

    Returns
    -------
    bool
        true if the packet matches ssdp heuristics.
    """
    return (
        source.port == config.ssdp_port
        or destination.port == config.ssdp_port
        or destination.address
        in {config.ssdp_multicast_ipv4, config.ssdp_multicast_ipv6}
    )


def direction_label(
    config: CaptureConfig,
    source: Endpoint,
    destination: Endpoint,
) -> str:
    """derive a directional hint for a packet.

    Parameters
    ----------
    config : CaptureConfig
        active capture configuration.
    source : Endpoint
        packet source endpoint.
    destination : Endpoint
        packet destination endpoint.

    Returns
    -------
    str
        human-readable directional hint.
    """
    if (
        destination.port == config.mdns_port
        and destination.address == config.mdns_multicast_ipv4
    ):
        return "multicast-discovery"

    if destination.port == config.ssdp_port and destination.address in {
        config.ssdp_multicast_ipv4,
        config.ssdp_multicast_ipv6,
    }:
        return "multicast-discovery"

    if destination.port in set(config.capture_ports):
        return "request-ish"

    if source.port in set(config.capture_ports):
        return "response-ish"

    return "unknown"


def parse_dns_event(
    config: CaptureConfig,
    packet: Any,
    protocol: str,
    source: Endpoint,
    destination: Endpoint,
) -> PacketEvent:
    """parse a dns or mdns packet into a packet event.

    Parameters
    ----------
    config : CaptureConfig
        active capture configuration.
    packet : Any
        scapy packet instance.
    protocol : str
        normalized protocol name.
    source : Endpoint
        packet source endpoint.
    destination : Endpoint
        packet destination endpoint.

    Returns
    -------
    PacketEvent
        normalized event object.
    """
    dns_layer = packet[DNS]

    query_name: str | None = None
    query_type: int | None = None

    if getattr(dns_layer, "qd", None) is not None:
        query_name = decode_dns_name(getattr(dns_layer.qd, "qname", b""))
        query_type = getattr(dns_layer.qd, "qtype", None)

    answers = iter_dns_records(
        getattr(dns_layer, "an", None), int(getattr(dns_layer, "ancount", 0))
    )
    authorities = iter_dns_records(
        getattr(dns_layer, "ns", None), int(getattr(dns_layer, "nscount", 0))
    )
    additionals = iter_dns_records(
        getattr(dns_layer, "ar", None), int(getattr(dns_layer, "arcount", 0))
    )

    is_response = int(getattr(dns_layer, "qr", 0)) == 1
    rcode = int(getattr(dns_layer, "rcode", 0))
    opcode = int(getattr(dns_layer, "opcode", 0))

    metadata = {
        "direction": direction_label(config, source, destination),
        "query_name": query_name,
        "query_type": query_type,
        "opcode": opcode,
        "rcode": rcode,
        "flags": {
            "aa": int(getattr(dns_layer, "aa", 0)),
            "tc": int(getattr(dns_layer, "tc", 0)),
            "rd": int(getattr(dns_layer, "rd", 0)),
            "ra": int(getattr(dns_layer, "ra", 0)),
        },
        "answers": answers,
        "authorities": authorities,
        "additionals": additionals,
    }

    summary = (
        f"query={query_name or '<none>'} "
        f"qtype={query_type} "
        f"response={is_response} "
        f"answers={len(answers)} "
        f"rcode={rcode}"
    )

    return PacketEvent(
        timestamp=now_iso(),
        protocol=protocol,
        source=source,
        destination=destination,
        summary=summary,
        metadata=metadata,
    )


def parse_ssdp_event(
    config: CaptureConfig,
    packet: Any,
    source: Endpoint,
    destination: Endpoint,
) -> PacketEvent:
    """parse an ssdp packet into a packet event.

    Parameters
    ----------
    config : CaptureConfig
        active capture configuration.
    packet : Any
        scapy packet instance.
    source : Endpoint
        packet source endpoint.
    destination : Endpoint
        packet destination endpoint.

    Returns
    -------
    PacketEvent
        normalized event object.
    """
    payload_bytes = bytes(packet[Raw].load) if Raw in packet else b""
    payload_text = payload_bytes.decode("utf-8", errors="replace").strip()
    lines = payload_text.splitlines()
    start_line = lines[0] if lines else "<empty>"
    headers = parse_ssdp_headers(payload_text)

    summary_parts = [start_line]
    for header_name in constant.SSDP_HEADER_SUMMARY_KEYS:
        header_value = headers.get(header_name)
        if header_value:
            summary_parts.append(f"{header_name.lower()}={header_value}")

    metadata = {
        "direction": direction_label(config, source, destination),
        "start_line": start_line,
        "headers": interesting_ssdp_headers(headers),
        "raw_preview": payload_text[:1500],
    }

    return PacketEvent(
        timestamp=now_iso(),
        protocol="SSDP",
        source=source,
        destination=destination,
        summary=" | ".join(summary_parts),
        metadata=metadata,
    )


def parse_ssdp_headers(payload_text: str) -> dict[str, str]:
    """parse ssdp payload headers.

    Parameters
    ----------
    payload_text : str
        decoded ssdp payload text.

    Returns
    -------
    dict[str, str]
        header dictionary with uppercase keys.
    """
    headers: dict[str, str] = {}

    for line in payload_text.splitlines()[1:]:
        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        headers[key.strip().upper()] = value.strip()

    return headers


def interesting_ssdp_headers(headers: dict[str, str]) -> dict[str, str | None]:
    """select the most useful ssdp headers for security triage.

    Parameters
    ----------
    headers : dict[str, str]
        parsed header dictionary.

    Returns
    -------
    dict[str, str | None]
        filtered interesting headers.
    """
    return {
        key.lower().replace(".", "_"): headers.get(key)
        for key in constant.SSDP_HEADER_KEYS
    }


def iter_dns_records(section: Any, count: int) -> list[dict[str, Any]]:
    """iterate a scapy dns record chain into normalized dictionaries.

    Parameters
    ----------
    section : Any
        scapy dns answer section head.
    count : int
        record count reported by the packet.

    Returns
    -------
    list[dict[str, Any]]
        normalized dns record dictionaries.
    """
    records: list[dict[str, Any]] = []
    current = section

    for _ in range(count):
        if current is None:
            break

        records.append(
            {
                "name": decode_dns_name(getattr(current, "rrname", b"<unknown>")),
                "type": getattr(current, "type", None),
                "ttl": getattr(current, "ttl", None),
                "data": decode_value(getattr(current, "rdata", "")),
            }
        )
        current = getattr(current, "payload", None)

    return records


def decode_dns_name(value: Any) -> str:
    """decode a dns name-like value.

    Parameters
    ----------
    value : Any
        value to decode.

    Returns
    -------
    str
        decoded dns name string.
    """
    return decode_value(value).rstrip(".")


def decode_value(value: Any) -> str:
    """decode a generic value into a string.

    Parameters
    ----------
    value : Any
        value to decode.

    Returns
    -------
    str
        decoded string value.
    """
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def render_event(console: Console, event: PacketEvent) -> None:
    """render an event to the rich console.

    Parameters
    ----------
    console : Console
        console used for output.
    event : PacketEvent
        event to render.
    """
    title = Text()
    title.append(event.title, style="bold cyan")
    title.append("\n")
    title.append(event.flow, style="green")

    body = Group(
        Text(event.summary, style="white"),
        Pretty(event.metadata, expand_all=False, indent_guides=True),
    )

    console.print(Panel(body, title=title, border_style="blue"))


def log_event(event: PacketEvent) -> None:
    """write an event to the file logger.

    Parameters
    ----------
    event : PacketEvent
        event to log.
    """
    logger.info(event.to_json())


def now_iso() -> str:
    """return the current local iso timestamp.

    Returns
    -------
    str
        iso-formatted local timestamp.
    """
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def run_tool() -> int:
    """run the cli entrypoint.

    Returns
    -------
    int
        process exit code.
    """
    config = build_capture_config()
    runtime = CaptureRuntime(config=config)
    return run_capture(runtime)
