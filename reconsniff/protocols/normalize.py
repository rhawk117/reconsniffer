from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw

from reconsniff.models.core import Endpoint, PacketContext


def extract_transport_payload(packet: Packet) -> bytes:
    if Raw in packet:
        return bytes(packet[Raw].load)
    if UDP in packet:
        return bytes(packet[UDP].payload)
    if TCP in packet:
        return bytes(packet[TCP].payload)
    return b''


def packet_to_context(
    packet: Packet,
    *,
    frame_number: int | None = None,
) -> PacketContext:
    ether_type: int | None = None
    ip_version: int | None = None
    transport: str | None = None

    src_address: str | None = None
    dst_address: str | None = None
    src_mac: str | None = None
    dst_mac: str | None = None
    src_port: int | None = None
    dst_port: int | None = None

    if Ether in packet:
        src_mac = str(packet[Ether].src)
        dst_mac = str(packet[Ether].dst)
        ether_type = int(packet[Ether].type)

    if IP in packet:
        ip_version = 4
        src_address = str(packet[IP].src)
        dst_address = str(packet[IP].dst)
    elif IPv6 in packet:
        ip_version = 6
        src_address = str(packet[IPv6].src)
        dst_address = str(packet[IPv6].dst)

    if UDP in packet:
        transport = 'udp'
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)
    elif TCP in packet:
        transport = 'tcp'
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)

    return PacketContext(
        timestamp=float(packet.time),
        frame_number=frame_number,
        interface_name=getattr(packet, 'sniffed_on', None),
        ether_type=ether_type,
        ip_version=ip_version,
        src=Endpoint(address=src_address, port=src_port, mac=src_mac),
        dst=Endpoint(address=dst_address, port=dst_port, mac=dst_mac),
        transport=transport,
        payload_bytes=extract_transport_payload(packet),
        raw_packet=packet,
    )
