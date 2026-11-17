"""Parse Ethernet, IPv4, TCP, and UDP headers from raw frame bytes."""

from __future__ import annotations

import struct

from .types import ParsedPacket

ETH_HEADER_LEN = 14
IPV4_ETHER_TYPE = 0x0800
PROTO_TCP = 6
PROTO_UDP = 17


def _ipv4_to_string(value: bytes) -> str:
    return ".".join(str(b) for b in value)


def parse_packet(data: bytes, ts_sec: int = 0, ts_usec: int = 0) -> ParsedPacket | None:
    parsed = ParsedPacket(timestamp_sec=ts_sec, timestamp_usec=ts_usec)

    if len(data) < ETH_HEADER_LEN:
        return None

    ether_type = struct.unpack_from("!H", data, 12)[0]
    if ether_type != IPV4_ETHER_TYPE:
        return None

    offset = ETH_HEADER_LEN
    if len(data) < offset + 20:
        return None

    version_ihl = data[offset]
    version = (version_ihl >> 4) & 0x0F
    ihl = version_ihl & 0x0F
    if version != 4:
        return None

    ip_header_len = ihl * 4
    if ip_header_len < 20 or len(data) < offset + ip_header_len:
        return None

    parsed.protocol = data[offset + 9]
    parsed.src_ip = _ipv4_to_string(data[offset + 12 : offset + 16])
    parsed.dest_ip = _ipv4_to_string(data[offset + 16 : offset + 20])
    parsed.has_ip = True
    offset += ip_header_len

    if parsed.protocol == PROTO_TCP:
        if len(data) < offset + 20:
            return None
        parsed.src_port, parsed.dest_port = struct.unpack_from("!HH", data, offset)
        tcp_offset = (data[offset + 12] >> 4) & 0x0F
        transport_len = tcp_offset * 4
        if transport_len < 20 or len(data) < offset + transport_len:
            return None
        parsed.has_tcp = True
        offset += transport_len
    elif parsed.protocol == PROTO_UDP:
        if len(data) < offset + 8:
            return None
        parsed.src_port, parsed.dest_port = struct.unpack_from("!HH", data, offset)
        parsed.has_udp = True
        offset += 8
    else:
        parsed.payload = data[offset:]
        return parsed

    parsed.payload = data[offset:]
    return parsed