"""Shared types for flow identification and application classification."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto


class AppType(Enum):
    UNKNOWN = auto()
    HTTP = auto()
    HTTPS = auto()
    DNS = auto()
    TLS = auto()
    QUIC = auto()
    GOOGLE = auto()
    FACEBOOK = auto()
    YOUTUBE = auto()
    TWITTER = auto()
    INSTAGRAM = auto()
    NETFLIX = auto()
    AMAZON = auto()
    MICROSOFT = auto()
    APPLE = auto()
    WHATSAPP = auto()
    TELEGRAM = auto()
    TIKTOK = auto()
    SPOTIFY = auto()
    ZOOM = auto()
    DISCORD = auto()
    GITHUB = auto()
    CLOUDFLARE = auto()


def app_type_label(app: AppType) -> str:
    labels = {
        AppType.UNKNOWN: "Unknown",
        AppType.HTTP: "HTTP",
        AppType.HTTPS: "HTTPS",
        AppType.DNS: "DNS",
        AppType.TLS: "TLS",
        AppType.QUIC: "QUIC",
        AppType.GOOGLE: "Google",
        AppType.FACEBOOK: "Facebook",
        AppType.YOUTUBE: "YouTube",
        AppType.TWITTER: "Twitter/X",
        AppType.INSTAGRAM: "Instagram",
        AppType.NETFLIX: "Netflix",
        AppType.AMAZON: "Amazon",
        AppType.MICROSOFT: "Microsoft",
        AppType.APPLE: "Apple",
        AppType.WHATSAPP: "WhatsApp",
        AppType.TELEGRAM: "Telegram",
        AppType.TIKTOK: "TikTok",
        AppType.SPOTIFY: "Spotify",
        AppType.ZOOM: "Zoom",
        AppType.DISCORD: "Discord",
        AppType.GITHUB: "GitHub",
        AppType.CLOUDFLARE: "Cloudflare",
    }
    return labels.get(app, "Unknown")


def parse_ipv4_string(ip: str) -> int:
    octets = [int(x) for x in ip.split(".")]
    if len(octets) != 4:
        raise ValueError(f"Invalid IPv4 address: {ip}")
    value = 0
    for i, octet in enumerate(octets):
        value |= octet << (8 * i)
    return value


def ipv4_to_string(value: int) -> str:
    return ".".join(str((value >> (8 * i)) & 0xFF) for i in range(4))


@dataclass(frozen=True, slots=True)
class FiveTuple:
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    protocol: int

    def __str__(self) -> str:
        proto = "TCP" if self.protocol == 6 else "UDP" if self.protocol == 17 else "?"
        return (
            f"{ipv4_to_string(self.src_ip)}:{self.src_port} -> "
            f"{ipv4_to_string(self.dst_ip)}:{self.dst_port} ({proto})"
        )


@dataclass(slots=True)
class ParsedPacket:
    timestamp_sec: int = 0
    timestamp_usec: int = 0
    src_ip: str = ""
    dest_ip: str = ""
    src_port: int = 0
    dest_port: int = 0
    protocol: int = 0
    has_ip: bool = False
    has_tcp: bool = False
    has_udp: bool = False
    payload: bytes = b""


@dataclass(slots=True)
class FlowState:
    tuple: FiveTuple | None = None
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets: int = 0
    bytes: int = 0
    blocked: bool = False