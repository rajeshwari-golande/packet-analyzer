"""Read classic libpcap capture files."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator

PCAP_MAGIC_NATIVE = 0xA1B2C3D4
PCAP_MAGIC_SWAPPED = 0xD4C3B2A1

GLOBAL_HEADER = struct.Struct("<IHHiIII")
PACKET_HEADER = struct.Struct("<IIII")


@dataclass(slots=True)
class PcapGlobalHeader:
    magic_number: int
    version_major: int
    version_minor: int
    thiszone: int
    sigfigs: int
    snaplen: int
    network: int

    def to_bytes(self) -> bytes:
        return GLOBAL_HEADER.pack(
            self.magic_number,
            self.version_major,
            self.version_minor,
            self.thiszone,
            self.sigfigs,
            self.snaplen,
            self.network,
        )


@dataclass(slots=True)
class RawPacket:
    ts_sec: int
    ts_usec: int
    data: bytes


def _swap16(value: int) -> int:
    return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8)


def _swap32(value: int) -> int:
    return (
        ((value & 0xFF000000) >> 24)
        | ((value & 0x00FF0000) >> 8)
        | ((value & 0x0000FF00) << 8)
        | ((value & 0x000000FF) << 24)
    )


class PcapReader:
    def __init__(self) -> None:
        self._file: BinaryIO | None = None
        self._header: PcapGlobalHeader | None = None
        self._swap = False

    def open(self, path: str | Path) -> bool:
        self.close()
        try:
            self._file = open(path, "rb")
        except OSError:
            return False

        raw = self._file.read(GLOBAL_HEADER.size)
        if len(raw) != GLOBAL_HEADER.size:
            self.close()
            return False

        magic, vmaj, vmin, tz, sig, snap, link = GLOBAL_HEADER.unpack(raw)
        if magic == PCAP_MAGIC_NATIVE:
            self._swap = False
        elif magic == PCAP_MAGIC_SWAPPED:
            self._swap = True
            vmaj, vmin, snap, link = (
                _swap16(vmaj),
                _swap16(vmin),
                _swap32(snap),
                _swap32(link),
            )
        else:
            self.close()
            return False

        self._header = PcapGlobalHeader(magic, vmaj, vmin, tz, sig, snap, link)
        return True

    @property
    def global_header(self) -> PcapGlobalHeader:
        if self._header is None:
            raise RuntimeError("PCAP file is not open")
        return self._header

    def iter_packets(self) -> Iterator[RawPacket]:
        if self._file is None or self._header is None:
            return

        snaplen = self._header.snaplen
        while True:
            header_bytes = self._file.read(PACKET_HEADER.size)
            if not header_bytes:
                break
            if len(header_bytes) != PACKET_HEADER.size:
                break

            ts_sec, ts_usec, incl_len, _orig_len = PACKET_HEADER.unpack(header_bytes)
            if self._swap:
                ts_sec = _swap32(ts_sec)
                ts_usec = _swap32(ts_usec)
                incl_len = _swap32(incl_len)

            if incl_len > snaplen or incl_len > 65535:
                continue

            data = self._file.read(incl_len)
            if len(data) != incl_len:
                break

            yield RawPacket(ts_sec, ts_usec, data)

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None
        self._header = None
        self._swap = False