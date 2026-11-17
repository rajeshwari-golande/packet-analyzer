"""Extract TLS SNI and HTTP Host headers from application payloads."""

from __future__ import annotations

CONTENT_TYPE_HANDSHAKE = 0x16
HANDSHAKE_CLIENT_HELLO = 0x01
EXTENSION_SNI = 0x0000
SNI_TYPE_HOSTNAME = 0x00


def _read_uint16_be(data: bytes, offset: int) -> int:
    return (data[offset] << 8) | data[offset + 1]


def _read_uint24_be(data: bytes, offset: int) -> int:
    return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]


def is_tls_client_hello(payload: bytes) -> bool:
    if len(payload) < 9:
        return False
    if payload[0] != CONTENT_TYPE_HANDSHAKE:
        return False
    version = _read_uint16_be(payload, 1)
    if version < 0x0300 or version > 0x0304:
        return False
    record_length = _read_uint16_be(payload, 3)
    if record_length > len(payload) - 5:
        return False
    if payload[5] != HANDSHAKE_CLIENT_HELLO:
        return False
    return True


def extract_tls_sni(payload: bytes) -> str | None:
    if not is_tls_client_hello(payload):
        return None

    offset = 5
    if offset + 4 > len(payload):
        return None

    handshake_length = _read_uint24_be(payload, offset + 1)
    if handshake_length > len(payload) - offset - 4:
        pass
    offset += 4

    offset += 2 + 32  # client version + random

    if offset >= len(payload):
        return None
    session_id_length = payload[offset]
    offset += 1 + session_id_length

    if offset + 2 > len(payload):
        return None
    cipher_suites_length = _read_uint16_be(payload, offset)
    offset += 2 + cipher_suites_length

    if offset >= len(payload):
        return None
    compression_methods_length = payload[offset]
    offset += 1 + compression_methods_length

    if offset + 2 > len(payload):
        return None
    extensions_length = _read_uint16_be(payload, offset)
    offset += 2
    extensions_end = min(offset + extensions_length, len(payload))

    while offset + 4 <= extensions_end:
        extension_type = _read_uint16_be(payload, offset)
        extension_length = _read_uint16_be(payload, offset + 2)
        offset += 4
        if offset + extension_length > extensions_end:
            break

        if extension_type == EXTENSION_SNI and extension_length >= 5:
            sni_type = payload[offset + 2]
            sni_length = _read_uint16_be(payload, offset + 3)
            if sni_type == SNI_TYPE_HOSTNAME and offset + 5 + sni_length <= extensions_end:
                return payload[offset + 5 : offset + 5 + sni_length].decode(
                    "ascii", errors="replace"
                )

        offset += extension_length

    return None


def is_http_request(payload: bytes) -> bool:
    if len(payload) < 4:
        return False
    methods = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI")
    return any(payload.startswith(m) for m in methods)


def extract_http_host(payload: bytes) -> str | None:
    if not is_http_request(payload):
        return None

    length = len(payload)
    i = 0
    while i + 5 < length:
        if (
            payload[i] in (ord("H"), ord("h"))
            and payload[i + 1] in (ord("o"), ord("O"))
            and payload[i + 2] in (ord("s"), ord("S"))
            and payload[i + 3] in (ord("t"), ord("T"))
            and payload[i + 4] == ord(":")
        ):
            start = i + 5
            while start < length and payload[start] in (ord(" "), ord("\t")):
                start += 1
            end = start
            while end < length and payload[end] not in (ord("\r"), ord("\n")):
                end += 1
            if end > start:
                host = payload[start:end].decode("ascii", errors="replace")
                if ":" in host:
                    host = host.split(":", 1)[0]
                return host
        i += 1
    return None