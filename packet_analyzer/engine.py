"""Deep packet inspection pipeline over offline PCAP captures."""

from __future__ import annotations

import struct
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from .classify import sni_to_app_type
from .packet_parser import parse_packet
from .pcap_reader import PcapReader
from .rules import BlockingRules
from .sni_extractor import extract_http_host, extract_tls_sni
from .types import AppType, FiveTuple, FlowState, app_type_label, parse_ipv4_string

PACKET_HEADER = struct.Struct("<IIII")


@dataclass(slots=True)
class ProcessingReport:
    total_packets: int
    forwarded: int
    dropped: int
    flow_count: int
    app_stats: dict[AppType, int]
    unique_snis: dict[str, AppType]


def process_pcap(
    input_path: str | Path,
    output_path: str | Path,
    rules: BlockingRules,
    *,
    verbose: bool = True,
) -> ProcessingReport | None:
    reader = PcapReader()
    if not reader.open(input_path):
        print(f"Error: Could not open input file: {input_path}")
        return None

    header = reader.global_header
    flows: dict[FiveTuple, FlowState] = {}
    total_packets = 0
    forwarded = 0
    dropped = 0
    app_stats: dict[AppType, int] = defaultdict(int)

    if verbose:
        print(f"Opened PCAP: {input_path}")
        print(f"  Version: {header.version_major}.{header.version_minor}")
        print(f"  Snaplen: {header.snaplen} bytes")
        link = " (Ethernet)" if header.network == 1 else ""
        print(f"  Link type: {header.network}{link}")
        print("[DPI] Processing packets...")

    with open(output_path, "wb") as output:
        output.write(header.to_bytes())

        for raw in reader.iter_packets():
            total_packets += 1
            parsed = parse_packet(raw.data, raw.ts_sec, raw.ts_usec)
            if parsed is None or not parsed.has_ip:
                continue
            if not parsed.has_tcp and not parsed.has_udp:
                continue

            five_tuple = FiveTuple(
                src_ip=parse_ipv4_string(parsed.src_ip),
                dst_ip=parse_ipv4_string(parsed.dest_ip),
                src_port=parsed.src_port,
                dst_port=parsed.dest_port,
                protocol=parsed.protocol,
            )

            flow = flows.setdefault(five_tuple, FlowState())
            if flow.tuple is None:
                flow.tuple = five_tuple
            flow.packets += 1
            flow.bytes += len(raw.data)

            payload = parsed.payload
            if (
                flow.app_type in (AppType.UNKNOWN, AppType.HTTPS)
                and not flow.sni
                and parsed.has_tcp
                and parsed.dest_port == 443
                and len(payload) > 5
            ):
                sni = extract_tls_sni(payload)
                if sni:
                    flow.sni = sni
                    flow.app_type = sni_to_app_type(sni)

            if (
                flow.app_type in (AppType.UNKNOWN, AppType.HTTP)
                and not flow.sni
                and parsed.has_tcp
                and parsed.dest_port == 80
                and payload
            ):
                host = extract_http_host(payload)
                if host:
                    flow.sni = host
                    flow.app_type = sni_to_app_type(host)

            if flow.app_type == AppType.UNKNOWN and (
                parsed.dest_port == 53 or parsed.src_port == 53
            ):
                flow.app_type = AppType.DNS

            if flow.app_type == AppType.UNKNOWN:
                if parsed.dest_port == 443:
                    flow.app_type = AppType.HTTPS
                elif parsed.dest_port == 80:
                    flow.app_type = AppType.HTTP

            if not flow.blocked:
                flow.blocked = rules.is_blocked(
                    five_tuple.src_ip, flow.app_type, flow.sni
                )
                if flow.blocked and verbose:
                    line = (
                        f"[BLOCKED] {parsed.src_ip} -> {parsed.dest_ip} "
                        f"({app_type_label(flow.app_type)}"
                    )
                    if flow.sni:
                        line += f": {flow.sni}"
                    print(line + ")")

            app_stats[flow.app_type] += 1

            if flow.blocked:
                dropped += 1
            else:
                forwarded += 1
                incl_len = len(raw.data)
                output.write(
                    PACKET_HEADER.pack(
                        raw.ts_sec, raw.ts_usec, incl_len, incl_len
                    )
                )
                output.write(raw.data)

    reader.close()

    unique_snis: dict[str, AppType] = {}
    for flow in flows.values():
        if flow.sni:
            unique_snis[flow.sni] = flow.app_type

    report = ProcessingReport(
        total_packets=total_packets,
        forwarded=forwarded,
        dropped=dropped,
        flow_count=len(flows),
        app_stats=dict(app_stats),
        unique_snis=unique_snis,
    )

    if verbose:
        _print_report(report, output_path)

    return report


def _print_report(report: ProcessingReport, output_path: str | Path) -> None:
    print()
    print("=" * 64)
    print("PROCESSING REPORT")
    print("-" * 64)
    print(f"Total Packets:  {report.total_packets:>10}")
    print(f"Forwarded:      {report.forwarded:>10}")
    print(f"Dropped:        {report.dropped:>10}")
    print(f"Active Flows:   {report.flow_count:>10}")
    print("-" * 64)
    print("APPLICATION BREAKDOWN")
    print("-" * 64)

    sorted_apps = sorted(
        report.app_stats.items(), key=lambda item: item[1], reverse=True
    )
    total = report.total_packets or 1
    for app, count in sorted_apps:
        pct = 100.0 * count / total
        bar_len = int(pct / 5)
        bar = "#" * bar_len
        print(
            f"{app_type_label(app):<16} {count:>8} {pct:5.1f}% {bar}"
        )

    print("=" * 64)

    if report.unique_snis:
        print("\n[Detected Applications/Domains]")
        for sni, app in sorted(report.unique_snis.items()):
            print(f"  - {sni} -> {app_type_label(app)}")

    print(f"\nOutput written to: {output_path}")