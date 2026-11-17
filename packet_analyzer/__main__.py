"""Command-line entry point for the DPI engine."""

from __future__ import annotations

import argparse
import sys

from .engine import process_pcap
from .rules import BlockingRules


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="packet_analyzer",
        description="Deep packet inspection over offline PCAP files.",
    )
    parser.add_argument("input_pcap", help="Input PCAP capture file")
    parser.add_argument("output_pcap", help="Filtered output PCAP file")
    parser.add_argument(
        "--block-ip",
        action="append",
        default=[],
        metavar="IP",
        help="Block traffic from a source IPv4 address",
    )
    parser.add_argument(
        "--block-app",
        action="append",
        default=[],
        metavar="APP",
        help="Block an application label (e.g. YouTube, Facebook)",
    )
    parser.add_argument(
        "--block-domain",
        action="append",
        default=[],
        metavar="DOMAIN",
        help="Block when SNI/Host contains this substring",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress per-packet and summary console output",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    rules = BlockingRules()
    for ip in args.block_ip:
        rules.block_ip(ip)
    for app in args.block_app:
        rules.block_app(app)
    for domain in args.block_domain:
        rules.block_domain(domain)

    if not args.quiet:
        print()
        print("DPI Engine")
        print("-" * 32)
        print()

    report = process_pcap(
        args.input_pcap,
        args.output_pcap,
        rules,
        verbose=not args.quiet,
    )
    return 0 if report is not None else 1


if __name__ == "__main__":
    sys.exit(main())