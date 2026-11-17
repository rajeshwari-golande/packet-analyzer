# Packet Analyzer — Python DPI Engine

Offline **deep packet inspection (DPI)** for PCAP files. The engine parses Ethernet/IPv4/TCP traffic, tracks flows by five-tuple, extracts **TLS SNI** and **HTTP Host** values, classifies common applications, applies blocking rules, and writes a filtered PCAP plus a console report.

**Author:** Rajeshwari Golande (`rajeshwari.golande22@pccoepune.org`)

## Requirements

- Python 3.10 or newer
- No third-party packages required for core operation

## Quick start

```bash
python -m packet_analyzer input.pcap output.pcap
```

### Blocking options

```bash
python -m packet_analyzer capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50 --block-domain facebook.com
```

| Option | Effect |
|--------|--------|
| `--block-ip` | Drop packets from a source IPv4 address |
| `--block-app` | Drop flows classified as that application |
| `--block-domain` | Drop when SNI/Host contains the substring |
| `-q` / `--quiet` | Run without progress or report output |

## What it does

1. Reads a standard **libpcap** capture (link-type Ethernet).
2. Builds a **five-tuple** per flow (addresses, ports, protocol).
3. Extracts **SNI** from TLS Client Hello (port 443) and **Host** from HTTP (port 80).
4. Maps hostnames to application labels (YouTube, Facebook, Google, and others).
5. Applies your blocking rules at flow granularity (subsequent packets in a blocked flow are dropped).
6. Writes allowed packets to the output PCAP and prints statistics.

## Project layout

```
packet_analyzer/     Python package (parser, SNI, rules, engine)
legacy/cpp/          Original C++ reference implementation
generate_test_pcap.py Sample PCAP generator
test_dpi.pcap        Sample input capture
```

## Install (optional)

```bash
pip install -e .
packet-analyzer input.pcap output.pcap
```

## Legacy C++ build

The previous C++ implementation is preserved under `legacy/cpp/` for reference. See `legacy/cpp/WINDOWS_SETUP.md` for the original build notes.

## License

MIT — see [LICENSE](LICENSE).