"""Offline deep packet inspection for PCAP capture files."""

from .engine import process_pcap
from .rules import BlockingRules

__version__ = "2.0.0"
__all__ = ["BlockingRules", "process_pcap", "__version__"]