#!/usr/bin/env python3
"""
sum_ip_len_bins.py – Summarize IPv4 Total Length per 1‑second interval.

This utility reads a .pcap file and reports, for each consecutive
one‑second time bucket starting at the first packet, the sum of the
IPv4 *Total Length* field over all packets whose timestamp falls
into that bucket.

Usage
-----
    python sum_ip_len_bins.py capture.pcap

Options
-------
    -b, --bin-size FLOAT   Width of time bin in seconds (default: 1.0)

Example
-------
    $ python sum_ip_len_bins.py demo.pcap
    [0, 1): 12345
    [1, 2): 6789
    [2, 3): 0
    ...

Requirements
------------
    pip install scapy

"""

import argparse
from collections import defaultdict
from scapy.utils import PcapReader
from scapy.layers.inet import IP
from pathlib import Path


def parse_args() -> argparse.Namespace:
    """Parse command‑line arguments."""
    parser = argparse.ArgumentParser(
        description="Sum IPv4 total length per time bin from a pcap capture.")
    parser.add_argument(
        "pcap",
        type=Path,
        help="Input pcap file (e.g., capture.pcap)")
    parser.add_argument(
        "-b",
        "--bin-size",
        type=float,
        default=1.0,
        help="Width of each time bin in seconds (default: 1.0)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not args.pcap.exists():
        raise FileNotFoundError(args.pcap)

    # Map bin index -> accumulated length in bytes
    bins: dict[int, int] = defaultdict(int)
    first_ts: float | None = None

    with PcapReader(str(args.pcap)) as reader:
        for pkt in reader:
            # Establish zero point at first packet
            if first_ts is None:
                first_ts = pkt.time

            # Time since the capture began
            rel_time = pkt.time - first_ts
            bin_idx = int(rel_time // args.bin_size)

            # IPv4 only: sum the Total Length header field (bytes on the wire)
            if IP in pkt:
                bins[bin_idx] += int(pkt[IP].len)

    # Pretty‑print results in ascending order of bins
    for idx in sorted(bins):
        start = idx * args.bin_size
        end = start + args.bin_size
        print(f"[{start:g}, {end:g}): {bins[idx]}")


if __name__ == "__main__":
    main()
