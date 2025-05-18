#!/usr/bin/env python3
"""
rewrite_timestamps.py – Adjust packet timestamps in a PCAP.

Usage:
    python rewrite_timestamps.py input.pcap output.pcap

Optional tweaks:
    • Edit the time_func() definition below.
    • Or pass --expr "idx * 0.05 + 1" on the command line.

Requires:  scapy  (pip install scapy)
"""

import argparse
from scapy.all import rdpcap, wrpcap, PcapReader  # noqa: F401


# ---------------------------------------------------------------------------
# 1) EDIT THIS FUNCTION to change how timestamps are generated
#    idx: 0-based packet index
#    Returns seconds (float) since epoch or since 0, as you prefer.
# ---------------------------------------------------------------------------
def time_func(idx: int) -> float:
    return idx * 0.00005


# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Rewrite packet timestamps in a PCAP with a custom function."
    )
    parser.add_argument("input", help="Path to the original pcap")
    parser.add_argument("output", help="Path to write the modified pcap")
    parser.add_argument(
        "--expr",
        metavar="EXPR",
        help=(
            "Inline Python expression for the timestamp, "
            'using variable "idx" (overrides time_func). '
            'Example: --expr "idx*0.05 + 1"'
        ),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Read all packets (rdpcap returns a PacketList)
    packets = rdpcap(args.input)

    if args.expr:
        # Compile the user expression once for speed
        code = compile(args.expr, "<expr>", "eval")
        ts = lambda i: eval(code, {"idx": i})  # noqa: E731  (lambda-on-the-fly)
    else:
        ts = time_func

    # Apply the timestamps
    for idx, pkt in enumerate(packets):
        pkt.time = float(ts(idx))

    # Write out the modified capture
    wrpcap(args.output, packets)
    print(f"Re-timestamped {len(packets)} packets -> {args.output}")


if __name__ == "__main__":
    main()
