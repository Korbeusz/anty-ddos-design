#!/usr/bin/env python3
from scapy.all import rdpcap, raw
import sys, itertools

f1, f2 = sys.argv[1:3]
p1, p2 = rdpcap(f1), rdpcap(f2)

if len(p1) != len(p2):
    sys.exit(f"different packet counts: {len(p1)} vs {len(p2)}")

for i, (a, b) in enumerate(itertools.zip_longest(p1, p2), 1):
    if raw(a) != raw(b):
        sys.exit(f"first difference at packet #{i}")

print("captures are identical")
