#!/usr/bin/env python3
"""
Write a 3-second PCAP:
  • sec 0  : five baseline flows
  • sec 1-2: baseline flows + 50 Mbit/s DNS-amplification traffic
Packets are never transmitted – we only produce flows.pcap.
"""

from scapy.all import Ether, IP, UDP, TCP, Raw, wrpcap
import time, itertools

# ------------ topology -------------------------------------------------
SERVER_IP = "192.168.1.100"
SERVER_MAC = "02:42:c0:a8:01:64"

CLIENT_IPS = [
    "192.168.1.101",
    "192.168.1.102",
    "192.168.1.103",
    "192.168.1.104",
    "192.168.1.105",
]
CLIENT_MACS = [
    "02:42:c0:a8:01:65",
    "02:42:c0:a8:01:66",
    "02:42:c0:a8:01:67",
    "02:42:c0:a8:01:68",
    "02:42:c0:a8:01:69",
]
# -----------------------------------------------------------------------

FLOWS = [
    dict(proto="TCP", dport=5001, sport=40001, size=120, rate=80000),
    dict(proto="TCP", dport=5002, sport=40002, size=120, rate=20000),
    dict(proto="UDP", dport=6001, sport=40003, size=512, rate=120000),
    dict(proto="UDP", dport=6002, sport=40004, size=512, rate=10000),
    dict(proto="UDP", dport=6003, sport=40005, size=256, rate=200000),
]

# ---------- DNS-amplification parameters -------------------------------
DDOS_SECONDS = {1, 2}  # attack only during these seconds
DDOS_RATE = 500000  # bits per second
DDOS_SIZE = 1_024  # UDP payload bytes
DDOS_SPORT = 53  # source port of “amplifier”
DDOS_DPORT = 40006  # arbitrary high port on victim
DDOS_SRC_IPS = [f"198.51.100.{i}" for i in range(1, 251)]  # 250 bots
DDOS_SRC_MAC = "de:ad:be:ef:00:%02x"  # template
# -----------------------------------------------------------------------

DURATION = 3  # seconds 0, 1, 2
pkts, t0 = [], time.time()

for sec in range(DURATION):
    # ---------------- baseline test traffic ---------------------------
    for i, f in enumerate(FLOWS):
        pps = f["rate"] // 8 // f["size"]
        for n in range(int(pps)):
            eth = Ether(src=CLIENT_MACS[i], dst=SERVER_MAC)
            ip = IP(src=CLIENT_IPS[i], dst=SERVER_IP)
            l4 = (
                TCP(sport=f["sport"], dport=f["dport"], flags="S")
                if f["proto"] == "TCP"
                else UDP(sport=f["sport"], dport=f["dport"])
            )
            pkt = eth / ip / l4 / Raw(b"x" * f["size"])
            pkt.time = t0 + sec + n / pps
            pkts.append(pkt)

    # ---------------- DNS-amplification traffic -----------------------
    if sec in DDOS_SECONDS:
        pps_ddos = DDOS_RATE // 8 // DDOS_SIZE
        src_cycle = itertools.cycle(DDOS_SRC_IPS)
        for n in range(int(pps_ddos)):
            src_ip = next(src_cycle)
            src_mac = DDOS_SRC_MAC % (n % 256)
            eth = Ether(src=src_mac, dst=SERVER_MAC)
            ip = IP(src=src_ip, dst=SERVER_IP)
            l4 = UDP(sport=DDOS_SPORT, dport=DDOS_DPORT)
            pkt = eth / ip / l4 / Raw(b"X" * DDOS_SIZE)
            pkt.time = t0 + sec + n / pps_ddos
            pkts.append(pkt)

# ------------------ ensure chronological order -------------------------
pkts.sort(key=lambda p: p.time)  # <-- NEW LINE

# ----------------------- write PCAP ------------------------------------
wrpcap("flows.pcap", pkts)
print(f"wrote flows.pcap with {len(pkts):,} packets in strict time order")
