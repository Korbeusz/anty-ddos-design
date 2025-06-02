from random import seed, random
import itertools
from scapy.all import Ether, IP, UDP, TCP, Raw  # type: ignore
from transactron.testing import TestCaseWithSimulator, SimpleTestCircuit
from transactron.testing.testbenchio import CallTrigger

# DUT -------------------------------------------------------------------
from mur.final_build.ParserCMSVol import ParserCMSVol  # adjust if module path differs

# -----------------------------------------------------------------------
#  Helpers (unchanged from the original version)
# -----------------------------------------------------------------------
CYCLE_TIME = 0.001  # 1 ms per cycle – matches ParserCMSVol configuration
RATE_SCALE = 20  # reduce traffic for faster tests


def bytes_to_int_le(b: bytes) -> int:
    """Convert *b* to little‑endian integer (max 64 B → 512 b word)."""
    return int.from_bytes(b, "little")


def split_chunks(buf: bytes, size: int = 64):
    """Split *buf* into *size*-byte chunks (pad last chunk with zeros)."""
    return [buf[i : i + size].ljust(size, b"\0") for i in range(0, len(buf), size)] or [
        b"".ljust(size, b"\0")
    ]


def packets_equal(pkts1, pkts2) -> bool:
    """Return ``True`` if two packet lists contain identical bytes."""
    if len(pkts1) != len(pkts2):
        return False
    for p1, p2 in zip(pkts1, pkts2):
        if bytes(p1) != bytes(p2):
            return False
    return True


def generate_packets(ddos_seconds: set[int]) -> list:
    """Generate packets following ``generate_pcap.py`` logic."""
    # topology -----------------------------------------------------------
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

    FLOWS = [
        dict(proto="TCP", dport=5001, sport=40001, size=120, rate=80000),
        dict(proto="TCP", dport=5002, sport=40002, size=120, rate=20000),
        dict(proto="UDP", dport=6001, sport=40003, size=512, rate=120000),
        dict(proto="UDP", dport=6002, sport=40004, size=512, rate=10000),
        dict(proto="UDP", dport=6003, sport=40005, size=256, rate=200000),
    ]

    # DNS-amplification parameters -------------------------------------
    DDOS_RATE = 500000  # bits per second
    DDOS_SIZE = 1_024  # UDP payload bytes
    DDOS_SPORT = 53
    DDOS_DPORT = 40006
    DDOS_SRC_IPS = [f"198.51.100.{i}" for i in range(1, 251)]
    DDOS_SRC_MAC = "de:ad:be:ef:00:%02x"

    DURATION = 3  # seconds 0, 1, 2

    pkts = []
    t0 = 0.0

    for sec in range(DURATION):
        # baseline traffic ----------------------------------------------
        for i, f in enumerate(FLOWS):
            pps = (f["rate"] // RATE_SCALE) // 8 // f["size"]
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
        # DNS-amplification traffic ------------------------------------
        if sec in ddos_seconds:
            pps_ddos = (DDOS_RATE // RATE_SCALE) // 8 // DDOS_SIZE
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

    pkts.sort(key=lambda p: p.time)
    return pkts


# -----------------------------------------------------------------------
#  Test‑bench
# -----------------------------------------------------------------------
class TestParserCMSVol(TestCaseWithSimulator):
    """Randomised functional TB for **ParserCMSVol** with direct packet output."""

    # ------------------------------------------------------------------
    #  Stimulus generation (identical to the previous version)
    # ------------------------------------------------------------------
    def setup_method(self):
        seed(42)

        pkts = generate_packets({1, 2})
        if not pkts:
            raise RuntimeError("Generated packet list is empty.")

        # Expected output after filtering ------------------------------
        self.expected_packets = generate_packets({1})
        # sanity check -- some packets should be removed by the filter
        assert not packets_equal(pkts, self.expected_packets)

        self.inputs: list[dict] = []  # queued words for *din*

        base_ts = pkts[0].time  # zero‑offset timestamps
        for p in pkts:
            raw = bytes(p)
            pkt_ts = p.time - base_ts

            # Split raw bytes into 64‑byte words -----------------------
            for i, chunk in enumerate(split_chunks(raw, 64)):
                last = i == ((len(raw) + 63) // 64) - 1
                eop_len = len(raw) % 64 if last else 0
                # Corner‑case: exact multiple of 64 B -----------------
                eop_len = 64 if last and eop_len == 0 and raw else eop_len

                self.inputs.append(
                    {
                        "data": bytes_to_int_le(chunk),
                        "end_of_packet": last,
                        "end_of_packet_len": eop_len,
                        "timestamp": pkt_ts,
                    }
                )

        # Shared indices & state flags --------------------------------
        self._in_idx: int = 0  # next word to feed into *din*
        self._driver_done: bool = False  # set True once driver finishes
        self.filtered_packets: list[bytes] = []  # packets reconstructed from *dout*

    # ------------------------------------------------------------------
    #  Driver – feeds *din* words in timestamp order
    # ------------------------------------------------------------------
    async def _drive_din(self, sim):
        cycle = 0
        while self._in_idx < len(self.inputs):
            cur = self.inputs[self._in_idx]
            sim_time = cycle * CYCLE_TIME

            # Honour original packet timestamp ------------------------
            if sim_time < cur["timestamp"]:
                await sim.tick()
                cycle += 1
                continue
            # Additional random delay to simulate real-world behaviour ------
            if random() < 0.1:
                await sim.tick()
                cycle += 1
                continue

            word = {k: v for k, v in cur.items() if k != "timestamp"}
            res = await self.dut.din.call_try(sim, word)
            cycle += 1
            if res is not None:  # accepted
                self._in_idx += 1
        # Let the pipeline drain naturally – mark driver completion
        self._driver_done = True

    # ------------------------------------------------------------------
    #  Sink – pulls packet words from *dout* and assembles filtered pcap
    # ------------------------------------------------------------------
    async def _collect_dout(self, sim):
        cur_pkt = bytearray()
        idle_cycles = 0
        in_middle_of_packet = False
        # Continue until the driver is done *and* dout stays idle for a while
        while not (self._driver_done and idle_cycles > 200):
            resp = await self.dut.dout.call_try(sim)
            assert not (
                (resp is None) and in_middle_of_packet
            ), "Unexpected idle cycle in the middle of a packet."
            if resp is None:
                idle_cycles += 1
                await sim.tick()
                continue

            in_middle_of_packet = True

            idle_cycles = 0  # reset on every successful read

            # Convert 64‑byte LE word back to bytes -------------------
            data_bytes = int(resp["data"]).to_bytes(64, byteorder="little")

            if resp["end_of_packet"]:
                length = resp["end_of_packet_len"] or 64
                cur_pkt.extend(data_bytes[:length])
                # Store completed packet ----------------------------
                self.filtered_packets.append(bytes(cur_pkt))
                cur_pkt.clear()
                in_middle_of_packet = False
            else:
                cur_pkt.extend(data_bytes)

        # After loop, compare with the expected packets ---------------
        assert packets_equal(
            self.filtered_packets, self.expected_packets
        ), "Filtered packets do not match expected output."

    # ------------------------------------------------------------------
    #  Top‑level test (entry‑point)
    # ------------------------------------------------------------------
    def test_pipeline(self):
        core = ParserCMSVol(
            depth=4,
            width=2**14,
            counter_width=32,
            window=int(1 / CYCLE_TIME),
            volume_threshold=5_000,
            cms_fifo_depth=16,
        )
        self.dut = SimpleTestCircuit(core)

        with self.run_simulation(self.dut) as sim:
            sim.add_testbench(self._drive_din)
            sim.add_testbench(self._collect_dout)
