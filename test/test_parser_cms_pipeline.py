from __future__ import annotations

"""test_parser_cms_pipeline.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Functional test‑bench for **ParserCMSVol** – a unified packet‑parsing and
count‑/volume‑statistics pipeline.

* Stimulus generation follows the original *test_parsing.py* logic.
* **NEW:** Instead of interpreting the numerical *out* decisions, the TB now
  consumes the fully reconstructed packet stream available on **dout** and
  writes it verbatim to *filtered_output_pipeline.pcap*.

Simulation input:  *example_pcaps/flows.pcap*
Simulation output: *filtered_output_pipeline.pcap* (written after the run)
"""

from random import seed, random
from scapy.all import rdpcap, wrpcap  # type: ignore
from transactron.testing import TestCaseWithSimulator, SimpleTestCircuit
from transactron.testing.testbenchio import CallTrigger

# DUT -------------------------------------------------------------------
from mur.final_build.ParserCMSVol import ParserCMSVol  # adjust if module path differs

# -----------------------------------------------------------------------
#  Helpers (unchanged from the original version)
# -----------------------------------------------------------------------
CYCLE_TIME = 0.0001  # 2 µs per cycle – matches ParserCMSVol configuration


def bytes_to_int_le(b: bytes) -> int:
    """Convert *b* to little‑endian integer (max 64 B → 512 b word)."""
    return int.from_bytes(b, "little")


def split_chunks(buf: bytes, size: int = 64):
    """Split *buf* into *size*-byte chunks (pad last chunk with zeros)."""
    return [buf[i : i + size].ljust(size, b"\0") for i in range(0, len(buf), size)] or [
        b"".ljust(size, b"\0")
    ]


def compare_pcap_files(file1: str, file2: str) -> bool:
    """Compare two pcap files and return True if they are identical."""
    pkts1 = rdpcap(file1)
    pkts2 = rdpcap(file2)

    if len(pkts1) != len(pkts2):
        return False

    for pkt1, pkt2 in zip(pkts1, pkts2):
        if bytes(pkt1) != bytes(pkt2):
            return False

    return True


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

        pkts = rdpcap("example_pcaps/flows.pcap")
        if not pkts:
            raise RuntimeError("Input pcap is empty or missing.")

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

        # After loop, write resulting capture -------------------------
        wrpcap("example_pcaps/filtered_output_pipeline.pcap", self.filtered_packets)
        print(f"Filtered pcap written with {len(self.filtered_packets)} packets.")
        # Compare with the original pcap (if available) ---------------
        assert compare_pcap_files(
            "example_pcaps/filtered_output_pipeline.pcap",
            "example_pcaps/flows_answer.pcap",
        ), "Filtered pcap does not match original."

    # ------------------------------------------------------------------
    #  Top‑level test (entry‑point)
    # ------------------------------------------------------------------
    def test_pipeline(self):
        core = ParserCMSVol(
            depth=4,
            width=16_384,
            counter_width=32,
            window=int(1 / CYCLE_TIME),
            volume_threshold=100_000,
            cms_fifo_depth=16,
        )
        self.dut = SimpleTestCircuit(core)

        with self.run_simulation(self.dut) as sim:
            sim.add_testbench(self._drive_din)
            sim.add_testbench(self._collect_dout)
