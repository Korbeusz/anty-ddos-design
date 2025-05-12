from __future__ import annotations

"""test_parsercmsvol.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Functional test-bench for **ParserCMSVol** – a unified packet-parsing and
count-/volume-statistics pipeline.

The stimulus and timing model follow *test_parsing.py* while the
sink/decision recording mirrors *test_cmsvolcontroller.py*.

Simulation input:  *example_pcaps/flows.pcap*
Simulation output: *filtered_output_pipeline.pcap* (written after the run)
"""

from random import seed
from scapy.all import rdpcap, wrpcap  # type: ignore
from transactron.testing import TestCaseWithSimulator, SimpleTestCircuit
from transactron.testing.testbenchio import CallTrigger

# DUT -------------------------------------------------------------------
from mur.final_build.ParserCMSVol import ParserCMSVol  # adjust if module path differs

# -----------------------------------------------------------------------
#  Helpers copied from test_parsing.py                                   
# -----------------------------------------------------------------------
CYCLE_TIME = 0.0001  # 2 µs per cycle (same as other TBs)


def bytes_to_int_le(b: bytes) -> int:
    """Convert *b* to little-endian integer (max 64 B → 512 b word)."""
    return int.from_bytes(b, "little")


def split_chunks(buf: bytes, size: int = 64):
    """Split *buf* into *size*-byte chunks (pad last one with zeros)."""
    return [buf[i : i + size].ljust(size, b"\0") for i in range(0, len(buf), size)] or [b"".ljust(size, b"\0")]


# -----------------------------------------------------------------------
#  Test-bench                                                            
# -----------------------------------------------------------------------
class TestParserCMSVol(TestCaseWithSimulator):
    """Randomised functional TB for **ParserCMSVol**."""

    # ------------------------------------------------------------------
    #  Stimulus generation
    # ------------------------------------------------------------------
    def setup_method(self):
        seed(42)

        pkts = rdpcap("example_pcaps/flows.pcap")
        if not pkts:
            raise RuntimeError("Input pcap is empty or missing.")

        self.inputs: list[dict] = []  # queued words for *din*
        self.packets: list = []       # original packet order

        base_ts = pkts[0].time  # zero-offset timestamps
        for p in pkts:
            raw = bytes(p)
            pkt_ts = p.time - base_ts

            # Split raw bytes into 64-byte words -----------------------
            for i, chunk in enumerate(split_chunks(raw, 64)):
                last = i == ((len(raw) + 63) // 64) - 1
                eop_len = len(raw) % 64 if last else 0
                # Corner-case: exact multiple of 64 B -----------------
                eop_len = 64 if last and eop_len == 0 and raw else eop_len

                self.inputs.append(
                    {
                        "data": bytes_to_int_le(chunk),
                        "end_of_packet": last,
                        "end_of_packet_len": eop_len,
                        "timestamp": pkt_ts,
                    }
                )

            self.packets.append(p)

        # Shared indices for coroutines --------------------------------
        self._in_idx: int = 0   # next word to feed into *din*
        self._out_idx: int = 0  # next packet to decide upon
        self._filtered: list = []  # packets kept by the DUT

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

            word = {k: v for k, v in cur.items() if k != "timestamp"}
            res = await self.dut.din.call_try(sim, word)
            cycle += 1
            if res is not None:  # accepted
                self._in_idx += 1

    # ------------------------------------------------------------------
    #  Sink – pulls decisions from *out* and builds filtered capture
    # ------------------------------------------------------------------
    async def _sink_out(self, sim):
        while self._out_idx < len(self.packets):
            resp = await self.dut.out.call(sim)
            if resp["valid"] == 0:
                continue  # back-pressure

            val = int(resp["data"])
            if val == 0:
                # Drop exactly one packet ----------------------------
                print("Dropping packet")
                self._out_idx += 1
            else:
                # Keep *val* packets (or until exhausted) -----------
                for _ in range(val):
                    if self._out_idx >= len(self.packets):
                        break
                    self._filtered.append(self.packets[self._out_idx])
                    self._out_idx += 1
        # After loop, write resulting capture -------------------------
        wrpcap("filtered_output_pipeline.pcap", self._filtered)
        print(f"Filtered pcap written with {len(self._filtered)} packets.")

    # ------------------------------------------------------------------
    #  Top-level test (entry-point)
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
            sim.add_testbench(self._sink_out)
