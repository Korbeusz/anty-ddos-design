from __future__ import annotations

"""Functional testbench for the ParserCMSVolModule wrapper.

This test mirrors ``test_parser_cms_pipeline.py`` but exercises the
``ParserCMSVolModule`` which exposes a 520-bit FIFO style interface.
The packets from ``flows.pcap`` are fed through the module and the
resulting packets are written to ``filtered_output_module.pcap`` for
comparison with the reference capture.
"""

from random import seed
from scapy.all import rdpcap, wrpcap  # type: ignore
from transactron.testing import (
    TestCaseWithSimulator,
    TestbenchContext as TBContext,
)

from mur.helping_modules.parsercmsvol_module import ParserCMSVolModule


CYCLE_TIME = 0.0001  # same as the pipeline test


def bytes_to_int_le(b: bytes) -> int:
    """Convert ``b`` to little-endian integer."""
    return int.from_bytes(b, "little")


def split_chunks(buf: bytes, size: int = 64):
    """Split ``buf`` into ``size``-byte chunks padding the last chunk."""
    return (
        [buf[i:i + size].ljust(size, b"\0") for i in range(0, len(buf), size)]
        or [b"".ljust(size, b"\0")]
    )


def compare_pcap_files(file1: str, file2: str) -> bool:
    pkts1 = rdpcap(file1)
    pkts2 = rdpcap(file2)
    if len(pkts1) != len(pkts2):
        return False
    for a, b in zip(pkts1, pkts2):
        if bytes(a) != bytes(b):
            return False
    return True


class TestParserCMSVolModule(TestCaseWithSimulator):
    """Randomised functional test for :class:`ParserCMSVolModule`."""

    def setup_method(self):
        seed(42)
        pkts = rdpcap("example_pcaps/flows.pcap")
        if not pkts:
            raise RuntimeError("Input pcap is empty or missing.")

        self.words: list[int] = []
        for p in pkts:
            raw = bytes(p)
            for i, chunk in enumerate(split_chunks(raw, 64)):
                last = i == ((len(raw) + 63) // 64) - 1
                eop_len = len(raw) % 64 if last else 0
                if last and eop_len == 0 and raw:
                    eop_len = 64
                sop = 1 if i == 0 else 0
                eop = 1 if last else 0
                empty = (64 - eop_len) if eop else 0
                word = (
                    (sop << 519)
                    | (eop << 518)
                    | (empty << 512)
                    | bytes_to_int_le(chunk)
                )
                self.words.append(word)

        self.filtered_packets: list[bytes] = []
        self.dut = ParserCMSVolModule()
        self.driver_done = False

    # --------------------------------------------------------------
    #  Driver: emulates an upstream FIFO
    # --------------------------------------------------------------
    async def _drive_input(self, sim: TBContext):
        idx = 0
        sim.set(self.dut.rst_n, 1)
        sim.set(self.dut.in_valid, 0)
        sim.set(self.dut.in_empty, 0 if self.words else 1)
        sim.set(self.dut.out_full, 0)

        while idx < len(self.words):
            word = self.words[idx]
            sim.set(self.dut.in_data, word)
            sim.set(self.dut.in_valid, 1)
            await sim.tick()
            # wait until DUT acknowledges by asserting rd_en_fifo
            while not sim.get(self.dut.rd_en_fifo):
                await sim.tick()
            sim.set(self.dut.in_valid, 0)
            idx += 1
            sim.set(self.dut.in_empty, 0 if idx < len(self.words) else 1)
            await sim.tick()
        self.driver_done = True

    # --------------------------------------------------------------
    #  Sink: collects output words and rebuilds packets
    # --------------------------------------------------------------
    async def _collect_output(self, sim: TBContext):
        cur = bytearray()
        idle = 0
        while not (self.driver_done and idle > 200):
            if sim.get(self.dut.wr_en_fifo):
                val = sim.get(self.dut.out_data)
                data = val & ((1 << 512) - 1)
                empty = (val >> 512) & 0x3F
                eop = (val >> 518) & 1
                sop = (val >> 519) & 1
                bytes_le = data.to_bytes(64, "little")
                if sop:
                    cur.clear()
                if eop:
                    length = 64 - empty if empty else 64
                    cur.extend(bytes_le[:length])
                    self.filtered_packets.append(bytes(cur))
                    cur.clear()
                else:
                    cur.extend(bytes_le)
                idle = 0
                await sim.tick()
            else:
                idle += 1
                await sim.tick()

        wrpcap(
            "example_pcaps/filtered_output_module.pcap",
            self.filtered_packets,
        )
        assert compare_pcap_files(
            "example_pcaps/filtered_output_module.pcap",
            "example_pcaps/flows_answer.pcap",
        )

    # --------------------------------------------------------------
    #  Entry point
    # --------------------------------------------------------------
    def test_pipeline_wrapper(self):
        with self.run_simulation(self.dut) as sim:
            sim.add_testbench(self._drive_input)
            sim.add_testbench(self._collect_output)
