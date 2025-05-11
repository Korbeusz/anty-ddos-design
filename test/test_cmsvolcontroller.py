from __future__ import annotations

"""test_cmsvolcontroller.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Randomised functional test‑bench for ``CMSVolController``.

* Opens *example_pcaps/flows.pcap* (same capture as ``test_parsing.py``).
* For every IPv4 packet it en‑queues three words into the controller:
    1. **push_a**  – IPv4 *source address* (32 bits, low word)
    2. **push_b**  – IPv4 *destination address* (32 bits, high word)
    3. **push_s**  – IPv4 *total length* field (16 bits)
* It continuously drains **pop_count** and builds an output pcap according
  to the controller’s decision stream:
    • ``data == 0``  → *drop* the next packet.
    • ``data == x > 0`` → *write* the next **x** packets to
      *filtered_output.pcap*.

The TB follows the timing/hand‑shake style used throughout the other tests
in *mur*.
"""
from transactron.testing.testbenchio import CallTrigger
from random import random, seed
from ipaddress import IPv4Address
from collections import deque

from scapy.all import rdpcap, wrpcap, IP

from transactron.testing import TestCaseWithSimulator, SimpleTestCircuit

from mur.count.CMSVolController import CMSVolController

# Simulation time‑step used in test_parsing.py
CYCLE_TIME = 0.0005

class TestCMSVolController(TestCaseWithSimulator):

    # ------------------------------------------------------------------
    #  Stimulus generation
    # ------------------------------------------------------------------
    def setup_method(self):
        seed(42)

        pkts = rdpcap("example_pcaps/flows.pcap")
        if not pkts:
            raise RuntimeError("Pcap capture is empty or missing.")

        self.inputs: list[dict] = []          # queued SRC/DST/LEN triples
        self.packets: list = []               # original packet order
        self.filtered: list = []              # packets kept by the DUT

        base_ts = pkts[0].time                # zero‑offset timestamps
        for p in pkts:
            # Only IPv4 packets are relevant for this TB
            if not p.haslayer(IP):
                continue
            ip = p[IP]
            src_ip = int(IPv4Address(ip.src))
            dst_ip = int(IPv4Address(ip.dst))
            tot_len = int(ip.len)

            # Record stimulus + reference packet
            self.inputs.append({
                "src":       src_ip,
                "dst":       dst_ip,
                "tot_len":   tot_len & 0xFFFF,   # 16‑bit field
                "timestamp": p.time - base_ts,
            })
            self.packets.append(p)

        # Position counters shared between coroutines
        self._in_idx   = 0     # next packet to *send* into the DUT
        self._out_idx  = 0     # next packet to *decide* upon from the DUT

    # ------------------------------------------------------------------
    #  Driver process – pushes SRC/DST/LEN triples into the DUT
    # ------------------------------------------------------------------
    async def _driver_process(self, sim):
        cycle = 0
        while self._in_idx < len(self.inputs):
            cur = self.inputs[self._in_idx]
            sim_time = cycle * CYCLE_TIME

            # Honour original packet timestamps
            if sim_time < cur["timestamp"]:
                await sim.tick()
                cycle += 1
                continue
            
            await CallTrigger(sim).call(self.dut.push_a,{"data": cur["src"]} )\
                .call(self.dut.push_b,{"data":cur["dst"]})\
                    .call(self.dut.push_s, {"data": cur["tot_len"]}).until_all_done()
            cycle += 1
            # Triple accepted – move to the next packet
            self._in_idx += 1

    # ------------------------------------------------------------------
    #  Sink process – pulls decisions and builds the filtered pcap
    # ------------------------------------------------------------------
    async def _sink_process(self, sim):
        while self._out_idx < len(self.packets):
        

            resp = await self.dut.pop_count.call(sim)
            val = int(resp["data"])
            print(f"pop_count: {val}")
            if val == 2323:
                continue
            if val == 0:
                # Drop exactly *one* packet
                self._out_idx += 1
            else:
                # Keep *val* packets (or until input exhausted)
                for _ in range(val):
                    if self._out_idx >= len(self.packets):
                        break
                    self.filtered.append(self.packets[self._out_idx])
                    self._out_idx += 1
        print("sink done!")

    # ------------------------------------------------------------------
    #  Top‑level test
    # ------------------------------------------------------------------
    def test_filter(self):
        core = CMSVolController(depth=4,width=16384,counter_width=32,
            window=int(1/CYCLE_TIME),
            threshold=100_000,
            fifo_depth=16,
        )
        self.dut = SimpleTestCircuit(core)

        with self.run_simulation(self.dut) as sim:
            sim.add_testbench(self._driver_process)
            sim.add_testbench(self._sink_process)

        # --- After simulation write the resulting capture --------------
        wrpcap("filtered_output.pcap", self.filtered)
        print(f"Filtered pcap written with {len(self.filtered)} packets.")
