from __future__ import annotations

"""test_cmsvolcontroller.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Randomised functional test‑bench for ``CMSVolController``.

* Opens *example_pcaps/flows.pcap* (same capture as ``test_parsing.py``).
* For every **IPv4** packet it en‑queues **four** words into the controller
  (**push_a**/src‑IP, **push_b**/dst‑IP, **push_c**/dst‑port, **push_s**/tot‑len).
* It continuously drains **out** and builds an output PCAP:
    • ``data == 0``  → *drop* the next packet.
    • ``data == x > 0`` → *write* the next **x** packets to
      *filtered_output.pcap*.

The TB follows the timing/hand‑shake style used throughout *mur*.
"""

from transactron.testing.testbenchio import CallTrigger
from random import random, seed
from ipaddress import IPv4Address

from scapy.all import rdpcap, wrpcap, IP, UDP, TCP

from transactron.testing import TestCaseWithSimulator, SimpleTestCircuit

from mur.count.CMSVolController import CMSVolController

# Simulation time‑step reused from test_parsing.py
CYCLE_TIME = 0.0005


class TestCMSVolController(TestCaseWithSimulator):
    """Functional TB for **CMSVolController** with the updated 4‑queue front‑end."""

    # ------------------------------------------------------------------
    #  Stimulus generation
    # ------------------------------------------------------------------
    def setup_method(self):
        seed(42)

        pkts = rdpcap("example_pcaps/flows.pcap")
        if not pkts:
            raise RuntimeError("Pcap capture is empty or missing.")

        self.inputs: list[dict] = []          # queued SRC/DST/DPORT/LEN tuples
        self.packets: list = []               # original packet order
        self.filtered: list = []              # packets kept by the DUT

        base_ts = pkts[0].time                # zero‑offset timestamps
        for p in pkts:
            # Only IPv4 is relevant for this TB
            if not p.haslayer(IP):
                continue

            ip = p[IP]
            src_ip  = int(IPv4Address(ip.src))
            dst_ip  = int(IPv4Address(ip.dst))
            tot_len = int(ip.len) & 0xFFFF     # 16‑bit total‑length field

            # --- Destination‑port (only UDP/TCP) -----------------------
            dport = 0
            if ip.proto == 17 and p.haslayer(UDP):
                dport = int(p[UDP].dport) & 0xFFFF
            elif ip.proto == 6 and p.haslayer(TCP):
                dport = int(p[TCP].dport) & 0xFFFF

            # Record stimulus + reference packet + timestamp
            self.inputs.append({
                "src":       src_ip,
                "dst":       dst_ip,
                "dport":     dport,
                "tot_len":   tot_len,
                "timestamp": p.time - base_ts,
            })
            self.packets.append(p)

        # Shared position counters for coroutines
        self._in_idx  = 0      # next packet to *send* into the DUT
        self._out_idx = 0      # next packet to *decide* upon from the DUT

    # ------------------------------------------------------------------
    #  Driver – pushes SRC/DST/DPORT/LEN quadruples into the DUT
    # ------------------------------------------------------------------
    async def _driver_process(self, sim):
        cycle = 0
        while self._in_idx < len(self.inputs):
            cur = self.inputs[self._in_idx]
            sim_time = cycle * CYCLE_TIME

            # Honour original timestamps
            if sim_time < cur["timestamp"]:
                await sim.tick()
                cycle += 1
                continue

            # Push one full quadruple atomically (CallTrigger chains)
            await CallTrigger(sim) \
                .call(self.dut.push_a, {"data": cur["src"]}) \
                .call(self.dut.push_b, {"data": cur["dst"]}) \
                .call(self.dut.push_c, {"data": cur["dport"]}) \
                .call(self.dut.push_s, {"data": cur["tot_len"]}) \
                .until_all_done()

            self._in_idx += 1
            cycle += 1

    # ------------------------------------------------------------------
    #  Sink – pulls *decisions* and assembles the filtered capture
    # ------------------------------------------------------------------
    async def _sink_process(self, sim):
        while self._out_idx < len(self.packets):
            resp = await self.dut.out.call(sim)           # back‑pressure

            val = int(resp["data"])
            print(f"out: {val}")

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
        print("Sink done! Filtered packets:", len(self.filtered))

    # ------------------------------------------------------------------
    #  Top‑level test
    # ------------------------------------------------------------------
    def test_filter(self):
        core = CMSVolController(
            depth=4,
            width=16_384,
            counter_width=32,
            window=int(1 / CYCLE_TIME),
            volume_threshold=100_000,   # renamed parameter
            fifo_depth=16,
        )
        self.dut = SimpleTestCircuit(core)

        with self.run_simulation(self.dut) as sim:
            sim.add_testbench(self._driver_process)
            sim.add_testbench(self._sink_process)

        # After simulation, write resulting capture --------------------
        wrpcap("filtered_output.pcap", self.filtered)
        print(f"Filtered pcap written with {len(self.filtered)} packets.")
