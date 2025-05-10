from __future__ import annotations
"""test_cmsvolcontroller.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Functional test‑bench for **CMSVolController**.

* Reads packets from *example_pcaps/flows.pcap* (same capture as other TBs).
* For **every IPv4 packet** extracts
    * 32‑bit *source IP*  → ingress FIFO A  (``push_a``)
    * 32‑bit *destination IP* → ingress FIFO B  (``push_b``)
    * 16‑bit *total_length* from the IPv4 header → ingress FIFO S  (``push_s``)
  and injects them *in that order*, one value per cycle.  Between successive
  packets a timestamp‑based throttling identical to *test_parsing.py* enforces
  realistic back‑pressure.
* A minimal **Python reference model** mirrors the RTL behaviour cycle‑for‑cycle
  (including the 1‑cycle latency of *query_resp*) and produces the expected
  sequence of results that should be popped from *pop_count*.

If the model ever disagrees with the DUT, an assertion will fail and the CI
run will flag the problem.
"""

import math
import random
from collections import deque
from pathlib import Path
from typing import Deque, List
from collections import defaultdict
from scapy.all import rdpcap  # type: ignore

from transactron.testing import SimpleTestCircuit, TestCaseWithSimulator

from mur.count.CMSVolController import CMSVolController  # RTL under test

# -----------------------------------------------------------------------------
#  Software reference model ----------------------------------------------------
# -----------------------------------------------------------------------------

_P = 4_294_967_291  # 2**32 − 5 – largest 32‑bit prime (same constant as RTL)


def _hash(a: int, b: int, width: int, x: int) -> int:
    """Purely combinational 32‑bit universal hash → [0, width‑1]."""
    return ((a * (x % _P) + b) % _P) % width


class _SoftCountMinSketch:
    """Single‑row CMS suitable for the reference model."""

    def __init__(self, width: int, a: int, b: int):
        self._width = width
        self._a = a % _P
        self._b = b % _P
        self._buckets: List[int] = [0] * width

    # --------------------------------------------------
    def insert(self, item: int):
        self._buckets[_hash(self._a, self._b, self._width, item)] += 1

    # --------------------------------------------------
    def query(self, item: int) -> int:
        return self._buckets[_hash(self._a, self._b, self._width, item)]

    # --------------------------------------------------
    def clear(self):
        for i in range(self._width):
            self._buckets[i] = 0


class _SoftRollingCMS:
    """Cycle‑accurate mirror of *RollingCountMinSketch* (3 sketches)."""

    def __init__(self, depth: int, width: int):
        # Build CountMinSketch rows for every sketch
        self._sketches: List[List[_SoftCountMinSketch]] = []
        for _ in range(3):
            rows = [_SoftCountMinSketch(width, row + 1, 0) for row in range(depth)]
            self._sketches.append(rows)

        self._head = 0  # index of UPDATE sketch
        self._mode = 0  # 0 = UPDATE  1 = QUERY
        self._pending_resp: int | None = None  # conveys 1‑cycle latency

    # --------------------------------------------------
    def _rotate_roles(self):
        cur_query = (self._head + 1) % 3
        # Wipe the sketch that *was* QUERY
        for row in self._sketches[cur_query]:
            row.clear()
        # Advance UPDATE → QUERY → CLEAR → UPDATE …
        self._head = (self._head + 2) % 3

    # --------------------------------------------------
    def set_mode(self, mode: int):
        self._mode = mode & 1

    # --------------------------------------------------
    def change_roles_if_needed(self):
        if self._mode == 0:  # Called exactly when VOL mode switches to UPDATE
            self._rotate_roles()

    # --------------------------------------------------
    def insert_or_query(self, item: int) -> int | None:
        """Process *one* item – mirrors the RTL latency.

        Returns *None* or a 32‑bit count estimated by the QUERY sketch.
        """
        resp = self._pending_resp  # response from the *previous* cycle
        self._pending_resp = None

        if self._mode == 0:  # UPDATE mode – INSERT only
            for row in self._sketches[self._head]:
                row.insert(item)
        else:               # QUERY mode – non‑destructive read from QUERY sketch
            q_idx = (self._head + 1) % 3
            est = min(row.query(item) for row in self._sketches[q_idx])
            self._pending_resp = est  # shows up 1 cycle later

        return resp


class _SoftVolCounter:
    """Reference for *VolCounter* – emits *mode* every *window* samples."""

    def __init__(self, window: int, threshold: int):
        self._window = window
        self._threshold = threshold
        self._acc = 0
        self._pos = 0

    # --------------------------------------------------
    def add_sample(self, sample: int) -> int | None:
        """Add *sample* and return *mode* (0/1) exactly at the window tail."""
        self._acc += sample
        self._pos += 1
        if self._pos == self._window:
            mode = 1 if self._acc > self._threshold else 0
            self._acc = 0
            self._pos = 0
            return mode
        return None


class _SoftCMSVolController:
    """Self‑contained software twin of *CMSVolController* (cycle‑accurate)."""

    def __init__(self, *, depth: int, width: int, window: int, threshold: int):
        self._cms = _SoftRollingCMS(depth, width)
        self._vc = _SoftVolCounter(window, threshold)

    # --------------------------------------------------
    def step(self, src_ip: int, dst_ip: int, total_len: int) -> int | None:
        # 1. Latched response from the *previous* cycle
        resp = self._cms.insert_or_query((dst_ip << 32) | src_ip)

        # 2. Update VolCounter and act on window boundary
        mode = self._vc.add_sample(total_len)
        if mode is not None:       # happens once every *window* packets
            self._cms.set_mode(mode)
            self._cms.change_roles_if_needed()

        return resp


# -----------------------------------------------------------------------------
#  Helper parsers (minimal subset) ---------------------------------------------
# -----------------------------------------------------------------------------

def _parse_ipv4(pkt: bytes) -> tuple[int, int, int] | None:
    """Return (src_ip, dst_ip, total_len) for IPv4 packets or *None*."""
    if len(pkt) < 14:
        return None
    ethertype = int.from_bytes(pkt[12:14], "big")
    if ethertype != 0x0800:  # IPv4 only
        return None
    ip_off = 14  # no VLAN parsing in this stripped‑down helper
    if len(pkt) < ip_off + 20:
        return None
    first = pkt[ip_off]
    ihl = first & 0x0F
    hdr_len = ihl * 4
    if len(pkt) < ip_off + hdr_len:
        return None
    total_len = int.from_bytes(pkt[ip_off + 2 : ip_off + 4], "big")
    src_ip = int.from_bytes(pkt[ip_off + 12 : ip_off + 16], "big")
    dst_ip = int.from_bytes(pkt[ip_off + 16 : ip_off + 20], "big")
    return src_ip, dst_ip, total_len


# -----------------------------------------------------------------------------
#  Test‑bench class ------------------------------------------------------------
# -----------------------------------------------------------------------------

CYCLE_TIME = 0.0005  # seconds per simulated clock edge – same as in test_parsing


class TestCMSVolController(TestCaseWithSimulator):
    """Randomised TB that cross‑checks RTL vs the Python reference model."""

    # --------------------------------------------------
    def setup_method(self):
        random.seed(42)

        # ── DUT / model parameters – keep in sync! ───────────────────
        self.depth = 4
        self.width = 32
        self.window = int(1/CYCLE_TIME)  
        self.threshold = 10_000

        # ── PCAP pre‑processing --------------------------------------
        pcap_path = Path("example_pcaps/flows.pcap")
        pkts = rdpcap(str(pcap_path))

        # Ingress operations in arrival order
        self.ops: List[dict] = []  # one dict per IPv4 packet
        base_ts = pkts[0].time 

        for sc in pkts:
            parsed = _parse_ipv4(bytes(sc))
            if parsed is None:
                continue  # ignore non‑IPv4 frames
            src_ip, dst_ip, tot_len = parsed
            self.ops.append(
                {
                    "src": src_ip,
                    "dst": dst_ip,
                    "len": tot_len & 0xFFFF,  # guard against oversize
                    "timestamp": sc.time - base_ts,
                }
            )

        # ── Expected results via software model ----------------------
        self.expected: Deque[int] = deque()
        model = _SoftCMSVolController(
            depth=self.depth,
            width=self.width,
            window=self.window,
            threshold=self.threshold,
        )
        for op in self.ops:
            r = model.step(op["src"], op["dst"], op["len"])
            if r is not None:
                self.expected.append(r)

    # --------------------------------------------------
    async def _driver(self, sim):
        """Inject src/dst/len triples into the three ingress FIFOs."""
        cycle = 0
        idx = 0        # packet index
        phase = 0      # 0 → src, 1 → dst, 2 → len
        len_acc = defaultdict(int) 
        while idx < len(self.ops):
            t_sim = cycle * CYCLE_TIME
            pkt = self.ops[idx]

            # honour original timestamp (similar to test_parsing.py)
            if t_sim < pkt["timestamp"]:
                await sim.tick()
                cycle += 1
                continue
            
            word = {"data": pkt["src"]}
            res = await self.dut.push_a.call(sim, word)
            
            word = {"data": pkt["dst"]}
            res = await self.dut.push_b.call(sim, word)
            len_acc[int(t_sim)] += pkt["len"]
            print(f"len_acc: {pkt['len']} (expected {len_acc[int(t_sim)]})")
            word = {"data": pkt["len"]}
            res = await self.dut.push_s.call(sim, word)

            idx += 1
            cycle += 1
        #print len acc 
        print(f"len_acc: {len_acc}")

    # --------------------------------------------------
    async def _checker(self, sim):
        """Pull *pop_count* and compare with the reference queue."""
        while self.expected:
            resp = await self.dut.pop_count.call_try(sim)
            if resp is None:
                await sim.tick()
                continue
            got = int(resp["data"])
            exp = self.expected.popleft()
            print(f"pop_count: {got} (expected {exp})")
            assert got == exp, f"CMSVolController mismatch: got {got}, exp {exp}"

    # --------------------------------------------------
    def test_against_reference(self):
        core = CMSVolController(
            depth=self.depth,
            width=self.width,
            counter_width=32,
            window=self.window,
            threshold=self.threshold,
        )
        self.dut = SimpleTestCircuit(core)

        with self.run_simulation(self.dut) as sim:
            sim.add_testbench(self._driver)
            sim.add_testbench(self._checker)
