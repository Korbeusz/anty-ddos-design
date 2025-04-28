from __future__ import annotations

"""Randomised functional test‑bench for ``RollingCountMinSketch``.

This version **pre‑generates the entire traffic trace and the list of expected
`query_resp` results *before* the simulator starts**.  That guarantees the
checker process enters its loop right away (no more empty ``self.expected``
edge‑case).

The schedule includes random idle stretches to stress the handshake timing
and reproduces the *resp_valid*‑gated rotation of the three sketches so the
software model stays cycle‑accurate.
"""

from random import randint, random, seed
from collections import deque

from transactron.testing import TestCaseWithSimulator, SimpleTestCircuit

# Local import – adjust if your project layout differs
from mur.count.RollingCountMinSketch import RollingCountMinSketch


class TestRollingCountMinSketch(TestCaseWithSimulator):
    """Cycle‑accurate, fully pre‑scheduled verification of the rolling CMS."""

    # ------------------------------------------------------------------
    #  Test‑vector generation (runs *before* any simulation)
    # ------------------------------------------------------------------
    def setup_method(self):
        seed(42)

        # ── Design parameters ──────────────────────────────────────────
        self.depth            = 4
        self.width            = 64
        self.counter_width    = 32
        self.data_width       = 32
        self.interval_cycles  = 32   # defines the “one‑second” window
        self.total_cycles     = 12_000

        # ── Universal hash prime (matches RTL) ─────────────────────────
        _P = 4_294_967_291  # 2**32 − 5

        def h(row: int, x: int) -> int:
            return (((row + 1) * x) % _P) % self.width

        # ── Three rolling sketches:  current | last | standby ──────────
        def new_sketch():
            return [[0] * self.width for _ in range(self.depth)]

        sketches = [new_sketch(), new_sketch(), new_sketch()]
        current, last, standby = 0, 1, 2

        # ── Schedules for the driver & checker coroutines ──────────────
        self.driver_sched  : list[tuple[int, str, int]] = []  # (delay, op, data)
        self.checker_sched : list[int]                   = []  # delay before read
        self.expected      : deque[dict[str, int]] = deque()

        delay_drv  = 0  # idle cycles waiting *before* the next driver op
        delay_chk  = 0  # idle cycles waiting *before* the next checker read
        outstanding = 0  # queries issued − responses already scheduled

        tick = 0  # 0 … interval_cycles‑1

        for cycle in range(self.total_cycles):
            # -------------------- DRIVER decision --------------------
            if random() < 0.7:  # 70 % chance to perform an operation
                op   = "insert" if random() < 0.6 else "query"
                data = randint(0, (1 << self.data_width) - 1)

                # Record the event with the idle gap that preceded it
                self.driver_sched.append((delay_drv, op, data))
                delay_drv = 0

                if op == "insert":
                    # Update the *current* sketch
                    for row in range(self.depth):
                        sketches[current][row][h(row, data)] += 1
                else:  # op == "query"
                    # Estimate from *last* sketch – stored immediately
                    counts = [sketches[last][row][h(row, data)] for row in range(self.depth)]
                    self.expected.append({"count": min(counts)})
                    outstanding += 1
            else:
                delay_drv += 1  # one more idle cycle before the next op

            # ------------------- CHECKER decision --------------------
            if outstanding > 0 and random() < 0.5:  # 50 % chance to read
                self.checker_sched.append(delay_chk)
                delay_chk = 0
                outstanding -= 1
            else:
                delay_chk += 1

            # ------------------- Role rotation logic -----------------
            if tick == self.interval_cycles - 1 and outstanding == 0:
                # Clear the sketch that moves to *standby*
                sketches[standby] = new_sketch()
                # Rotate roles: current → last → standby → current
                current, last, standby = standby, current, last
                tick = 0
            else:
                tick = (tick + 1) % self.interval_cycles

        # ------------------- Flush outstanding queries --------------
        # Schedule reads (with one idle cycle spacing) until all answers pulled
        while outstanding > 0:
            self.checker_sched.append(delay_chk)
            delay_chk = 1  # leave ≥1 idle cycle between further reads
            outstanding -= 1

        # Any residual driver idle time must be appended to *every* op’s
        # *following* delay, so the trailing gap is irrelevant here.

    # ------------------------------------------------------------------
    #  Driver coroutine – replays the *pre‑computed* stimulus  ----------
    # ------------------------------------------------------------------
    async def driver_process(self, sim):
        for delay, op, data in self.driver_sched:
            for _ in range(delay):
                await sim.tick()
            print(f"driver delay {delay} op {op} data {data}")
            if op == "insert":
                await self.dut.insert.call(sim, {"data": data})
            else:  # "query"
                print(f"query_req: {data}")
                await self.dut.query_req.call(sim, {"data": data})
            print(f"query_reqk: {data}")
            # Advance one cycle *after* every transaction, mirroring the
            # generation model and guaranteeing back‑to‑back requests can’t
            # happen in a single clock.
            await sim.tick()

    # ------------------------------------------------------------------
    #  Checker coroutine – pulls answers on the fixed schedule ----------
    # ------------------------------------------------------------------
    async def checker_process(self, sim):
        for delay in self.checker_sched:
           
            for _ in range(delay):
                await sim.tick()
            print(f"checker delay {delay}")
            resp = await self.dut.query_resp.call(sim)
            assert resp == self.expected.popleft()
            print(f"query_resp: {resp['count']}")
            # One extra tick keeps the handshake phasing identical to the
            # generation‑time model.
            await sim.tick()

    # ------------------------------------------------------------------
    #  Top‑level simulation wrapper ------------------------------------
    # ------------------------------------------------------------------
    def test_pre_scheduled(self):
        core = RollingCountMinSketch(
            depth             = self.depth,
            width             = self.width,
            counter_width     = self.counter_width,
            input_data_width  = self.data_width,
            interval_cycles   = self.interval_cycles,
        )
        self.dut = SimpleTestCircuit(core)

        with self.run_simulation(self.dut) as sim:
            sim.add_testbench(self.driver_process)
            sim.add_testbench(self.checker_process)
