# test_volcounter.py  (updated)

from random import randint, random, seed
from collections import deque

from transactron.testing import TestCaseWithSimulator, SimpleTestCircuit
from mur.count.VolCounter import VolCounter


class TestVolCounter(TestCaseWithSimulator):
    """
    Randomised functional test-bench for ``VolCounter`` that now injects
    random *idle* cycles.  Every idle «sim.tick()» is interpreted as a
    zero-valued sample in the reference model.
    """

    # ──────────────────────────────────────────────────────────────
    #  Stimulus & reference model
    # ──────────────────────────────────────────────────────────────
    def setup_method(self):
        seed(23)

        # -- DUT parameters --
        self.window = 400
        self.input_width = 16
        self.threshold = self.window * ((1 << self.input_width) // 3)

        # -- Generate raw data samples --
        raw_count = 20_480  # only *real* samples
        raw_stream = [randint(0, (1 << self.input_width) - 1) for _ in range(raw_count)]

        # -- Interleave idle cycles (prob. 0.6 per gap) --
        self.events: list[int | None] = []  # None ⇒ idle tick
        idle_prob = 0.3
        for value in raw_stream:
            while random() < idle_prob:  # 0 – N idles
                self.events.append(None)
            self.events.append(value)

        # -- Reference window accumulator --
        self.expected = deque()
        acc = 0
        cnt = 1
        for ev in self.events:
            acc += ev or 0  # idle ⇒ 0
            cnt += 1
            if cnt == self.window:
                self.expected.append({"mode": 1 if acc > self.threshold else 0})
                acc = cnt = 0

    # ──────────────────────────────────────────────────────────────
    #  Driver : send samples / idle ticks
    # ──────────────────────────────────────────────────────────────
    async def driver_process(self, sim):
        """Feeds ADD_SAMPLE transactions, inserting real idle ticks."""
        for ev in self.events:
            if ev is None:  # idle ⇒ just a clock
                await sim.tick()
            else:  # active sample
                await self.dut.add_sample.call_try(sim, {"data": ev})

    # ──────────────────────────────────────────────────────────────
    #  Checker : verify every RESULT
    # ──────────────────────────────────────────────────────────────
    async def checker_process(self, sim):
        while self.expected:
            resp = await self.dut.result.call(sim)
            print("RESULT", resp)
            assert resp == self.expected.popleft()

    # ──────────────────────────────────────────────────────────────
    #  Top-level simulation
    # ──────────────────────────────────────────────────────────────
    def test_randomised(self):
        self.dut = SimpleTestCircuit(
            VolCounter(
                window=self.window,
                threshold=self.threshold,
                input_width=self.input_width,
            )
        )
        with self.run_simulation(self.dut) as sim:
            sim.add_testbench(self.driver_process)
            sim.add_testbench(self.checker_process)
