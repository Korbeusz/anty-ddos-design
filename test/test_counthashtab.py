from random import randint, random, seed
from collections import deque

from transactron.testing import TestCaseWithSimulator, SimpleTestCircuit

# Adjust the import path according to your project structure
from mur.count.CountHashTab import CountHashTab


class TestCountHashTab(TestCaseWithSimulator):
    """Randomized functional test‑bench for ``CountHashTab``.

    It follows the same structure as *test_aligner.py* and verifies that the
    hardware counter table behaves like a Python reference model under a stream
    of random *insert* and *query* operations.
    """

    def setup_method(self):
        seed(42)

        # ── Design parameters ──────────────────────────────────────────
        self.size = 64  # number of hash buckets
        self.counter_width = 64
        self.data_width = 32

        # ── Simulation stimulus ────────────────────────────────────────
        self.operation_count = 10_000
        self.ops: list[tuple[str, int]] = []  # ("insert"|"query", data)
        self.expected = deque()               # expected query responses

        # ── Reference model ----------------------------------------------------
        P = 4_294_967_291  # 2**32 − 5 (largest 32‑bit prime)
        self.a = 1
        self.b = 0
        self.model = [0] * self.size  # bucket counters

        def h(idx_input: int) -> int:
            """Software copy of the on‑chip universal hash."""
            return ((self.a * idx_input + self.b) % P) % self.size

        # Generate a mixed trace of inserts and queries
        for _ in range(self.operation_count):
            if random() < 0.65:
                data = randint(0, (1 << self.data_width) - 1)
                self.ops.append(("insert", data))
                self.model[h(data)] += 1
            else:
                data = randint(0, (1 << self.data_width) - 1)
                self.ops.append(("query", data))
                self.expected.append({"count": self.model[h(data)]})

    # ------------------------------------------------------------------
    #  Test‑bench processes
    # ------------------------------------------------------------------
    async def driver_process(self, sim):
        """Feeds *insert* / *query_req* transactions into the DUT."""
        for op, data in self.ops:
            # Random idle cycles to shake loose FSM corner‑cases
            while random() >= 0.7:
                await sim.tick()

            if op == "insert":
                await self.dut.insert.call(sim, {"data": data})
            else:  # op == "query"
                await self.dut.query_req.call(sim, {"data": data})
                # Guarantee at least one cycle before the checker reads
                await sim.tick()

    async def checker_process(self, sim):
        """Pulls *query_resp* and compares with the reference model."""
        while self.expected:
            while random() >= 0.4:  # random back‑pressure
                await sim.tick()
            resp = await self.dut.query_resp.call(sim)
            assert resp == self.expected.popleft()
            if resp != {"count": 0}:
                print(f"query_resp: {resp['count']}")

    # ------------------------------------------------------------------
    #  Top‑level test
    # ------------------------------------------------------------------
    def test_randomized(self):
        core = CountHashTab(
            size=self.size,
            counter_width=self.counter_width,
            input_data_width=self.data_width,
            hash_a=self.a,
            hash_b=self.b,
        )
        self.dut = SimpleTestCircuit(core)

        with self.run_simulation(self.dut) as sim:
            sim.add_testbench(self.driver_process)
            sim.add_testbench(self.checker_process)
