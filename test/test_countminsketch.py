from random import randint, random, seed
from collections import deque

from transactron.testing import TestCaseWithSimulator, SimpleTestCircuit

# Adjust the import path according to your project structure
from mur.count.CountMinSketch import CountMinSketch


class TestCountMinSketch(TestCaseWithSimulator):
    """Randomised functional test‑bench for ``CountMinSketch``.

    Follows the structure of *test_aligner.py* and *test_counthashtab.py*:
    * A mixed trace of *insert* / *query* / *clear* operations with random
      back‑pressure and idle cycles.
    * A Python reference model that mirrors the hardware algorithm.
    * Verification that the DUT responses match the model, including after a
      *clear()* sweep.
    """

    # ------------------------------------------------------------------
    #  Test stimulus generation
    # ------------------------------------------------------------------
    def setup_method(self):
        seed(42)

        # ── Design parameters ──────────────────────────────────────────
        self.depth = 4   # number of hash rows
        self.width = 64  # buckets per row
        self.counter_width = 64
        self.data_width = 32

        # ── Simulation stimulus ────────────────────────────────────────
        self.operation_count = 15_000
        self.ops: list[tuple[str, int | None]] = []  # ("insert"|"query"|"clear", data)
        self.expected = deque()                      # expected query responses

        # ── Reference model ---------------------------------------------------
        P = 4_294_967_291  # 2**32 − 5 (largest 32‑bit prime)
        # Simple deterministic hash params identical to hardware defaults
        self.hash_params = [(row_idx + 1, 0) for row_idx in range(self.depth)]

        def h(row: int, x: int) -> int:
            """Software copy of the on‑chip universal hash of *row*."""
            a, b = self.hash_params[row]
            return ((a * x + b) % P) % self.width

        # Per‑row bucket counters
        self.model = [[0] * self.width for _ in range(self.depth)]

        # Build a trace with random clears sprinkled in
        clear_interval = 250  # average spacing between clears
        next_clear_at = randint(clear_interval // 2, clear_interval * 3 // 2)

        for i in range(self.operation_count):
            # Schedule a *clear* roughly every ~clear_interval operations
            if i == next_clear_at:
                self.ops.append(("clear", None))
                # Reset the model
                for row in self.model:
                    for idx in range(self.width):
                        row[idx] = 0
                # Pick the next clear position
                next_clear_at += randint(clear_interval // 2, clear_interval * 3 // 2)
                continue

            if random() < 0.65:
                data = randint(0, (1 << self.data_width) - 1)
                self.ops.append(("insert", data))
                for row_idx in range(self.depth):
                    self.model[row_idx][h(row_idx, data)] += 1
            else:
                data = randint(0, (1 << self.data_width) - 1)
                self.ops.append(("query", data))
                # The Count‑Min estimate is the *minimum* across rows
                min_estimate = min(self.model[row_idx][h(row_idx, data)] for row_idx in range(self.depth))
                self.expected.append({"count": min_estimate})

    # ------------------------------------------------------------------
    #  Test‑bench processes
    # ------------------------------------------------------------------
    async def driver_process(self, sim):
        """Feeds *insert*, *query_req*, and *clear* transactions into the DUT."""
        for op, data in self.ops:
            # Random idle cycles to shake loose FSM corner‑cases
            while random() >= 0.7:
                await sim.tick()

            if op == "insert":
                await self.dut.insert.call(sim, {"data": data})

            elif op == "query":
                await self.dut.query_req.call(sim, {"data": data})
                 
            else:  # op == "clear"
                await self.dut.clear.call(sim, {})
              
            await sim.tick()
                
            

    async def checker_process(self, sim):
        """Pulls *query_resp* and compares with the reference model."""
        while self.expected:
            # Random back‑pressure so *query_resp* may wait in the FIFO
            while random() >= 0.5:
                await sim.tick()
            resp = await self.dut.query_resp.call(sim)
            assert resp == self.expected.popleft()
            if resp != {"count": 0}:
                print(f"query_resp: {resp['count']}")


    # ------------------------------------------------------------------
    #  Top‑level test
    # ------------------------------------------------------------------
    def test_randomized(self):
        core = CountMinSketch(
            depth            = self.depth,
            width            = self.width,
            counter_width    = self.counter_width,
            input_data_width = self.data_width,
            hash_params      = self.hash_params,
        )
        self.dut = SimpleTestCircuit(core)

        with self.run_simulation(self.dut) as sim:
            sim.add_testbench(self.driver_process)
            sim.add_testbench(self.checker_process)
