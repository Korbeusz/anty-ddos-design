from random import randint, random, seed
from collections import deque

from transactron.testing import TestCaseWithSimulator, SimpleTestCircuit

from mur.count.CountMinSketch import CountMinSketch


class TestCountMinSketch(TestCaseWithSimulator):
    """Randomised functional test‑bench for ``CountMinSketch``.

    Mirrors *test_counthashtab.py* but extends it to multi‑row sketches.
    It drives a long mixed trace of *insert*, *query*, and *clear* operations
    through the DUT while maintaining a minimal Python reference model.
    Every ``query_resp`` is checked against the model, including after global
    clears.
    """

    # ──────────────────────────────────────────────────────────────
    #  Stimulus generation
    # ──────────────────────────────────────────────────────────────
    def setup_method(self):
        seed(42)

        # ── Design parameters ─────────────────────────────────────
        self.depth = 4  # number of hash rows
        self.width = 32  # buckets per row
        self.counter_width = 32
        self.data_width = 32

        # Universal‑hash coefficients (same deterministic defaults as RTL)
        self.hash_params = [(row + 1, 0) for row in range(self.depth)]
        P = 65521

        def h(row: int, x: int) -> int:
            """Software copy of the on‑chip universal hash."""
            a, b = self.hash_params[row]
            return ((a * x + b) % P) % self.width

        # Per‑row bucket counters (reference model)
        self.model = [[0] * self.width for _ in range(self.depth)]

        # ── Random operation trace ────────────────────────────────
        self.operation_count = 20_000
        #                  kind          payload
        #   ops[i] = ("insert"|"query"|"clear",  int | None)
        self.ops: list[tuple[str, int | None]] = []
        self.expected = deque()  # queued QUERY responses

        clear_interval = 300
        next_clear_at = randint(clear_interval // 2, clear_interval * 3 // 2)

        for i in range(self.operation_count):
            if i == next_clear_at:
                # -------------- CLEAR ----------------------------
                self.ops.append(("clear", None))
                for row in self.model:  # wipe the reference model
                    for idx in range(self.width):
                        row[idx] = 0
                next_clear_at += randint(clear_interval // 2, clear_interval * 3 // 2)
                continue

            if random() < 0.65:
                # -------------- INSERT ---------------------------
                data = randint(0, (1 << self.data_width) - 1)
                self.ops.append(("insert", data))
                for row_idx in range(self.depth):
                    self.model[row_idx][h(row_idx, data)] += 1
            else:
                # -------------- QUERY ----------------------------
                data = randint(0, (1 << self.data_width) - 1)
                self.ops.append(("query", data))
                est = min(
                    self.model[row_idx][h(row_idx, data)]
                    for row_idx in range(self.depth)
                )
                self.expected.append({"count": est})

    # ──────────────────────────────────────────────────────────────
    #  Driver process
    # ──────────────────────────────────────────────────────────────
    async def driver_process(self, sim):
        """Feeds INSERT / QUERY_REQ / CLEAR transactions into the DUT."""
        for kind, data in self.ops:
            while random() >= 0.7:  # idle cycles to rattle corner‑cases
                await sim.tick()

            if kind == "insert":
                await self.dut.insert.call_try(sim, {"data": data})

            elif kind == "query":
                await self.dut.query_req.call_try(sim, {"data": data})

            else:  # kind == "clear"
                await self.dut.clear.call_try(sim, {})
                # Allow the DUT time to sweep the memory
                for _ in range(self.width + 10):
                    await sim.tick()

    # ──────────────────────────────────────────────────────────────
    #  Checker process
    # ──────────────────────────────────────────────────────────────
    async def checker_process(self, sim):
        """Pulls QUERY_RESP results and checks them against *expected*."""
        while self.expected:
            resp = await self.dut.query_resp.call_try(sim)
            # If the RTL exposes a *valid* field use it; otherwise assume ready
            if resp["valid"] == 0:
                continue  # back‑pressure the FIFO until a real response
            assert resp["count"] == self.expected.popleft()["count"]
            if resp["count"] != 0:
                print(f"query_resp: {resp['count']}")

    # ──────────────────────────────────────────────────────────────
    #  Top‑level test
    # ──────────────────────────────────────────────────────────────
    def test_randomised(self):
        core = CountMinSketch(
            depth=self.depth,
            width=self.width,
            counter_width=self.counter_width,
            input_data_width=self.data_width,
            hash_params=self.hash_params,
        )
        self.dut = SimpleTestCircuit(core)

        with self.run_simulation(self.dut) as sim:
            sim.add_testbench(self.driver_process)
            sim.add_testbench(self.checker_process)
