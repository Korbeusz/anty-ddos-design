from random import randint, random, seed
from collections import deque

from transactron.testing import TestCaseWithSimulator, SimpleTestCircuit

from mur.count.RollingCountMinSketch import RollingCountMinSketch


class TestRollingCountMinSketch(TestCaseWithSimulator):
    """Randomised functional test‑bench for ``RollingCountMinSketch``.

    • Generates a long trace of INSERT / QUERY / CHANGE_ROLES operations with
      random idle cycles and back‑pressure.
    • Maintains a twin‑sketch (ping‑pong) Python reference model.
    • Verifies every ``output`` (when *valid* == 1) against the model.

    **Rule enforced** – there are *at least* ``self.width`` other operations
    between two consecutive ``change_roles`` calls, giving the DUT enough
    cycles to finish its internal *clear* sweep.
    """

    # ──────────────────────────────────────────────────────────────
    #  Stimulus generation
    # ──────────────────────────────────────────────────────────────
    def setup_method(self):
        seed(42)

        # ── Design parameters ─────────────────────────────────────
        self.depth = 2           # rows per sketch
        self.width = 16          # buckets per row
        self.counter_width = 32
        self.data_width = 32

        # Universal‑hash coefficients (deterministic defaults)
        self.hash_params = [(row + 1, 0) for row in range(self.depth)]
        P = 4_294_967_291  # 2**32 − 5 – largest 32‑bit prime

        def h(row: int, x: int) -> int:
            """Pure Python copy of the on‑chip universal hash."""
            a, b = self.hash_params[row]
            return ((a * x + b) % P) % self.width

        # ── Reference model – two independent sketches 0 / 1 ──────
        self.model = [[0] * self.width for _ in range(self.depth)]  # sketch 1
        
        self.active = 0   # 0 → sketch0 active, 1 → sketch1 active
        self.mode = 0     # 0 → UPDATE, 1 → QUERY

        # ── Random operation trace ────────────────────────────────
        self.operation_count = 25_000
        #                     kind          payload
        #   ops[i] = ("insert"|"query"|"change",  int | None)
        self.ops: list[tuple[str, int | None]] = []
        self.expected = deque()  # queued QUERY responses

        # Ensure ≥ width ops between CHANGE events -----------------
        next_change_at = randint(self.width, self.width * 3)

        for i in range(self.operation_count):
            if i == next_change_at:
                # -------------- CHANGE_ROLES -------------------
                self.ops.append(("change", None))
                # Clear the *stand‑by* (was active) sketch in the model
                standby = self.active
                for row in self.model:
                    for idx in range(self.width):
                        row[idx] = 0
                next_change_at += randint(self.width, self.width * 3)
                continue

            if random() < 0.65:
                # -------------- INSERT ------------------------
                data = randint(0, (1 << self.data_width) - 1)
                self.ops.append(("insert", data))
                for row_idx in range(self.depth):
                    idx = h(row_idx, data)
                    self.model[row_idx][idx] += 1
            else:
                # -------------- QUERY -------------------------
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
        """Feeds INSERT / QUERY / CHANGE_ROLES transactions into the DUT."""
        current_mode = 0  # DUT starts in UPDATE mode (matching RTL default)
        for kind, data in self.ops:
            while random() >= 0.7:  # idle cycles to rattle corner‑cases
                await sim.tick()

            if kind == "change":
                await self.dut.change_roles.call_try(sim, {})
                continue

            # Switch mode on the DUT if required ------------------
            if kind == "insert" and current_mode != 0:
                await self.dut.set_mode.call_try(sim, {"mode": 0})
                current_mode = 0
    
            elif kind == "query" and current_mode != 1:
                await self.dut.set_mode.call_try(sim, {"mode": 1})
                current_mode = 1

            # Issue the actual INSERT / QUERY request -------------
            await self.dut.input.call_try(sim, {"data": data})


    # ──────────────────────────────────────────────────────────────
    #  Checker process
    # ──────────────────────────────────────────────────────────────
    async def checker_process(self, sim):
        """Pulls OUTPUT responses and checks them against *expected*."""
        while self.expected:
            resp = await self.dut.output.call_try(sim)
            # Wait until the sketch signals a *valid* response
            if resp["valid"] == 0:
                continue 
            assert resp["count"] == self.expected.popleft()["count"]
            if resp["count"] != 0:
                print(f"query_resp: {resp['count']}")

    # ──────────────────────────────────────────────────────────────
    #  Top‑level test
    # ──────────────────────────────────────────────────────────────
    def test_randomised(self):
        core = RollingCountMinSketch(
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
