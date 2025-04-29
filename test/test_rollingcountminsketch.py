from random import randint, random, seed
from collections import deque

from transactron.testing import TestCaseWithSimulator, SimpleTestCircuit

# Adjust the import path if your project structure differs
from mur.count.RollingCountMinSketch import RollingCountMinSketch


class TestRollingCountMinSketch(TestCaseWithSimulator):
    """Randomised functional test‑bench for ``RollingCountMinSketch``.

    Mirrored after *test_countminsketch.py* and *test_counthashtab.py*:

    * Generates a mixed stream of ``insert``, ``query``, ``change_roles`` and
      ``set_mode`` operations with random idle cycles and back‑pressure.
    * Maintains a Python reference model of the double‑buffered sketches.
    * Checks that every ``query_resp`` matches the reference model.
    """

    # ------------------------------------------------------------------
    #  Stimulus generation
    # ------------------------------------------------------------------
    def setup_method(self):
        seed(42)

        # ── Design parameters ────────────────────────────────────────
        self.depth = 4
        self.width = 64
        self.counter_width = 64
        self.data_width = 32

        # ── Operation trace ──────────────────────────────────────────
        self.operation_count = 10_000
        self.ops: list[tuple[str, int | None]] = []  # (op, arg)
        self.expected = deque()                      # expected query responses

        # ── Reference model -------------------------------------------------
        P = 4_294_967_291  # 2**32 − 5
        self.hash_params = [(row + 1, 0) for row in range(self.depth)]

        def h(row: int, x: int) -> int:
            a, b = self.hash_params[row]
            return ((a * x + b) % P) % self.width

        # Two sketches: 0 and 1 (ping‑pong)
        self.model = [
            [[0] * self.width for _ in range(self.depth)],
            [[0] * self.width for _ in range(self.depth)],
        ]
        self.active = 0  # 0 → sketch0 active, 1 → sketch1 active
        self.mode = 0    # 0 → UPDATE mode, 1 → QUERY mode

        for _ in range(self.operation_count):
            if self.mode == 0:  # UPDATE mode --------------------------------
                r = random()
                if r < 0.7:
                    # INSERT -------------------------------------------------
                    data = randint(0, (1 << self.data_width) - 1)
                    self.ops.append(("insert", data))
                    for row in range(self.depth):
                        self.model[self.active][row][h(row, data)] += 1
                elif r < 0.85:
                    # CHANGE ROLES ------------------------------------------
                    self.ops.append(("change_roles", None))
                    # Swap active / stand‑by
                    self.active ^= 1
                    # Clear new stand‑by (old active) immediately in model
                    standby = 1 - self.active
                    for row in range(self.depth):
                        for idx in range(self.width):
                            self.model[standby][row][idx] = 0
                else:
                    # SWITCH TO QUERY MODE ----------------------------------
                    self.ops.append(("set_mode", 1))
                    self.mode = 1
            else:  # QUERY mode ---------------------------------------------
                if random() < 0.75:
                    data = randint(0, (1 << self.data_width) - 1)
                    self.ops.append(("query", data))
                    est = min(
                        self.model[self.active][row][h(row, data)]
                        for row in range(self.depth)
                    )
                    self.expected.append({"count": est})
                else:
                    # BACK TO UPDATE MODE -----------------------------------
                    self.ops.append(("set_mode", 0))
                    self.mode = 0

    # ------------------------------------------------------------------
    #  Driver process
    # ------------------------------------------------------------------
    async def driver_process(self, sim):
        """Feeds operations into the DUT with random idle cycles."""
        for op, arg in self.ops:
            # Random idle cycles to shake loose corner‑cases
            while random() >= 0.7:
                await sim.tick()

            if op == "insert":
                print(f"Before insert.call() with data={arg}")
                await self.dut.insert.call(sim, {"data": arg})
                print(f"After insert.call() with data={arg}")
            elif op == "query":
                print(f"Before query_req.call() with data={arg}")
                await self.dut.query_req.call(sim, {"data": arg})
                print(f"After query_req.call() with data={arg}")
            elif op == "change_roles":
                print("Before change_roles.call()")
                await self.dut.change_roles.call(sim, {})
                print("After change_roles.call()")
            elif op == "set_mode":
                print(f"Before set_mode.call() with mode={arg}")
                await self.dut.set_mode.call(sim, {"mode": arg})
                print(f"After set_mode.call() with mode={arg}")
            else:
                raise ValueError(f"Unknown operation {op}")

            # Ensure one cycle before a possible query_resp
            if op == "query":
                await sim.tick()

    # ------------------------------------------------------------------
    #  Checker process
    # ------------------------------------------------------------------
    async def checker_process(self, sim):
        """Checks that DUT responses match the reference model."""
        while self.expected:
            # Random back‑pressure before reading
            while random() >= 0.5:
                await sim.tick()
            print("Before query_resp.call()")
            resp = await self.dut.query_resp.call(sim)
            print(f"After query_resp.call(), received: {resp}")
            assert resp == self.expected.popleft()

    # ------------------------------------------------------------------
    #  Top‑level test
    # ------------------------------------------------------------------
    def test_randomized(self):
        core = RollingCountMinSketch(
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
