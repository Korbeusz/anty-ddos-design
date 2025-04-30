from random import randint, random, seed
from collections import deque

from transactron.testing import TestCaseWithSimulator, SimpleTestCircuit

# Adjust the import path according to your project structure
from mur.count.RollingCountMinSketch import RollingCountMinSketch


class TestRollingCountMinSketch(TestCaseWithSimulator):
    """Randomised functional test‑bench for ``RollingCountMinSketch``.

    The structure mirrors *test_counthashtab.py* and *test_countminsketch.py*:
    * A mixed trace of *insert* / *query* / *change_roles* operations with
      random back‑pressure and idle cycles.
    * A deterministic software model of the two internal Count‑Min Sketches.
    * Verification that **every** ``query_req`` is matched with the correct
      ``query_resp`` *before* we switch the DUT back to *UPDATE* mode, exactly
      as required by the interface contract.
    """

    # ------------------------------------------------------------------
    #  Stimulus generation & reference model
    # ------------------------------------------------------------------
    def setup_method(self):
        seed(42)

        # ── Design parameters ──────────────────────────────────────────
        self.depth = 2
        self.width = 16
        self.counter_width = 64
        self.data_width = 32

        # ------------------------------------------------------------------
        #  DUT instantiation
        # ------------------------------------------------------------------
        core = RollingCountMinSketch(
            depth            = self.depth,
            width            = self.width,
            counter_width    = self.counter_width,
            input_data_width = self.data_width,
            # hash_params omitted → defaults (row_idx+1, 0)
        )
        self.dut = SimpleTestCircuit(core)

        # ------------------------------------------------------------------
        #  Software reference – one CMS per internal sketch
        # ------------------------------------------------------------------
        self._P = 4_294_967_291  # 2**32 − 5
        self.model = [
            [[0] * self.width for _ in range(self.depth)],  # sketch 0
            [[0] * self.width for _ in range(self.depth)],  # sketch 1
        ]

        self.active = 0  # 0 → cms0 active, 1 → cms1 active
        self.mode   = 0  # 0 → UPDATE, 1 → QUERY

        # Helper — universal hash identical to DUT default parameters
        def h(row: int, x: int) -> int:
            a, b = row + 1, 0
            return ((a * x + b) % self._P) % self.width

        self._h = h  # keep a reference for the TB process

        # ------------------------------------------------------------------
        #  Build a mixed trace of operations
        # ------------------------------------------------------------------
        self.operation_count = 10_000
        self.ops: list[tuple[str, int | None]] = []  # (op, data)
        self.expected = deque()                      # expected query counts

        for _ in range(self.operation_count):
            if self.mode == 0:  # UPDATE mode
                r = random()
                if r < 0.7:
                    data = randint(0, (1 << self.data_width) - 1)
                    self.ops.append(("insert", data))
                    for row in range(self.depth):
                        self.model[self.active][row][h(row, data)] += 1
                elif r < 0.85:
                    # change_roles (only legal in UPDATE mode)
                    self.ops.append(("change_roles", None))
                    self.active ^= 1  # swap active sketch
                    standby = 1 ^ self.active
                    for row in range(self.depth):
                        self.model[standby][row] = [0] * self.width  # clear
                else:
                    # Switch to QUERY mode
                    self.ops.append(("set_mode_query", None))
                    self.mode = 1
            else:  # QUERY mode
                r = random()
                if r < 0.8:
                    data = randint(0, (1 << self.data_width) - 1)
                    self.ops.append(("query", data))
                    min_est = min(
                        self.model[self.active][row][h(row, data)]
                        for row in range(self.depth)
                    )
                    self.expected.append(min_est)
                else:
                    self.ops.append(("set_mode_update", None))
                    self.mode = 0

    # ------------------------------------------------------------------
    #  Test‑bench coroutine – combines driver & checker logic so that each
    #  *query_req* is immediately followed by the matching *query_resp*.
    # ------------------------------------------------------------------
    async def tb_process(self, sim):
        h = self._h
        mode = 0  # local copy
        active = 0

        for op, data in self.ops:
            # Random idle cycles to shake loose FSM corner‑cases
            while random() >= 0.75:
                await sim.tick()

            # Ensure we are in the correct DUT mode for the upcoming op
            if op in ("insert", "change_roles") and mode != 0:
                await self.dut.set_mode.call(sim, {"mode": 0})
                mode = 0
            elif op == "query" and mode != 1:
                await self.dut.set_mode.call(sim, {"mode": 1})
                mode = 1

            # Execute the operation
            if op == "insert":
                await self.dut.insert.call(sim, {"data": data})

            elif op == "change_roles":
                await self.dut.change_roles.call(sim, {})
                active ^= 1

            elif op == "query":
                if active == 0:
                    await self.dut.query_req0.call(sim, {"data": data})
                else:
                    await self.dut.query_req1.call(sim, {"data": data})

                # Guarantee at least one cycle before collecting the resp
                await sim.tick()

                if active == 0:
                    resp = await self.dut.query_resp0.call(sim)
                else:
                    resp = await self.dut.query_resp1.call(sim)

                expected = {"count": self.expected.popleft()}
                assert resp == expected
                #if resp count is not 0
                if resp["count"] != 0:
                    print("Response:", resp)
                
            # Mode‑switch helper pseudo‑ops
            elif op == "set_mode_query":
                await self.dut.set_mode.call(sim, {"mode": 1})
                mode = 1
            elif op == "set_mode_update":
                await self.dut.set_mode.call(sim, {"mode": 0})
                mode = 0

            # Extra idle cycles to inject back‑pressure
            if random() < 0.3:
                await sim.tick()

    # ------------------------------------------------------------------
    #  Top‑level test wrapper
    # ------------------------------------------------------------------
    def test_randomized(self):
        with self.run_simulation(self.dut) as sim:
            sim.add_testbench(self.tb_process)
