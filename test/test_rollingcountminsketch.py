from random import randint, random, seed
from collections import deque

from transactron.testing import TestCaseWithSimulator, SimpleTestCircuit

from mur.count.RollingCountMinSketch import RollingCountMinSketch


class TestRollingCountMinSketch(TestCaseWithSimulator):
    """Randomised functional test‑bench for ``RollingCountMinSketch``.

    Extends the approach used in *test_countminsketch.py* but adds
    *mode* switching and *change_roles* rotation.  A light‑weight Python
    reference model keeps three separate sketches whose roles rotate in
    lock‑step with the DUT.  Between two ``change_roles`` calls there
    are **always at least ``self.width`` other operations**, ensuring the
    background CLEAR sweep finishes before the next rotation.
    """

    # ------------------------------------------------------------------
    #  Stimulus generation
    # ------------------------------------------------------------------
    def setup_method(self):
        seed(42)

        # ── Sketch parameters ──────────────────────────────────────────
        self.depth = 4
        self.width = 32
        self.counter_width = 32
        self.data_width = 32
        self.hash_params = [(row + 1, 0) for row in range(self.depth)]
        self.P = 65521

        def h(row: int, x: int) -> int:
            """Software copy of the 32‑bit universal hash used on‑chip."""
            a, b = self.hash_params[row]
            return ((a * x + b) % self.P) % self.width

        # ── Three rolling sketches (reference model) ------------------
        self.model = [[[0] * self.width for _ in range(self.depth)] for _ in range(3)]
        self.head = 0  # index (0‒2) of the current UPDATE sketch
        self.mode = 0  # 0 = UPDATE, 1 = QUERY

        # ── Random operation trace ------------------------------------
        self.operation_count = 25_000
        self.ops: list[tuple[str, int | None]] = []  # (kind, payload)
        self.expected = deque()  # queued QUERY outputs

        last_change_at = -self.width  # distance from previous change_roles

        for i in range(self.operation_count):
            # -------------- Possibly rotate roles --------------------
            if (i - last_change_at) >= self.width and random() < 0.02:
                self._rotate_reference()  # update the model first
                self.ops.append(("change_roles", None))
                last_change_at = i
                continue

            # -------------- Possibly toggle mode ---------------------
            if random() < 0.02:
                self.mode ^= 1  # flip UPDATE/QUERY
                self.ops.append(("set_mode", self.mode))
                continue

            # -------------- INSERT or QUERY depending on mode --------
            data = randint(0, (1 << self.data_width) - 1)
            if self.mode == 0:
                self.ops.append(("insert", data))
                # ------------ UPDATE model --------------------------
                for row in range(self.depth):
                    idx = h(row, data)
                    self.model[self.head][row][idx] += 1
            else:
                self.ops.append(("query", data))
                # ------------ QUERY model ---------------------------
                q_idx = (self.head + 1) % 3
                est = min(
                    self.model[q_idx][row][h(row, data)] for row in range(self.depth)
                )
                self.expected.append({"count": est})

    # ------------------------------------------------------------------
    #  Reference‑model helpers
    # ------------------------------------------------------------------
    def _rotate_reference(self):
        """Mimic the DUT behaviour on ``change_roles``."""
        # Sketch that **was** QUERY gets cleared
        cur_query = (self.head + 1) % 3
        for row in self.model[cur_query]:
            for idx in range(self.width):
                row[idx] = 0
        # Advance roles (UPDATE → QUERY → CLEAR → UPDATE …)
        self.head = (self.head + 2) % 3

    # ------------------------------------------------------------------
    #  Test‑bench driver
    # ------------------------------------------------------------------
    async def driver_process(self, sim):
        """Feeds INSERT / QUERY / SET_MODE / CHANGE_ROLES into the DUT."""
        for kind, data in self.ops:
            while random() >= 0.7:  # random idle cycles
                await sim.tick()

            if kind == "insert" or kind == "query":
                await self.dut.input.call_try(sim, {"data": data})

            elif kind == "set_mode":
                await self.dut.set_mode.call_try(sim, {"mode": data})

            else:  # kind == "change_roles"
                await self.dut.change_roles.call_try(sim, {})
                # No extra wait here — the "width" spacing is handled
                # by the pre‑generated operation trace.

    # ------------------------------------------------------------------
    #  Checker process
    # ------------------------------------------------------------------
    async def checker_process(self, sim):
        """Pulls QUERY responses and validates them against *expected*."""
        while self.expected:
            resp = await self.dut.output.call_try(sim)
            if resp["valid"] == 0:
                continue  # back‑pressure until a real response appears
            assert resp["count"] == self.expected.popleft()["count"]
            if resp["count"] != 0:
                print(f"QUERY: {resp['count']})")

    # ------------------------------------------------------------------
    #  Top‑level test
    # ------------------------------------------------------------------
    def test_randomised(self):
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
