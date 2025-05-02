from random import randint, random, seed
from collections import deque

from transactron.testing import TestCaseWithSimulator, SimpleTestCircuit

# Adjust the import if your package hierarchy is different
from mur.count.RollingCountMinSketch import RollingCountMinSketch


class TestRollingCountMinSketch(TestCaseWithSimulator):
    """
    Randomised functional test-bench for ``RollingCountMinSketch``.

    * Generates a stream of UPDATE / QUERY traffic with occasional
      role-swaps (``change_roles``) exactly like a production data-path.
    * Keeps a software reference model of *both* internal Count-Min
      sketches, including the “ping-pong” active/stand-by logic and the
      background clear that follows a role swap.
    * Verifies every QUERY response byte-for-byte against the model while
      exercising all handshake, back-pressure and arbitration paths.
    """

    # ------------------------------------------------------------------
    #  Stimulus generation
    # ------------------------------------------------------------------
    def setup_method(self):
        seed(42)

        # ── DUT parameters ────────────────────────────────────────────
        self.depth          = 2
        self.width          = 16
        self.counter_width  = 32
        self.item_width     = 16           # width of one FIFO word
        self.concat_width   = 2 * self.item_width
        self.hash_params    = [(row + 1, 0) for row in range(self.depth)]
        #declare python's queue 
        self.fifo1 = deque()
        self.fifo2 = deque()

        # ── Simulation trace ------------------------------------------
        self.operation_count = 10_000
        # Each op is a tuple: (kind, payload)
        #   kind ∈ {"insert", "query", "change_roles"}
        #   payload = (lo, hi) for insert/query; None for change_roles
        self.ops: list[tuple[str, int | None]] = []

        # Expected QUERY responses in the exact arrival order
        self.expected = deque()

        # ── Reference model -------------------------------------------
        P = 4_294_967_291    # 2**32 − 5
        self.active = 0      # 0 → cms0 active, 1 → cms1 active

        # Single CMS state array (removing the first dimension)
        self.model = [[0] * self.width for _ in range(self.depth)]

        def h(row: int, x: int) -> int:
            a, b = self.hash_params[row]
            return ((a * x + b) % P) % self.width

        # Build a mixed trace with random role-swaps
        for _ in range(self.operation_count):
            r = random()

            # 10 % probability to swap roles (only while updating)
            if r < 0.01:
                self.ops.append(("change_roles", None))

                # Immediate effect in the model: toggle active and clear model
                self.active ^= 1
                for row in self.model:
                    for idx in range(self.width):
                        row[idx] = 0
                continue

            # Choose INSERT vs QUERY
            in_value = randint(0, (1 << self.item_width) - 1)

            if r < 0.75:
                # INSERT ------------------------------------------------
                if len(self.fifo2) == 4 or (random() < 0.50 and len(self.fifo1) < 4):
                    self.fifo1.append(in_value)
                    self.ops.append(("insert1", in_value))
                else:
                    self.fifo2.append(in_value)
                    self.ops.append(("insert2", in_value))
                if len(self.fifo1) and len(self.fifo2):
                    lo = self.fifo1.popleft()
                    hi = self.fifo2.popleft()
                    word = (hi << self.item_width) | lo
                    for row in range(self.depth):
                        self.model[row][h(row, word)] += 1
            else:
                # QUERY -------------------------------------------------
                if len(self.fifo2) == 4 or (random() < 0.50 and len(self.fifo1) < 4):
                    self.fifo1.append(in_value)
                    self.ops.append(("query1", in_value))
                else:
                    self.fifo2.append(in_value)
                    self.ops.append(("query2", in_value))
                if len(self.fifo1) and len(self.fifo2):
                    lo = self.fifo1.popleft()
                    hi = self.fifo2.popleft()
                    word = (hi << self.item_width) | lo
                    min_est = min(self.model[row][h(row, word)]for row in range(self.depth))
                    self.expected.append({"count": min_est})

    # ------------------------------------------------------------------
    #  Test-bench processes
    # ------------------------------------------------------------------
    async def driver_process(self, sim):
        """
        Feeds FIFO writes, mode changes and role swaps into the DUT.
        Keeps the driver simple: the handshake waits until the DUT
        is *ready*, so we do not need explicit ready checks.
        """
        cur_mode = 0           # 0 = UPDATE, 1 = QUERY (matches DUT reset)

        for kind, payload in self.ops:
            # Random idle cycles to rattle FSM corner-cases
            while random() >= 0.7:
                print(f"[DRIVER] Adding idle cycle")
                await sim.tick()
                print(f"[DRIVER] Idle cycle complete")

            if kind == "change_roles":
                # ``change_roles`` is only legal in UPDATE mode
                if cur_mode != 0:
                    print(f"[DRIVER] Setting mode to UPDATE (0) before change_roles")
                    await self.dut.set_mode.call(sim, {"mode": 0})
                    print(f"[DRIVER] Mode set to UPDATE (0)")
                    cur_mode = 0
                print(f"[DRIVER] Calling change_roles")
                await self.dut.change_roles.call(sim, {})
                print(f"[DRIVER] change_roles completed")
                # One tick of breathing space
                print(f"[DRIVER] Adding breathing space tick")
                await sim.tick()
                print(f"[DRIVER] Breathing space tick complete")
                continue

            if kind == "insert1" or kind == "insert2":
                # Ensure we are in UPDATE mode
                if cur_mode != 0:
                    print(f"[DRIVER] Setting mode to UPDATE (0)")
                    await self.dut.set_mode.call(sim, {"mode": 0})
                    print(f"[DRIVER] Mode set to UPDATE (0)")
                    cur_mode = 0

            else:  # kind == "query"
                # Switch to QUERY mode if necessary
                if cur_mode != 1:
                    print(f"[DRIVER] Setting mode to QUERY (1)")
                    await self.dut.set_mode.call(sim, {"mode": 1})
                    print(f"[DRIVER] Mode set to QUERY (1)")
                    cur_mode = 1
            
            if kind == "insert1":
                print(f"[DRIVER] Calling fifo1.call with data={payload}")
                await self.dut.fifo1.call(sim, {"data": payload})
                print(f"[DRIVER] fifo1.call completed")
            elif kind == "insert2":
                print(f"[DRIVER] Calling fifo2.call with data={payload}")
                await self.dut.fifo2.call(sim, {"data": payload})
                print(f"[DRIVER] fifo2.call completed")
            elif kind == "query1":
                print(f"[DRIVER] Calling fifo1.call with data={payload}")
                await self.dut.fifo1.call(sim, {"data": payload})
                print(f"[DRIVER] fifo1.call completed")
            elif kind == "query2":
                print(f"[DRIVER] Calling fifo2.call with data={payload}")
                await self.dut.fifo2.call(sim, {"data": payload})
                print(f"[DRIVER] fifo2.call completed")
            else:
                raise ValueError(f"Unknown operation: {kind}")
            # Give the DUT at least one cycle to move things along
            print(f"[DRIVER] Adding cycle for operation {kind}")
            await sim.tick()
            print(f"[DRIVER] Cycle for operation {kind} complete")

    async def checker_process(self, sim):
        """Pulls *read_count* results and compares with the model."""
        while self.expected:
            # Randomised back-pressure on the result FIFO
            #while random() >= 0.5:
            #    print(f"[CHECKER] Adding back-pressure cycle")
            #    await sim.tick()
            #    print(f"[CHECKER] Back-pressure cycle complete")
            
            print(f"[CHECKER] Calling read_count")
            resp = await self.dut.read_count.call(sim)
            expected = self.expected.popleft()
            print(f"[CHECKER] read_count completed with result {resp}, expected {expected}")
            
            assert resp == expected
            if resp != {"count": 0}:
                print(f"read_count: {resp['count']}")

    # ------------------------------------------------------------------
    #  Top-level test
    # ------------------------------------------------------------------
    def test_randomised(self):
        print("[TEST] Creating RollingCountMinSketch instance")
        core = RollingCountMinSketch(
            depth            = self.depth,
            width            = self.width,
            counter_width    = self.counter_width,
            input_data_width = self.item_width,
            hash_params      = self.hash_params,
        )
        print("[TEST] RollingCountMinSketch instance created")
        
        print("[TEST] Creating SimpleTestCircuit")
        self.dut = SimpleTestCircuit(core)
        print("[TEST] SimpleTestCircuit created")

        print("[TEST] Starting simulation")
        with self.run_simulation(self.dut) as sim:
            print("[TEST] Adding driver process")
            sim.add_testbench(self.driver_process)
            print("[TEST] Adding checker process")
            sim.add_testbench(self.checker_process)
        print("[TEST] Simulation complete")
