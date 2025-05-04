# test_counthashtab.py  (drop-in replacement)

from random import randint, random, seed
from collections import deque

from transactron.testing import TestCaseWithSimulator, SimpleTestCircuit
from mur.count.CountHashTab import CountHashTab


class TestCountHashTab(TestCaseWithSimulator):
    """
    Randomised functional test-bench for ``CountHashTab``

    • Generates a long trace of INSERT / QUERY / CLEAR operations with
      random idle cycles and back-pressure.
    • Keeps a very small Python reference model of the bucket array.
    • Compares every *query_resp* against the model, including across
      clear-sweeps.
    """

    # ------------------------------------------------------------------
    #  Stimulus generation
    # ------------------------------------------------------------------
    def setup_method(self):

        seed(42)

        # ── DUT parameters ────────────────────────────────────────────
        self.size          = 18     # number of hash buckets
        self.counter_width = 32
        self.data_width    = 32

        # ── Random operation trace ------------------------------------
        self.operation_count = 15_000
        #               kind          payload
        #   ops[i]  = ("insert"|"query"|"clear",  data:int | None)
        self.ops: list[tuple[str, int | None]] = []

        # Expected QUERY responses in arrival order
        self.expected = deque()

        # ── Reference model -------------------------------------------
        P      = 4_294_967_291                     # 2**32 − 5
        self.a = 1                                 # hash coefficients
        self.b = 0
        self.model = [0] * self.size               # bucket counters

        def h(x: int) -> int:                      # software hash
            return ((self.a * x + self.b) % P) % self.size

        # Sprinkle CLEAR roughly every ~300 ops
        clear_interval = 300
        next_clear_at  = randint(clear_interval // 2,
                                 clear_interval * 3 // 2)

        for i in range(self.operation_count):
            if i == next_clear_at:
                # ----------- CLEAR ------------------------------------
                self.ops.append(("clear", None))
                for idx in range(self.size):       # wipe reference
                    self.model[idx] = 0
                next_clear_at += randint(clear_interval // 2,
                                          clear_interval * 3 // 2)
                continue

            if random() < 0.65:
                # ----------- INSERT -----------------------------------
                data = randint(0, (1 << self.data_width) - 1)
                self.ops.append(("insert", data))
                self.model[h(data)] += 1
            else:
                # ----------- QUERY ------------------------------------
                data = randint(0, (1 << self.data_width) - 1)
                self.ops.append(("query", data))
                self.expected.append({"count": self.model[h(data)]})


    # ------------------------------------------------------------------
    #  Test-bench processes
    # ------------------------------------------------------------------
    async def driver_process(self, sim):
        """
        Feeds INSERT / QUERY_REQ / CLEAR transactions into the DUT with
        random idle cycles to rattle corner-cases.
        """

        for kind, data in self.ops:
            while random() >= 0.7:          # idle cycle
                await sim.tick()

            if kind == "insert":
                await self.dut.insert.call_try(sim, {"data": data})
            elif kind == "query":
                await self.dut.query_req.call_try(sim, {"data": data})
            else:                           # kind == "clear"
                await self.dut.clear.call_try(sim, {})
                for idx in range(self.size):
                    await sim.tick()         # wait for clear to finish



    async def checker_process(self, sim):
        """
        Pulls QUERY_RESP results and checks them against *expected*,
        inserting random back-pressure so responses queue up.
        """  
        while self.expected:
            resp = await self.dut.query_resp.call_try(sim)
            if resp["valid"] == 0:
                continue
            assert resp["count"] == self.expected.popleft()["count"]
            if resp["count"] != {"count": 0}:
                print(f"query_resp: {resp['count']}")

    # ------------------------------------------------------------------
    #  Top-level test
    # ------------------------------------------------------------------
    def test_randomised(self):

        core = CountHashTab(
            size              = self.size,
            counter_width     = self.counter_width,
            input_data_width  = self.data_width,
            hash_a            = self.a,
            hash_b            = self.b,
        )
        self.dut = SimpleTestCircuit(core)

        with self.run_simulation(self.dut) as sim:
            sim.add_testbench(self.driver_process)
            sim.add_testbench(self.checker_process)

