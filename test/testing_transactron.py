# conditional_readiness.py
from amaranth import *
from transactron import *
from transactron.testing import (
    TestCaseWithSimulator,
    SimpleTestCircuit,
    TestbenchContext,
)


class ConditionalReadinessCircuit(Elaboratable):
    """
    Conditionally calls one of two producer methods; the *false* branch
    points at a method that is **never** ready.  A third method,
    **get_result()**, is always ready and lets the test-bench read back
    the last committed result.
    """

    def __init__(self):
        self.cond = Signal(1, init=1)  # choose the branch
        self._result_q = Signal(8, init=0)

        # ── Public Transactron API ────────────────────────────────────
        self.ready_method = Method(o=[("data", 8)])
        self.not_ready_method = Method(o=[("data", 8)])
        self.get_result = Method(o=[("data", 8)])  # <── new!
        self.change_cond_method = Method()

    # ------------------------------------------------------------------
    #  Elaborate
    # ------------------------------------------------------------------
    def elaborate(self, platform):
        m = TModule()

        # -------- producer methods ------------------------------------
        @def_method(m, self.ready_method, ready=C(1))
        def _always_ok():
            return {"data": 42}

        @def_method(m, self.not_ready_method, ready=C(1))
        def _never_ok():
            return {"data": 99}

        @def_method(m, self.change_cond_method)
        def _change_cond():
            m.d.sync += self.cond.eq(~self.cond)

        # -------- consumer (transaction) ------------------------------
        #    with Transaction(name="PickOne").body(m, request=self.cond):
        #        with m.If(self.cond):
        #            m.d.sync += self._result_q.eq(self.ready_method(m)["data"])
        #       with m.Else():
        #            m.d.sync += self._result_q.eq(self.not_ready_method(m)["data"])
        #
        # -------- this works different then above ------------------------------
        with Transaction(name="PickOne2").body(m, request=self.cond):
            with m.If(self.cond):
                d = self.ready_method(m)["data"]
            with m.Else():
                d = self.not_ready_method(m)["data"]
            m.d.sync += self._result_q.eq(d)

        # -------- read-back path --------------------------------------
        @def_method(m, self.get_result, ready=C(1))
        def _():
            return {"data": self._result_q}

        return m


# ======================================================================
#  Test-bench
# ======================================================================
class TestConditionalReadiness(TestCaseWithSimulator):
    """Mirrors the driver / checker split used in the project’s other tests."""

    # ---------- checker -------------------------------------------------
    async def checker(self, sim: TestbenchContext):
        resp = 0
        await self.dut.change_cond_method.call(sim)
        # inspect the cond signal using sim get_signal_value
        print(f"cond = {self.dut.cond}")
        print(f"resp = {resp}")
        #   sim.tick()

        await self.dut.change_cond_method.call(sim)
        print(f"resp = {resp}")
        #  sim.tick()

        await self.dut.change_cond_method.call(sim)
        print(f"resp = {resp}")

    # sim.tick()

    # ---------- top-level test -----------------------------------------
    def test_conditional_readiness(self):
        core = ConditionalReadinessCircuit()
        self.dut = SimpleTestCircuit(core)

        with self.run_simulation(self.dut) as sim:
            sim.add_testbench(self.checker)
