from __future__ import annotations
from transactron.lib import logging
from amaranth import *
from amaranth.utils import ceil_log2
from transactron import Method, def_method, TModule
log = logging.HardwareLogger("count.VolCounter")
__all__ = ["VolCounter"]


class VolCounter(Elaboratable):

    def __init__(
        self,
        *,
        window: int,
        threshold: int,
        input_width: int = 16,
    ) -> None:
        if window < 1:
            raise ValueError("window must be ≥ 1")
        if input_width < 1:
            raise ValueError("input_width must be ≥ 1")

        self.window = window
        self.threshold = threshold
        self.input_width = input_width

        # Calculate accumulator width that can cover the worst‑case sum
        worst_case_bits = input_width + ceil_log2(window)
        self.sum_width = worst_case_bits

        # ── Public Transactron API ────────────────────────────────────
        self.add_sample = Method(i=[("data", input_width)])
        self.result = Method(o=[("mode", 1)])

    # ------------------------------------------------------------------
    #  Elaborate – RTL implementation
    # ------------------------------------------------------------------
    def elaborate(self, platform):
        m = TModule()

        counter = Signal(range(self.window))
        acc = Signal(self.sum_width)
       
        with m.If(counter == self.window - 1):
            m.d.sync += counter.eq(0)
            m.d.sync += acc.eq(0)
        with m.Else():
            m.d.sync += counter.eq(counter + 1)

        @def_method(m, self.add_sample)
        def _add_sample(data):
            with m.If(~(counter == self.window - 1)):
                m.d.sync += acc.eq(acc + data)
            with m.Else():
                m.d.sync += acc.eq(data)
            log.debug(m, True, "acc {:d} + {:d} = {:d}", acc, data, acc + data)
                    

        
        mode = Signal(1)
        @def_method(m, self.result, ready=(counter == self.window - 1))
        def _result():
            m.d.comb += mode.eq(Mux(acc > self.threshold, 1, 0))
            log.debug(m, True, "acc {:d} th: {:d} ", acc, self.threshold)
            return {"mode": mode}

        return m
