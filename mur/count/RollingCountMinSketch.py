from __future__ import annotations
# RollingCountMinSketch – request-flagged transactions (idiomatic “with” form)
from transactron.lib import logging
from amaranth import *
from amaranth.lib.data import StructLayout
from transactron import *
from transactron.core import TModule, Transaction
from transactron.lib import BasicFifo

from mur.count.CountMinSketch import CountMinSketch
log = logging.HardwareLogger("count.rolling_cms")


__all__ = ["RollingCountMinSketch"]


class RollingCountMinSketch(Elaboratable):

    # ------------------------------------------------------------------ #
    #  Constructor                                                       #
    # ------------------------------------------------------------------ #
    def __init__(
        self,
        *,
        depth: int,
        width: int,
        counter_width: int,
        input_data_width: int,
        hash_params: list[tuple[int, int]] | None = None,
    ) -> None:
        if depth < 1:
            raise ValueError("depth must be ≥ 1")

        # Public parameters ---------------------------------------------
        self.depth         = depth
        self.width         = width
        self.counter_width = counter_width
        self.item_width    = input_data_width

        self.set_mode     = Method(i=[("mode", 1)])   # 0 = UPDATE, 1 = QUERY
        self.change_roles = Method()                  # swap active/stand-by

        # Internal sketches (ping-pong) ---------------------------------
        self._cms0 = CountMinSketch(
            depth            = depth,
            width            = width,
            counter_width    = counter_width,
            input_data_width = self.item_width,
            hash_params      = hash_params,
        )
        self._cms1 = CountMinSketch(
            depth            = depth,
            width            = width,
            counter_width    = counter_width,
            input_data_width = self.item_width,
            hash_params      = hash_params,
        )

        self.input  = Method(i=[("data", self.item_width)])  # input data
        # Result FIFO ---------------------------------------------------
        self.output = Method(o=[("count", self.counter_width),("valid", 1)])  # output data
        # Control / status regs ----------------------------------------
        self._active_sel   = Signal(1, init=0)  # 0 → cms0 active, 1 → cms1
        self._mode         = Signal(1, init=0)  # 0 → UPDATE, 1 → QUERY
        
    # ------------------------------------------------------------------ #
    #  Elaborate                                                         #
    # ------------------------------------------------------------------ #
    def elaborate(self, platform):
        m = TModule()
        m.submodules += [self._cms0, self._cms1]
        

        @def_method(m,self.input)
        def _input(data):
            with m.Switch(Cat(self._active_sel, self._mode)):
                with m.Case(0):
                    self._cms0.insert(m, data=data)
                with m.Case(1):
                    self._cms1.insert(m, data=data)
                with m.Case(2):
                    self._cms0.query_req(m, data=data)
                with m.Case(3):
                    self._cms1.query_req(m, data=data)
        
        output_valid = Signal(1)
        output_count = Signal(self.counter_width)
        @def_method(m,self.output)
        def _output():
            res0 = self._cms0.query_resp(m)
            res1 = self._cms1.query_resp(m)
            m.d.comb += [
                output_valid.eq(res0["valid"] | res1["valid"]),
                output_count.eq(Mux(res0["valid"], res0["count"], res1["count"]))
            ]
            return {"count": output_count, "valid": output_valid}
 

        @def_method(m, self.change_roles)
        def _():
            m.d.sync += self._active_sel.eq(~self._active_sel)
            with m.If(self._active_sel == 0):
                self._cms0.clear(m)
            with m.Else():
                self._cms1.clear(m)   

        @def_method(m, self.set_mode)
        def _set_mode(mode):
            m.d.sync += self._mode.eq(mode)

     

        return m
