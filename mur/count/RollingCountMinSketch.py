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
    """Double-buffered Count-Min Sketch with unified ingress FIFOs and
    request-flagged transactions (no explicit req/resp ports)."""

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
        self.concat_width  = 2 * input_data_width   # fifo1 bits = LSBs

        self.set_mode     = Method(i=[("mode", 1)])   # 0 = UPDATE, 1 = QUERY
        self.change_roles = Method()                  # swap active/stand-by

        # Internal sketches (ping-pong) ---------------------------------
        self._cms0 = CountMinSketch(
            depth            = depth,
            width            = width,
            counter_width    = counter_width,
            input_data_width = self.concat_width,
            hash_params      = hash_params,
        )
        self._cms1 = CountMinSketch(
            depth            = depth,
            width            = width,
            counter_width    = counter_width,
            input_data_width = self.concat_width,
            hash_params      = hash_params,
        )

        # Ingress staging FIFOs ----------------------------------------
        word_layout = StructLayout({"data": self.item_width})
        self._fifo1 = BasicFifo(word_layout, 4)
        self._fifo2 = BasicFifo(word_layout, 4)
        
        self.fifo1 = self._fifo1.write
        self.fifo2 = self._fifo2.write
        # Result FIFO ---------------------------------------------------
        res_layout  = StructLayout({"count": self.counter_width})
        self._res_fifo = BasicFifo(res_layout, 32)
        self.read_count = self._res_fifo.read
        # Control / status regs ----------------------------------------
        self._active_sel   = Signal(1, init=0)  # 0 → cms0 active, 1 → cms1
        self._mode         = Signal(1, init=0)  # 0 → UPDATE, 1 → QUERY
        self._resp_pending = Signal(5, init=0)           # waiting for query_resp
        self.old_mode      = Signal(1)  # previous mode (for change_roles)
        self.old_active    = Signal(1)  # previous active sketch (for change_roles)
        # Background-clear bookkeeping
        self._clr_pending  = Signal()
        self._clr_busy     = Signal()
        self._clr_timer    = Signal(range(self.width + 1))

    # ------------------------------------------------------------------ #
    #  Helper: pop+concatenate ingress pair                               #
    # ------------------------------------------------------------------ #
    def _pop_pair(self, m: TModule) -> Value:
        lo = self._fifo1.read(m)["data"]
        hi = self._fifo2.read(m)["data"]
        return Cat(lo, hi)

    # ------------------------------------------------------------------ #
    #  Elaborate                                                         #
    # ------------------------------------------------------------------ #
    def elaborate(self, platform):
        m = TModule()
        m.submodules += [
            self._cms0, self._cms1,
            self._fifo1, self._fifo2,
            self._res_fifo,
        ]
        

        # -------------------------------------------------------------- #
        #  UPDATE-mode inserts (two tiny transactions)                   #
        # -------------------------------------------------------------- #
        with Transaction(name="Upd_cms0").body(
            m, request=(~self._mode) & (self._active_sel == 0)
        ):
            self._cms0.insert(m, data=self._pop_pair(m))
            log.debug(m, True, "cms0 insert")

        with Transaction(name="Upd_cms1").body(
            m, request=(~self._mode) & (self._active_sel == 1)
        ):
            self._cms1.insert(m, data=self._pop_pair(m))
            log.debug(m, True, "cms1 insert")

        # -------------------------------------------------------------- #
        #  QUERY-mode: issue query_req                                   #
        # -------------------------------------------------------------- #
        with Transaction(name="QryReq_cms0").body(
            m,
            request=self._mode & (self._active_sel == 0),
        ):
            self._cms0.query_req(m, data=self._pop_pair(m))
            m.d.sync += self._resp_pending.eq(self._resp_pending + 1)
            log.debug(m, True, "cms0 query_req")

        with Transaction(name="QryReq_cms1").body(
            m,
            request=self._mode & (self._active_sel == 1) ,
        ):
            self._cms1.query_req(m, data=self._pop_pair(m))
            m.d.sync += self._resp_pending.eq(self._resp_pending + 1)
            log.debug(m, True, "cms1 query_req")

        # -------------------------------------------------------------- #
        #  QUERY responses → result FIFO                                 #
        # -------------------------------------------------------------- #
        with Transaction(name="Resp_cms0").body(
            m,
      
        ):
            resp = self._cms0.query_resp(m)
            self._res_fifo.write(m, count=resp["count"])
            m.d.sync += self._resp_pending.eq(self._resp_pending - 1)
            log.debug(m, True, "cms0 query_resp %s", resp["count"])

        with Transaction(name="Resp_cms1").body(
            m,
           
        ):
            resp = self._cms1.query_resp(m)
            self._res_fifo.write(m, count=resp["count"])
            m.d.sync += self._resp_pending.eq(self._resp_pending - 1)
            log.debug(m, True, "cms1 query_resp %s", resp["count"])

        # -------------------------------------------------------------- #
        #  change_roles (allowed only in UPDATE)                         #
        # -------------------------------------------------------------- #
        @def_method(
            m,
            self.change_roles,
            ready=(~self._mode) & ~self._clr_busy & ~self._clr_pending , 
        )
        def _():
            m.d.sync += [
                self._active_sel.eq(~self._active_sel),
                self._clr_pending.eq(1),   # clear the *new* standby
            ]
            log.debug(m, True, "change_roles: %s", self._active_sel)
    
        # -------------------------------------------------------------- #
        #  set_mode                                                      #
        # -------------------------------------------------------------- #
        @def_method(m, self.set_mode, ready=(~self._clr_busy & ~self._clr_pending))
        def _(mode):
            m.d.sync += self._mode.eq(mode)
            log.debug(m, True, "set_mode: %s", mode)

        # -------------------------------------------------------------- #
        #  Background clear (two transactions, one per standby sketch)   #
        # -------------------------------------------------------------- #
        with Transaction(name="Clr_cms0").body(
            m,
            request=self._clr_pending & ~self._clr_busy & (self._active_sel == 1),
        ):
            self._cms0.clear(m)
            m.d.sync += [
                self._clr_busy.eq(1),
                self._clr_pending.eq(0),
                self._clr_timer.eq(0),
            ]
            log.debug(m, True, "cms0 clear")

        with Transaction(name="Clr_cms1").body(
            m,
            request=self._clr_pending & ~self._clr_busy & (self._active_sel == 0),
        ):
            self._cms1.clear(m)
            m.d.sync += [
                self._clr_busy.eq(1),
                self._clr_pending.eq(0),
                self._clr_timer.eq(0),
            ]
            log.debug(m, True, "cms1 clear")

        # Clear latency timer ------------------------------------------
        with m.If(self._clr_busy):
            m.d.sync += self._clr_timer.eq(self._clr_timer + 1)
            with m.If(self._clr_timer == self.width - 1):
                m.d.sync += self._clr_busy.eq(0)
                log.debug(m, True, "cms clear done")

        return m
