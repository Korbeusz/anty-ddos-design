from __future__ import annotations

from amaranth import *
from amaranth.utils import ceil_log2
from transactron import *
from transactron.core import Transaction, TModule
from transactron.lib import BasicFifo
from transactron.utils.transactron_helpers import make_layout, extend_layout
from mur.count.CountMinSketch import CountMinSketch
from amaranth.lib.data import StructLayout

__all__ = ["RollingCountMinSketch"]


class RollingCountMinSketch(Elaboratable):
    """Double‑buffered Count‑Min Sketch with **dual‑FIFO** insert path.

    Two :class:`transactron.lib.BasicFifo` instances gather inserts coming
    from the public *insert_fifo1* / *insert_fifo2* methods.  As soon as
    *both* FIFOs hold data **and** the unit is in *UPDATE* mode, the pair is
    read, concatenated bit‑wise (``Cat(fifo1, fifo2)`` with *fifo1* forming
    the LSBs), and the resulting value is forwarded to the *active* internal
    :class:`~mur.count.CountMinSketch.CountMinSketch`.

    Aside from the modified insert interface, the external API mirrors the
    previous revision:

    * *query_req0/1* & *query_resp0/1* — one‑cycle‑latency query ports that
      address whichever sketch is currently *active*;
    * *change_roles()* — ping‑pongs the active / stand‑by sketches (legal
      only in *UPDATE* mode after the stand‑by sweep has finished);
    * *set_mode(mode)* — «0» → *UPDATE*, «1» → *QUERY*.

    Parameters
    ----------
    depth, width, counter_width, input_data_width  – as before.
    hash_params  – optional list of per‑row universal‑hash coefficients.
    """

    # ------------------------------------------------------------------
    #  Constructor
    # ------------------------------------------------------------------
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
            raise ValueError("depth must be ≥ 1")

        # ── Public parameters ──────────────────────────────────────────
        self.depth         = depth
        self.width         = width
        self.counter_width = counter_width
        self.item_width    = input_data_width
        self.concat_width  = 2 * input_data_width  # value sent to CMS rows

        # ── External Transactron interface ────────────────────────────
        # Dual‑port insert — one FIFO each
        self.insert_fifo1 = Method(i=[("data", self.item_width)])
        self.insert_fifo2 = Method(i=[("data", self.item_width)])

        # Query ports (one per sketch for seamless role swap)
        self.query_req0  = Method(i=[("data", self.concat_width)])
        self.query_resp0 = Method(o=[("count", self.counter_width)])
        self.query_req1  = Method(i=[("data", self.concat_width)])
        self.query_resp1 = Method(o=[("count", self.counter_width)])

        self.change_roles = Method()                # no arguments
        self.set_mode     = Method(i=[("mode", 1)])  # «0» UPDATE, «1» QUERY

        # One‑cycle latency contract
        self.query_resp0.schedule_before(self.query_req0)
        self.query_resp1.schedule_before(self.query_req1)

        # ── Internal Count‑Min Sketches (double‑buffered) ─────────────
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

        # ── Input staging FIFOs ───────────────────────────────────────
        fifo_layout = StructLayout({"data": self.item_width})
        self._fifo1 = BasicFifo(fifo_layout, 4)
        self._fifo2 = BasicFifo(fifo_layout, 4)

        # ── Control / status registers ────────────────────────────────
        self._active_sel = Signal(1, init=0)   # 0 → cms0 active, 1 → cms1
        self._mode       = Signal(1, init=0)   # 0 → UPDATE, 1 → QUERY

        # Background‑clear bookkeeping for the stand‑by sketch
        self._clr_pending = Signal()           # 1 → call *clear()* ASAP
        self._clr_busy    = Signal()
        self._clr_timer   = Signal(range(self.width + 1))

        # One‑cycle latency tracking for each query path
        self._resp_valid0 = Signal()
        self._resp_valid1 = Signal()

    # ------------------------------------------------------------------
    #  Elaborate
    # ------------------------------------------------------------------
    def elaborate(self, platform):
        m = TModule()
        m.submodules += [self._cms0, self._cms1, self._fifo1, self._fifo2]

        # ============================================================
        #  INSERT – feed the FIFOs (allowed only in UPDATE mode)
        # ============================================================
        @def_method(m, self.insert_fifo1, ready=(~self._mode) & self._fifo1.write.ready)
        def _(data):
            self._fifo1.write(m, data=data)

        @def_method(m, self.insert_fifo2, ready=(~self._mode) & self._fifo2.write.ready)
        def _(data):
            self._fifo2.write(m, data=data)

        # ============================================================
        #  MERGE FIFO outputs → active CMS
        # ============================================================
        with Transaction(name="MergeFifoInserts").body(m):
            with m.If((~self._mode) & self._fifo1.read.ready & self._fifo2.read.ready):
                d1 = self._fifo1.read(m)["data"]  # LSBs
                d2 = self._fifo2.read(m)["data"]  # MSBs
                merged = Cat(d1, d2)

                with m.Switch(self._active_sel):
                    with m.Case(0):
                        self._cms0.insert(m, data=merged)
                    with m.Case(1):
                        self._cms1.insert(m, data=merged)

        # ============================================================
        #  QUERY paths (unchanged w.r.t. v1)
        # ============================================================
        @def_method(m, self.query_resp0,
                    ready=self._mode & self._resp_valid0 & (self._active_sel == 0))
        def _():
            ret = self._cms0.query_resp(m)
            m.d.sync += self._resp_valid0.eq(0)
            return {"count": ret["count"]}

        @def_method(m, self.query_req0,
                    ready=self._mode & (self._active_sel == 0)
                          & (~self._resp_valid0 | self.query_resp0.run))
        def _(data):
            self._cms0.query_req(m, data=data)
            m.d.sync += self._resp_valid0.eq(1)

        @def_method(m, self.query_resp1,
                    ready=self._mode & self._resp_valid1 & (self._active_sel == 1))
        def _():
            ret = self._cms1.query_resp(m)
            m.d.sync += self._resp_valid1.eq(0)
            return {"count": ret["count"]}

        @def_method(m, self.query_req1,
                    ready=self._mode & (self._active_sel == 1)
                          & (~self._resp_valid1 | self.query_resp1.run))
        def _(data):
            self._cms1.query_req(m, data=data)
            m.d.sync += self._resp_valid1.eq(1)

        # ============================================================
        #  CHANGE ROLES – ping‑pong (only in UPDATE mode)
        # ============================================================
        @def_method(m, self.change_roles,
                    ready=(~self._mode) & ~self._clr_busy & ~self._clr_pending)
        def _():
            m.d.sync += [
                self._active_sel.eq(~self._active_sel),
                self._clr_pending.eq(1),  # clear the *new* stand‑by
            ]

        # ============================================================
        #  SET MODE – 0 UPDATE, 1 QUERY
        # ============================================================
        @def_method(m, self.set_mode, ready=~self._clr_busy)
        def _(mode):
            m.d.sync += self._mode.eq(mode)

        # ============================================================
        #  BACKGROUND CLEAR – keep stand‑by sketch fresh
        # ============================================================
        with Transaction(name="BackgroundClear").body(m):
            with m.If(self._clr_pending & ~self._clr_busy):
                with m.If(self._active_sel == 0):
                    self._cms1.clear(m)   # cms1 is stand‑by
                with m.Else():
                    self._cms0.clear(m)   # cms0 is stand‑by
                m.d.sync += [
                    self._clr_pending.eq(0),
                    self._clr_busy.eq(1),
                    self._clr_timer.eq(0),
                ]

        # Timer – CountMinSketch.clear() stalls each row for <width> cycles.
        with m.If(self._clr_busy):
            m.d.sync += self._clr_timer.eq(self._clr_timer + 1)
            with m.If(self._clr_timer == self.width - 1):
                m.d.sync += self._clr_busy.eq(0)

        return m
