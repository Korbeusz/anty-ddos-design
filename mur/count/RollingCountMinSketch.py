from __future__ import annotations

from amaranth import *
from amaranth.utils import ceil_log2
from transactron import *
from transactron.core import Transaction  # for explicit Transaction blocks

# Local import – adjust the path to your project structure if needed
from mur.count.CountMinSketch import CountMinSketch

__all__ = ["RollingCountMinSketch"]


class RollingCountMinSketch(Elaboratable):
    """Double-buffered **Count-Min Sketch** with background clearing.

    Two internal :class:`~mur.count.CountMinSketch.CountMinSketch` instances are
    kept and alternated in a *ping-pong* fashion:

    * **active sketch** – receives *insert* transactions or serves *query* 
      requests, depending on the *mode* selected with :py:meth:`set_mode`.
    * **stand-by sketch** – is cleared **automatically** in the background so
      that it is ready to become the next active sketch on the next role swap.

    External API (all are *Transactron* :class:`~transactron.core.Method` s)
    ----------------------------------------------------------------------
    ``insert(data)``
        Increment the sketch for *data* (ready **only** in *UPDATE* mode).
    ``query_req(data)`` / ``query_resp()``
        One-cycle-latency query interface (ready **only** in *QUERY* mode).
    ``change_roles()``
        Swap *active* / *stand-by* sketches.  Ready **only** in *UPDATE* mode
        *and* after the stand-by sketch has finished its background clear.
    ``set_mode(mode)``
        ``mode = 0`` → *UPDATE*, ``mode = 1`` → *QUERY*.

    The design purposefully mirrors the handshake and arbitration style of
    :class:`~mur.count.CountMinSketch.CountMinSketch` so that it can be a drop-
    in replacement in existing data paths.  See the referenced source files
    for the implementation patterns reused here.
    """

    # ----------------------------- Constructor -----------------------------
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
        self.depth = depth
        self.width = width
        self.counter_width = counter_width
        self.input_data_width = input_data_width

        # ── Public Transactron interface ──────────────────────────────────
        self.insert = Method(i=[("data", self.input_data_width)])
        self.query_req = Method(i=[("data", self.input_data_width)])
        self.query_resp = Method(o=[("count", self.counter_width)])
        self.change_roles = Method()  # no arguments
        self.set_mode = Method(i=[("mode", 1)])  # 0 = UPDATE, 1 = QUERY

        # *query_resp* must win arbitration over *query_req* just like in the
        # underlying *CountMinSketch* implementation. citeturn0file2
        self.query_resp.schedule_before(self.query_req)

        # ── Two internal sketches ─────────────────────────────────────────
        self._cms0 = CountMinSketch(
            depth=depth,
            width=width,
            counter_width=counter_width,
            input_data_width=input_data_width,
            hash_params=hash_params,
        )
        self._cms1 = CountMinSketch(
            depth=depth,
            width=width,
            counter_width=counter_width,
            input_data_width=input_data_width,
            hash_params=hash_params,
        )

        # ── Local control / status signals ───────────────────────────────
        self._active_sel = Signal(1, init=0)  # 0 → cms0 active, 1 → cms1 active
        self._mode = Signal(1, init=0)        # 0 → UPDATE, 1 → QUERY

        # Background-clear book-keeping for the stand-by sketch
        self._clr_pending = Signal()  # 1 → call *clear()* on stand-by ASAP
        self._clr_busy = Signal()     # 1 → stand-by is currently sweeping
        self._clr_timer = Signal(range(self.width + 1))  # progress counter

        # One-cycle latency tracking for the query path (same trick as in CMS)
        self._resp_valid = Signal()

    # ------------------------------- Elaborate -----------------------------
    def elaborate(self, platform):
        m = TModule()
        m.submodules.cms0 = self._cms0
        m.submodules.cms1 = self._cms1

        # ------------------------------------------------------------------
        # INSERT (only in UPDATE mode)
        # ------------------------------------------------------------------
        @def_method(m, self.insert, ready=~self._mode)
        def _(data):
            # Route the call to the active sketch only.
            with m.If(self._active_sel == 0):
                self._cms0.insert(m, data=data)
            with m.Else():
                self._cms1.insert(m, data=data)

        # ------------------------------------------------------------------
        # QUERY – *response* side (mirrors pattern from CountMinSketch)
        # ------------------------------------------------------------------
        @def_method(m, self.query_resp, ready=self._mode & self._resp_valid)
        def _():
            count = Signal(self.counter_width)
            with m.If(self._active_sel == 0):
                ret = self._cms0.query_resp(m)
                m.d.av_comb += count.eq(ret["count"])
            with m.Else():
                ret = self._cms1.query_resp(m)
                m.d.av_comb += count.eq(ret["count"])

            m.d.sync += self._resp_valid.eq(0)
            return {"count": count}

        # ------------------------------------------------------------------
        # QUERY – *request* side
        # ------------------------------------------------------------------
        @def_method(
            m,
            self.query_req,
            ready=self._mode & (~self._resp_valid | self.query_resp.run),
        )
        def _(data):
            with m.If(self._active_sel == 0):
                self._cms0.query_req(m, data=data)
            with m.Else():
                self._cms1.query_req(m, data=data)
            m.d.sync += self._resp_valid.eq(1)

        # ------------------------------------------------------------------
        # CHANGE ROLES – ping-pong the two sketches
        #   Ready when:
        #     * we are in UPDATE mode, and
        #     * the stand-by sketch is *not* in the middle of a clear sweep.
        # ------------------------------------------------------------------
        @def_method(
            m,
            self.change_roles,
            ready=(~self._mode) & ~self._clr_busy & ~self._clr_pending,
        )
        def _():
            m.d.sync += [
                self._active_sel.eq(~self._active_sel),
                self._clr_pending.eq(1),  # clear the *new* stand-by
            ]

        # ------------------------------------------------------------------
        # SET MODE – 0 = UPDATE, 1 = QUERY
        # ------------------------------------------------------------------
        @def_method(m, self.set_mode, ready=~self._clr_busy)
        def _(mode):
            m.d.sync += self._mode.eq(mode)

        # ------------------------------------------------------------------
        # AUTOMATIC BACKGROUND CLEAR of the stand-by sketch
        # ------------------------------------------------------------------
        with Transaction().body(m):
            # Fire *clear()* exactly once per role swap
            with m.If(self._clr_pending & ~self._clr_busy):
                # Call *clear()* on the current stand-by sketch.
                with m.If(self._active_sel == 0):  # cms1 is stand-by
                    self._cms1.clear(m)
                with m.Else():                      # cms0 is stand-by
                    self._cms0.clear(m)
                # Book-keeping
                m.d.sync += [
                    self._clr_pending.eq(0),
                    self._clr_busy.eq(1),
                    self._clr_timer.eq(0),
                ]

        # Simple timer – *CountMinSketch.clear()* keeps the row blocked for
        # *width* cycles, so after that many cycles we know the sweep ended.
        with m.If(self._clr_busy):
            m.d.sync += self._clr_timer.eq(self._clr_timer + 1)
            with m.If(self._clr_timer == self.width - 1):
                m.d.sync += self._clr_busy.eq(0)

        return m
