from __future__ import annotations

from amaranth import *
from transactron import *
from transactron import TModule, def_method

from mur.count.CountMinSketch import CountMinSketch

__all__ = ["RollingCountMinSketch"]


class RollingCountMinSketch(Elaboratable):
    """Triple‑buffered, rolling Count‑Min Sketch.

    Roles of the three internal sketches (``cms0``‒``cms2``):

    * **UPDATE**  – receives *insert* transactions while the module is in
      *update* mode.
    * **QUERY**   – serves *query* transactions while the module is in
      *query* mode.
    * **CLEAR**   – is being scrubbed to zero in the background.

    ``change_roles`` rotates the roles forward (UPDATE → QUERY → CLEAR →
    UPDATE …) and immediately triggers *clear* on the sketch that *was*
    QUERY, without disturbing an on‑going sweep.  The finished CLEAR
    sketch becomes the next UPDATE.
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
        self.depth = depth
        self.width = width
        self.counter_width = counter_width
        self.item_width = input_data_width

        # ── Public Transactron API ────────────────────────────────────
        self.set_mode     = Method(i=[("mode", 1)])     # 0 = UPDATE, 1 = QUERY
        self.change_roles = Method()                      # rotate roles
        self.input        = Method(i=[("data", self.item_width)],o=[("mode", 1)])
        self.output       = Method(o=[("count", self.counter_width), ("valid", 1)])

        # ── Three internal sketches ──────────────────────────────────
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
        self._cms2 = CountMinSketch(
            depth            = depth,
            width            = width,
            counter_width    = counter_width,
            input_data_width = self.item_width,
            hash_params      = hash_params,
        )

        # ── Role bookkeeping ─────────────────────────────────────────
        # _head == index (0‒2) of the current UPDATE sketch.
        self._head = Signal(range(3), init=0)
        self._mode = Signal(1, init=0)   # 0 = UPDATE, 1 = QUERY

    # ------------------------------------------------------------------
    #  Elaborate
    # ------------------------------------------------------------------
    def elaborate(self, platform):
        m = TModule()
        m.submodules += [self._cms0, self._cms1, self._cms2]

        # --------------------------------------------------  INPUT
        @def_method(m, self.input)
        def _(data):
            with m.If(self._mode == 0):            # ── UPDATE mode
                with m.Switch(self._head):
                    with m.Case(0): self._cms0.insert(m, data=data)
                    with m.Case(1): self._cms1.insert(m, data=data)
                    with m.Case(2): self._cms2.insert(m, data=data)
            with m.Else():                         # ── QUERY mode
                # query_idx = (head + 1) % 3
                with m.Switch(self._head):
                    with m.Case(0): self._cms1.query_req(m, data=data)
                    with m.Case(1): self._cms2.query_req(m, data=data)
                    with m.Case(2): self._cms0.query_req(m, data=data)
            return {"mode": self._mode}

        # --------------------------------------------------  OUTPUT
        @def_method(m, self.output)
        def _():
            r0 = self._cms0.query_resp(m)
            r1 = self._cms1.query_resp(m)
            r2 = self._cms2.query_resp(m)

            valid = Signal(1)
            count = Signal(self.counter_width)

            # One – and only one – sketch raises *valid* at a time.
            m.d.comb += [
                valid.eq(r0["valid"] | r1["valid"] | r2["valid"]),
                count.eq(Mux(r0["valid"], r0["count"],
                              Mux(r1["valid"], r1["count"], r2["count"]))),
            ]
            return {"count": count, "valid": valid}

        # --------------------------------------------------  CHANGE_ROLES
        @def_method(m, self.change_roles)
        def _():
            cur_query = (self._head + 1) % 3        # sketch that was QUERY
            # Advance roles
            m.d.sync += self._head.eq((self._head + 2) % 3)

            # Kick off CLEAR on the sketch that *was* QUERY
            with m.Switch(cur_query):
                with m.Case(0): self._cms0.clear(m)
                with m.Case(1): self._cms1.clear(m)
                with m.Case(2): self._cms2.clear(m)

        # --------------------------------------------------  SET_MODE
        @def_method(m, self.set_mode)
        def _(mode):
            m.d.sync += self._mode.eq(mode)

        return m
