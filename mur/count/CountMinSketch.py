from __future__ import annotations

from amaranth import *
from amaranth.utils import ceil_log2
from transactron import *

# Local import — adjust to your project layout if needed
from mur.count.CountHashTab import CountHashTab

__all__ = ["CountMinSketch"]


class CountMinSketch(Elaboratable):

    # Largest 32‑bit prime used for the universal hash in the rows
    _P = CountHashTab._P

    # ------------------------------------------------------------------ #
    #  Constructor
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

        self.depth             = depth
        self.width             = width
        self.counter_width     = counter_width
        self.input_data_width  = input_data_width

        # ── Public Transactron API ─────────────────────────────────────
        self.insert             = Method(i=[("data", self.input_data_width)])
        self.query_req          = Method(i=[("data", self.input_data_width)])
        self.query_resp         = Method(o=[("count", self.counter_width),("valid", 1)])
        self.clear              = Method()

        self.rows: list[CountHashTab] = []
        for idx in range(depth):
            a, b = (hash_params[idx] if hash_params is not None else (idx + 1, 0))
            row = CountHashTab(
                size             = width,
                counter_width     = counter_width,
                input_data_width  = input_data_width,
                hash_a            = a,
                hash_b            = b,
            )
            setattr(self, f"_row{idx}", row)
            self.rows.append(row)

    # ------------------------------------------------------------------ #
    #  Elaborate
    # ------------------------------------------------------------------ #
    def elaborate(self, platform):
        m = TModule()
        m.submodules += self.rows  

        @def_method(m, self.insert)
        def _(data):
            for row in self.rows:
                row.insert(m, data=data)
        
          # ---------------------- QUERY — response phase ----------------
        @def_method(m, self.query_resp)
        def _():
            counts = [row.query_resp(m) for row in self.rows]
            expr = counts[0]["count"]
            for cnt in counts[1:]:
                expr = Mux(cnt["count"] < expr, cnt["count"], expr)
            return {"count": expr, "valid":counts[0]["valid"]}

        # ---------------------- QUERY — request phase -----------------
        @def_method(m, self.query_req)
        def _(data):
            for row in self.rows:
                row.query_req(m, data=data)

        # ----------------------------- CLEAR --------------------------
        @def_method(m, self.clear)
        def _():
            for row in self.rows:
                row.clear(m)

        return m
