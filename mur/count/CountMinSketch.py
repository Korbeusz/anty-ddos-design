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

    @staticmethod
    def _tree_min(values: list[Value]) -> Value:
        """Return minimum of *values* using a balanced tree of Mux nodes.

        This shortens the combinational path from *O(n)* to *O(log₂ n)*.
        """
        if not values:
            raise ValueError("values must be non‑empty")

        layer = values
        while len(layer) > 1:
            next_layer: list[Value] = []
            # Pair‑wise compare/choose ---------------------------------
            for i in range(0, len(layer), 2):
                if i + 1 < len(layer):
                    left  = layer[i]
                    right = layer[i + 1]
                    # Select the smaller counter -----------------------
                    next_layer.append(Mux(right < left, right, left))
                else:
                    # Odd element propagates unchanged ----------------
                    next_layer.append(layer[i])
            layer = next_layer
        return layer[0]

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
            row_results = [row.query_resp(m) for row in self.rows]
            count_signals = [r["count"] for r in row_results]
            min_count = self._tree_min(count_signals)
            return {"count": min_count, "valid": row_results[0]["valid"]}
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
