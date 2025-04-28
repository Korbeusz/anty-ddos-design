from __future__ import annotations

from amaranth import *
from amaranth.utils import ceil_log2
from transactron import *

# Local import — adjust to your project layout if needed
from mur.count.CountHashTab import CountHashTab

__all__ = ["CountMinSketch"]


class CountMinSketch(Elaboratable):
    """Count‑Min Sketch implementation built from *CountHashTab* sub‑modules.

    The design closely mirrors the structure of *CountHashTab* and the pipeline
    style of *ParserAligner*, while demonstrating the sub‑module method‑call
    pattern shown in *RecursiveUnsignedMul* (see ``fast_recursive.py``).

    Parameters
    ----------
    depth: int
        Number of hash rows (‖ hash functions).
    width: int
        Number of buckets per row (*d* in Count‑Min Sketch literature).
    counter_width: int
        Bit‑width of each per‑bucket counter.
    input_data_width: int
        Bit‑width of the item inserted / queried.
    hash_params: list[tuple[int, int]] | None, default = ``None``
        Optional list of *(a, b)* pairs for the universal hashes of each row.
        If omitted, *a* defaults to ``row_idx + 1`` and *b* to ``0``.

    Methods
    -------
    insert(data)
        Increment the sketch for *data* (broadcasts to every row).
    query_req(data)
        Request the estimated count for *data*.
    query_resp() -> {"count": …}
        Returns the *minimum* of the row counters *one cycle later*.
    update_hash_params(row_idx, a, b)
        Change the universal‑hash coefficients of a selected row at run‑time.
    clear()
        Resets **all** buckets to zero; other methods stall during the sweep.
    """

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
        self.query_resp         = Method(o=[("count", self.counter_width)])
        self.update_hash_params = Method(i=[("row_idx", ceil_log2(depth)),
                                            ("a", 32), ("b", 32)])
        self.clear              = Method()

        # *query_resp* must win arbitration over *query_req* to keep
        # the one‑cycle latency intact (same trick as in CountHashTab)
        self.query_resp.schedule_before(self.query_req)

        # ── Sub‑modules: one CountHashTab per row ──────────────────────
        if hash_params is not None and len(hash_params) != depth:
            raise ValueError("hash_params length must match depth")

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
            setattr(self, f"_row{idx}", row)  # for *nmigen* signal names
            self.rows.append(row)

    # ------------------------------------------------------------------ #
    #  Elaborate
    # ------------------------------------------------------------------ #
    def elaborate(self, platform):
        m = TModule()
        m.submodules += self.rows  # handshake logic is inside the rows

        # ── Local FSM state ────────────────────────────────────────────
        resp_valid   = Signal()   # a query is in‑flight
        clr_running  = Signal()   # global clear is sweeping
        clr_counter  = Signal(range(self.width + 1))  # row‑sweep progress

        # We purposefully clear **all** rows concurrently and simply keep
        # the top‑level blocked for *width* cycles. This guarantees that the
        # slowest row (one counter / cycle) finishes before *clr_running*
        # drops.

        # ---------------------------- INSERT --------------------------
        @def_method(m, self.insert, ready=~clr_running)
        def _(data):
            for row in self.rows:
                row.insert(m, data=data)  # broadcast
        
          # ---------------------- QUERY — response phase ----------------
        @def_method(m, self.query_resp, ready=resp_valid & ~clr_running)
        def _():
            # Collect the per‑row counters *in the same cycle*, compute the
            # minimum completely combinatorially, and clear the *resp_valid*
            # flag for the next transaction.
            counts = [row.query_resp(m)["count"] for row in self.rows]

            # Build a reduction tree of *min()* using nested *Mux*es.
            expr = counts[0]
            for cnt in counts[1:]:
                expr = Mux(cnt < expr, cnt, expr)

            m.d.sync += resp_valid.eq(0)
            return {"count": expr}

        # ---------------------- QUERY — request phase -----------------
        @def_method(m, self.query_req,
                    ready=(~resp_valid | self.query_resp.run) & ~clr_running)
        def _(data):
            # Broadcast the request to every row and set *resp_valid*.
            for row in self.rows:
                row.query_req(m, data=data)
            m.d.sync += resp_valid.eq(1)

      

        # --------------------- HASH PARAMETER UPDATE ------------------
        @def_method(m, self.update_hash_params)
        def _(row_idx, a, b):
            # Dispatch the update to the selected row using a *switch*.
            with m.Switch(row_idx):
                for idx, row in enumerate(self.rows):
                    with m.Case(idx):
                        row.update_hash_params(m, a=a % self._P, b=b % self._P)

        # ----------------------------- CLEAR --------------------------
        @def_method(m, self.clear, ready=~clr_running)
        def _():
            # Fire a *clear* on *all* rows in this very cycle and start the
            # top‑level blocking timer.
            for row in self.rows:
                row.clear(m)
            m.d.sync += [
                clr_running.eq(1),
                clr_counter.eq(0),
            ]

        # Timer that releases the stall once every row has had *width*
        # opportunities to wipe all its buckets.
        with m.If(clr_running):
            m.d.sync += clr_counter.eq(clr_counter + 1)
            with m.If(clr_counter == self.width - 1):
                m.d.sync += clr_running.eq(0)

        return m
