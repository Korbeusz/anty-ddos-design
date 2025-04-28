from amaranth import *
from amaranth.utils import ceil_log2
from transactron import *

# Local import – adjust the path if your project structure differs
from mur.count.CountMinSketch import CountMinSketch

__all__ = ["RollingCountMinSketch"]


class RollingCountMinSketch(Elaboratable):
    """Triple‑buffered **Count‑Min Sketch** with a one‑second sliding window.

    The design instantiates **three** :class:`CountMinSketch` blocks and
    rotates their roles every *interval* clock cycles::

        current  ← inserts for the ongoing second
        last     ← frozen counts of the *previous* second, serves queries
        standby  ← is being cleared so it is ready to become *current*

    After each rotation the following invariants hold:

    * *current* has just been cleared and starts collecting fresh data.
    * *last* can be queried for counts of the *preceding* one‑second window.
    * *standby* is in the middle of a `clear()` sweep and remains inaccessible
      to the outside world until the next rotation.

    Parameters
    ----------
    depth, width, counter_width, input_data_width
        Passed straight to the underlying :class:`CountMinSketch` rows.
    interval_cycles: int
        Number of **clock cycles** that make up one second in your design.
        For a 125 MHz Ethernet MAC clock this would be ``interval_cycles=125_000_000``.
    hash_params: list[tuple[int, int]] | None, optional
        Optional per‑row universal‑hash coefficients (identical for every
        sub‑sketch). Defaults to ``[(row + 1, 0) for row in range(depth)]``.

    Public API
    ----------
    insert(data)
        Increment the *current* sketch.
    query_req(data)
        Request the count **of the previous second** (served from *last*).
    query_resp() -> {"count": …}
        Returns the estimate one cycle later, *mirroring* the latency of the
        sub‑sketch.
    """

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
        interval_cycles: int,
        hash_params: list[tuple[int, int]] | None = None,
    ) -> None:
        if depth < 1:
            raise ValueError("depth must be ≥ 1")
        if interval_cycles < 2:
            raise ValueError("interval_cycles must be ≥ 2")

        # ―― Public Transactron API ―――――――――――――――――――――――――――――――――
        self.insert     = Method(i=[("data", input_data_width)])
        self.query_req  = Method(i=[("data", input_data_width)])
        self.query_resp = Method(o=[("count", counter_width)])

        # ―― Three rolling sub‑sketches ―――――――――――――――――――――――――――――
        self.cms: list[CountMinSketch] = []
        for idx in range(3):
            cms = CountMinSketch(
                depth            = depth,
                width            = width,
                counter_width    = counter_width,
                input_data_width = input_data_width,
                hash_params      = hash_params,
            )
            setattr(self, f"_cms{idx}", cms)  # readable signal names
            self.cms.append(cms)

        # ―― Timing parameters ――――――――――――――――――――――――――――――――――――――
        self._interval_cycles = interval_cycles
        self.query_resp.schedule_before(self.query_req)
    # ------------------------------------------------------------------ #
    #  Elaborate
    # ------------------------------------------------------------------ #
    def elaborate(self, platform):
        m = TModule()
        m.submodules += self.cms

        # ── Role registers ────────────────────────────────────────────
        current = Signal(2, init=0)  # 0 … 2
        last    = Signal(2, init=1)
        standby = Signal(2, init=2)

        # ── One‑second counter ────────────────────────────────────────
        tick = Signal(range(self._interval_cycles), init=0)

        # ── Outstanding query tracking (mirrors CountMinSketch) ──────
        resp_valid = Signal()

        # =============================================================
        # INSERT  → *current*
        # =============================================================
        @def_method(m, self.insert)
        def _(data):
            with m.Switch(current):
                with m.Case(0):
                    self.cms[0].insert(m, data=data)
                with m.Case(1):
                    self.cms[1].insert(m, data=data)
                with m.Case(2):
                    self.cms[2].insert(m, data=data)

        # =============================================================
        # QUERY (response) ← *last*
        # =============================================================
        @def_method(m, self.query_resp, ready=resp_valid)
        def _():
            with m.Switch(last):
                with m.Case(0):
                    res = self.cms[0].query_resp(m)
                with m.Case(1):
                    res = self.cms[1].query_resp(m)
                with m.Case(2):
                    res = self.cms[2].query_resp(m)
            m.d.sync += resp_valid.eq(0)
            return {"count": res["count"]}

        # =============================================================
        # QUERY (request) → *last*
        # =============================================================
        @def_method(m, self.query_req, ready=(~resp_valid | self.query_resp.run))
        def _(data):
            with m.Switch(last):
                with m.Case(0):
                    self.cms[0].query_req(m, data=data)
                with m.Case(1):
                    self.cms[1].query_req(m, data=data)
                with m.Case(2):
                    self.cms[2].query_req(m, data=data)
            m.d.sync += resp_valid.eq(1)

        # =============================================================
        # House‑keeping FSM (runs *every* clock via Transaction)
        # =============================================================
        init_done = Signal(init=0)

        with Transaction().body(m):
            # One‑off: clear the initial *standby* sketch
            with m.If(~init_done):
                self.cms[2].clear(m)
                m.d.sync += init_done.eq(1)

            # Regular operation once initial clear has completed
            with m.Else():
                m.d.sync += tick.eq(tick + 1)

                # Rotate roles at the end of the 1‑s window *iff* no query
                # response is pending. Otherwise postpone by one cycle.
                with m.If((tick == self._interval_cycles - 1) & ~resp_valid):
                    # Kick off clearing of the sketch that moves to *standby*
                    with m.Switch(last):
                        with m.Case(0):
                            self.cms[0].clear(m)
                        with m.Case(1):
                            self.cms[1].clear(m)
                        with m.Case(2):
                            self.cms[2].clear(m)

                    # Rotate the role registers in a single clock edge
                    m.d.sync += [
                        tick.eq(0),
                        current.eq(standby),
                        last.eq(current),
                        standby.eq(last),
                    ]

        return m
