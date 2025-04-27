from amaranth import *
from transactron import *
from amaranth.utils import ceil_log2
from synth_examples.genverilog import gen_verilog
class CountHashTab(Elaboratable):
    """
    Counter hash table with sequential clear.

    Universal hash:
        h_a,b(x) = ((a * x + b) mod P) mod size
        P = 2^32 − 5  (largest 32-bit prime)

    Methods
    -------
    insert(data)           -- add one occurrence of *data*
    query_req(data)        -- request the current count
    query_resp()           -- returns {"count": …} one cycle later
    update_hash_params(a,b)
    clear()                -- wipes the table; blocks other methods
    """

    _P = 4_294_967_291  # 2**32 − 5

    # ------------------------------------------------------------------ #
    #  constructor
    # ------------------------------------------------------------------ #
    def __init__(
        self,
        size: int,
        counter_width: int,
        input_data_width: int,
        *,
        hash_a: int = 1,
        hash_b: int = 0,
    ):
        if input_data_width > 96:
            raise ValueError(
                "input_data_width > 96 is not supported "
                "(cost of the mod-P stage would explode)."
            )

        self.size              = size
        self.counter_width     = counter_width
        self.input_data_width  = input_data_width

        # ── Transactron API ─────────────────────────────────────────────
        self.insert             = Method(i=[("data", self.input_data_width)])
        self.query_req          = Method(i=[("data", self.input_data_width)])
        self.query_resp         = Method(o=[("count", self.counter_width)])
        self.update_hash_params = Method(i=[("a", 32), ("b", 32)])
        self.clear              = Method()

        self.query_resp.schedule_before(self.query_req)

        # ── Storage ─────────────────────────────────────────────────────
        # An Array-of-Registers is kept for simplicity; one write / cycle
        # (after this patch) is sufficient for RAM inference.
        self.counters = Array(Signal(counter_width) for _ in range(size))

        # ── Run-time configurable hash parameters ───────────────────────
        self.hash_a = Signal(32, init=hash_a % self._P)  # 0 < a < P
        self.hash_b = Signal(32, init=hash_b % self._P)       # 0 ≤ b < P

    # ------------------------------------------------------------------ #
    #  Hash core
    # ------------------------------------------------------------------ #
    def _hash_index(self, m: TModule, x: Value) -> Signal:
        """
        Return ((a * x + b) mod P) mod size.
        """
        x_mod_p   = Signal(32)
        prod      = Signal(64)
        sum_ab    = Signal(64)
        mod_p     = Signal(32)
        idx       = Signal(ceil_log2(self.size))

        m.d.av_comb += [
            x_mod_p.eq(x % self._P),
            prod.eq(self.hash_a * x_mod_p),
            sum_ab.eq(prod + self.hash_b),
            mod_p.eq(sum_ab % self._P),
            idx.eq(mod_p % self.size),
        ]
        return idx

    # ------------------------------------------------------------------ #
    #  Elaborate
    # ------------------------------------------------------------------ #
    def elaborate(self, platform):
        m = TModule()

        # ── Local handshake state ───────────────────────────────────────
        insert_valid = Signal()
        resp_valid   = Signal()

        insert_data  = Signal(self.input_data_width)
        query_data   = Signal(self.input_data_width)

        # ── Sequential clear FSM state ──────────────────────────────────
        clr_running  = Signal()                       # 1 while sweeping
        clr_addr     = Signal(range(self.size))       # current index

        # ── Hash indices ────────────────────────────────────────────────
        hash_insert = self._hash_index(m, insert_data)
        hash_query  = self._hash_index(m, query_data)

        # ── Data-path: counter update on insert ─────────────────────────
        with m.If(insert_valid & ~clr_running):
            m.d.sync += [
                self.counters[hash_insert].eq(self.counters[hash_insert] + 1),
                insert_valid.eq(0),
            ]

        # ── Sequential clear: one cell per clock ────────────────────────
        with m.If(clr_running):
            m.d.sync += [
                self.counters[clr_addr].eq(0),        # single write
                clr_addr.eq(clr_addr + 1),
            ]
            with m.If(clr_addr == self.size - 1):
                m.d.sync += clr_running.eq(0)         # done

        # ── Transactron method bodies ───────────────────────────────────
        #  (all gated by ~clr_running except clear itself)
        # ----------------------------------------------------------------
        @def_method(m, self.insert, ready=~clr_running)
        def _(data):
            m.d.sync += [
                insert_data.eq(data),
                insert_valid.eq(1),
            ]

        @def_method(
            m,
            self.query_resp,
            ready=resp_valid & ~clr_running
        )
        def _():
            m.d.sync += resp_valid.eq(0)
            return {"count": self.counters[hash_query]}

        @def_method(
            m,
            self.query_req,
            ready=(~resp_valid | self.query_resp.run) & ~clr_running
        )
        def _(data):
            m.d.sync += [
                query_data.eq(data),
                resp_valid.eq(1),
            ]

        @def_method(m, self.update_hash_params)
        def _(a, b):
            m.d.sync += [
                self.hash_a.eq(a % self._P),
                self.hash_b.eq(b % self._P),
            ]

        # ------------- sequential clear trigger ------------------------
        @def_method(m, self.clear, ready=~clr_running)
        def _():
            # start the sweep
            m.d.sync += [
                clr_running.eq(1),
                clr_addr.eq(0),
            ]

        return m
if __name__ == "__main__":
    gen_verilog(CountHashTab(size=256, counter_width=16, input_data_width=32), "count_hash.v")