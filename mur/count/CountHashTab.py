from amaranth import *
from amaranth.utils import ceil_log2
from transactron import *
from amaranth.lib.memory import Memory as memory

__all__ = ["CountHashTab"]


class CountHashTab(Elaboratable):
    _P = 4_294_967_291            # 2**32 − 5

    # ---------------------------------------------------------------- #
    #  constructor                                                     #
    # ---------------------------------------------------------------- #
    def __init__(self, *, size: int, counter_width: int,
                 input_data_width: int, hash_a: int = 1, hash_b: int = 0):
        if input_data_width > 96:
            raise ValueError("input_data_width > 96 is not supported")

        self.size             = size
        self.counter_width    = counter_width
        self.input_data_width = input_data_width

        # ── Transactron API ───────────────────────────────────────────
        self.insert             = Method(i=[("data", input_data_width)])
        self.query_req          = Method(i=[("data", input_data_width)])
        self.query_resp         = Method(o=[("count", counter_width)])
        self.update_hash_params = Method(i=[("a", 32), ("b", 32)])
        self.clear              = Method()

        self.query_resp.schedule_before(self.query_req)
        

        # ── Runtime-programmable hash coefficients ────────────────────
        self.hash_a = Signal(32, init=hash_a % self._P)
        self.hash_b = Signal(32, init=hash_b % self._P)

        # ── Counter storage (sync Memory) ─────────────────────────────
        #
        # • one write port   – used by INSERT and CLEAR
        # • one read  port   – shared by INSERT (read-modify-write) and
        #                      QUERY; flagged transparent so that a read
        #                      hitting the same address as an earlier
        #                      write in the *same* cycle returns the
        #                      updated value.
        #
        self._mem = memory(shape=counter_width, depth=size, init=[0]*size)

    # ---------------------------------------------------------------- #
    #  Internal helpers                                                #
    # ---------------------------------------------------------------- #
    def _hash_index(self, m: TModule, x: Value) -> Signal:
        x_mod_p  = Signal(32)
        prod     = Signal(64)
        sum_ab   = Signal(64)
        mod_p    = Signal(32)
        idx      = Signal(ceil_log2(self.size))

        m.d.av_comb += [
            x_mod_p.eq(x % self._P),
            prod.eq(self.hash_a * x_mod_p),
            sum_ab.eq(prod + self.hash_b),
            mod_p.eq(sum_ab % self._P),
            idx.eq(mod_p % self.size),
        ]
        return idx

    # ---------------------------------------------------------------- #
    #  elaborate                                                       #
    # ---------------------------------------------------------------- #
    def elaborate(self, platform):
        m = TModule()

        # Add the memory so the simulator/back-end sees it
        m.submodules += self._mem

        wr = self._mem.write_port(domain="sync")
        rd = self._mem.read_port(domain="sync", transparent_for=(wr,))

        # ── Control / housekeeping flags ──────────────────────────────
        ins_pending  = Signal()        # waiting for rd-data to update
        ins_addr     = Signal.like(rd.addr)
        resp_valid   = Signal()        # QUERY response waiting
        resp_ready   = Signal()        # QUERY response consumed
        resp         = Signal.like(rd.data)
        clr_running  = Signal()        # sequential clear in progress
        clr_addr     = Signal(range(self.size))

        # ------------------------ INSERT -----------------------------
        #
        # Cycle-0 (req): latch address & start memory read
        # Cycle-1 (upd): write(rd.data + 1) back to same address
        #
        with m.If(ins_pending):
            # C-1 of INSERT
            m.d.comb += [wr.en.eq(1),
                         wr.addr.eq(ins_addr),
                         wr.data.eq(rd.data + 1)]
            m.d.sync += ins_pending.eq(0)
        
        # --------------------- SEQUENTIAL CLEAR ----------------------
        with m.If(clr_running):
            m.d.comb += [
                wr.en.eq(1),
                wr.addr.eq(clr_addr),
                wr.data.eq(0),
            ]
            m.d.sync += clr_addr.eq(clr_addr + 1)
            with m.If(clr_addr == self.size - 1):
                m.d.sync += clr_running.eq(0)
        
        with m.If(resp_ready):
            m.d.sync += [
                resp_ready.eq(0),
                resp_valid.eq(1),
                resp.eq(rd.data),
            ]

        # -------------------- Transactron bodies ---------------------
        @def_method(m, self.insert, ready=(~ins_pending & ~clr_running))
        def _(data):
            addr = self._hash_index(m, data)
            m.d.comb += [
                rd.en.eq(1),
                rd.addr.eq(addr),
            ]
            m.d.sync += ins_addr.eq(addr)
            m.d.sync += ins_pending.eq(1)
        @def_method(m, self.query_resp, ready=resp_valid & ~clr_running)
        def _():
            m.d.sync += resp_valid.eq(0)
            return {"count": resp}

        @def_method(m, self.query_req,
                    ready=(~resp_valid | self.query_resp.run) & ~clr_running & ~self.insert.run & ~ins_pending)
        def _(data):
            m.d.comb += [
                rd.en.eq(1),
                rd.addr.eq(self._hash_index(m, data)),
            ]
            m.d.sync += resp_ready.eq(1)


        @def_method(m, self.update_hash_params)
        def _(a, b):
            m.d.sync += [
                self.hash_a.eq(a % self._P),
                self.hash_b.eq(b % self._P),
            ]

        @def_method(m, self.clear, ready=~clr_running & ~ins_pending)
        def _():
            m.d.sync += [
                clr_running.eq(1),
                clr_addr.eq(0),
            ]

        return m
