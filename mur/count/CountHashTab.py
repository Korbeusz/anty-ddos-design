# mur/count/CountHashTab.py
from __future__ import annotations
from amaranth import *
from amaranth.utils import ceil_log2
from transactron import *
from amaranth.lib.memory import Memory as memory

__all__ = ["CountHashTab"]


class CountHashTab(Elaboratable):
    """Single-row Count-Min bucket array with a **1-cycle pipelined hash**."""

    _P = 4_294_967_291                     # 2**32 − 5

    # ---------------------------------------------------------------- #
    #  constructor                                                     #
    # ---------------------------------------------------------------- #
    def __init__(
        self, *,
        size: int,
        counter_width: int,
        input_data_width: int,
        hash_a: int = 1,
        hash_b: int = 0,
    ):
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

        # Response must win arbitration to preserve latency
        self.query_resp.schedule_before(self.query_req)

        # ── Runtime-programmable hash coefficients ────────────────────
        self.hash_a = Signal(32, init=hash_a % self._P)
        self.hash_b = Signal(32, init=hash_b % self._P)

        # ── Counter storage (single-port WRITE / single-port READ) ────
        self._mem = memory(shape=counter_width, depth=size, init=[0] * size)

    # ---------------------------------------------------------------- #
    #  Internal helpers                                                #
    # ---------------------------------------------------------------- #
    def _hash_index(self, m: TModule, x: Value) -> Value:
        """Purely combinational 32-bit universal hash → [0, size-1]"""
        x_mod_p = Signal(32)
        prod    = Signal(64)
        sum_ab  = Signal(64)
        mod_p   = Signal(32)
        idx     = Signal(ceil_log2(self.size))

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
        m.submodules += self._mem

        wr = self._mem.write_port(domain="sync")
        rd = self._mem.read_port(domain="sync", transparent_for=(wr,))

        # ── Pipeline and housekeeping flags ───────────────────────────
        # Stage-1  (new):   hash-to-address register
        pipe_valid     = Signal()
        pipe_addr      = Signal.like(rd.addr)
        pipe_is_insert = Signal()        # 1 = INSERT, 0 = QUERY

        # Stage-2 (old read-modify-write / read capture)
        ins_pending  = Signal()          # waiting to write rd.data+1
        ins_addr     = Signal.like(rd.addr)
        resp_valid   = Signal()          # QUERY data buffered
        resp_ready   = Signal()
        resp_data    = Signal.like(rd.data)

        # CLEAR sequencer
        clr_running  = Signal()
        clr_addr     = Signal(range(self.size))
        m.d.comb += wr.en.eq(0)
        m.d.comb += rd.en.eq(0)
        # ------------------------------------------------------------ #
        #  Stage-2: memory operations & CLEAR                          #
        # ------------------------------------------------------------ #
        with m.If(pipe_valid):
            # Kick off the actual memory access one cycle after hash
            m.d.comb += [rd.en.eq(1), rd.addr.eq(pipe_addr)]
            with m.If(pipe_is_insert):
                # INSERT → read now, write next cycle
                m.d.sync += [
                    ins_addr.eq(pipe_addr),
                    ins_pending.eq(1),
                ]
            with m.Else():  # QUERY
                m.d.sync += resp_ready.eq(1)
            m.d.sync += pipe_valid.eq(self.insert.run | self.query_req.run)

        with m.If(ins_pending):
            # Read-modify-write in cycle after the read
            m.d.comb += [
                wr.en.eq(1),
                wr.addr.eq(ins_addr),
                wr.data.eq(rd.data + 1),
            ]
            m.d.sync += ins_pending.eq(pipe_valid & pipe_is_insert)

        with m.If(resp_ready):
            # Latch the read data for QUERY -> QUERY_RESP
            m.d.sync += [
                resp_ready.eq(pipe_valid & ~pipe_is_insert),
                resp_valid.eq(1),
                resp_data.eq(rd.data),
            ]

        # Sequential clear (same as before)
        with m.If(clr_running):
            m.d.comb += [
                wr.en.eq(1),
                wr.addr.eq(clr_addr),
                wr.data.eq(0),
            ]
            m.d.sync += clr_addr.eq(clr_addr + 1)
            with m.If(clr_addr == self.size - 1):
                m.d.sync += clr_running.eq(0)

        # ------------------------------------------------------------ #
        #  Transactron method bodies                                   #
        # ------------------------------------------------------------ #

        @def_method(m, self.insert, ready=~clr_running)
        def _(data):
            # Cycle-0: compute hash, enter pipeline
            m.d.sync += [
                pipe_valid.eq(1),
                pipe_addr.eq(self._hash_index(m, data)),
                pipe_is_insert.eq(1),
            ]
        
        @def_method(m, self.query_resp, ready=resp_valid)
        def _():
            m.d.sync += resp_valid.eq(resp_ready)
            return {"count": resp_data}

        @def_method(m, self.query_req,
                    ready=(~clr_running & ~resp_valid))
        def _(data):
            m.d.sync += [
                pipe_valid.eq(1),
                pipe_addr.eq(self._hash_index(m, data)),
                pipe_is_insert.eq(0),
            ]



        @def_method(m, self.update_hash_params)
        def _(a, b):
            m.d.sync += [
                self.hash_a.eq(a % self._P),
                self.hash_b.eq(b % self._P),
            ]

        @def_method(m, self.clear, ready=~clr_running         # NEW – no pending response
                  & ~pipe_valid          # optional – stage-1 bubble-free
                  & ~ins_pending)
        def _():
            m.d.sync += [
                clr_running.eq(1),
                clr_addr.eq(0),
            ]

        return m
