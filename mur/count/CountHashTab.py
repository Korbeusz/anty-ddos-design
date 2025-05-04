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

        self.size             = size
        self.counter_width    = counter_width
        self.input_data_width = input_data_width

        # ── Transactron API ───────────────────────────────────────────
        self.insert             = Method(i=[("data", input_data_width)])
        self.query_req          = Method(i=[("data", input_data_width)])
        self.query_resp         = Method(o=[("count", counter_width),("valid", 1)])
        self.clear              = Method()

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
        idx     = Signal(range(self.size))

        m.d.comb += [
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
        req_memory_read = Signal()          # memory access in progress
        req_ready        = Signal()          # ready to accept new request

        insert_memory_read = Signal()         # INSERT memory access
        insert_memory_write = Signal()        # INSERT memory access
        insert_memory_write_address = Signal(range(self.size))

        req_addr_for_read     = Signal(range(self.size))  # hash index
        insert_addr_for_read     = Signal(range(self.size))  # hash index

        # CLEAR sequencer
        clr_running  = Signal()
        clr_addr     = Signal(range(self.size))
        m.d.comb += [
            wr.en.eq(0),
            rd.en.eq(0),
        ]
        m.d.sync += [
            req_memory_read.eq(0),
            req_ready.eq(req_memory_read),
            insert_memory_read.eq(0),
            insert_memory_write.eq(insert_memory_read),
        ]
        # ------------------------------------------------------------ #
        #  Stage-2: memory operations & CLEAR                          #
        # ------------------------------------------------------------ #
        with m.If(req_memory_read):
            m.d.comb += [rd.en.eq(1), rd.addr.eq(req_addr_for_read)]
        
        with m.If(insert_memory_read):
            m.d.comb += [rd.en.eq(1), rd.addr.eq(insert_addr_for_read)]
            m.d.sync += insert_memory_write_address.eq(insert_addr_for_read)

        with m.If(insert_memory_write):
            # Read-modify-write in cycle after the read
            m.d.comb += [
                wr.en.eq(1),
                wr.addr.eq(insert_memory_write_address),
                wr.data.eq(rd.data + 1),
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

        @def_method(m, self.insert)
        def _(data):
            m.d.sync += insert_memory_read.eq(1)
            m.d.sync += insert_addr_for_read.eq(self._hash_index(m, data)),
            
        
        @def_method(m, self.query_resp)
        def _():
            return {"count": rd.data, "valid": req_ready}

        @def_method(m, self.query_req)
        def _(data):
            m.d.sync += req_memory_read.eq(1)
            m.d.sync += req_addr_for_read.eq(self._hash_index(m, data)),
        

        @def_method(m, self.clear)
        def _():
            m.d.sync += [
                clr_running.eq(1),
                clr_addr.eq(0),
            ]

        return m
