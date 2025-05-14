# mur/count/CountHashTab.py
from __future__ import annotations
from amaranth import *
from amaranth.utils import ceil_log2
from transactron import *
from amaranth.lib.memory import Memory as memory
from transactron.lib import logging
log = logging.HardwareLogger("count.counthashtab")
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
        # Size should be a power of 2
        if size & (size - 1) != 0:
            raise ValueError(f"size must be a power of 2, got {size}")
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
    #  elaborate                                                       #
    # ---------------------------------------------------------------- #
    def elaborate(self, platform):
        m = TModule()
        m.submodules += self._mem

        wr = self._mem.write_port(domain="sync")
        rd = self._mem.read_port(domain="sync", transparent_for=(wr,))

        # ── Pipeline and housekeeping flags ───────────────────────────
        req_hash_calculating1 = Signal()  # hash index calculation in progress
        req_hash_calculating2 = Signal()  # hash index calculation in progress
        req_memory_read = Signal()          # memory access in progress
        req_ready        = Signal()          # ready to accept new request

        insert_hash_calculating1 = Signal()
        insert_hash_calculating2 = Signal()  # hash index calculation in progress
        insert_memory_read = Signal()         # INSERT memory access
        insert_memory_write = Signal()        # INSERT memory access
        insert_memory_write_address = Signal(range(self.size))

        req_addr_for_read     = Signal(range(self.size))  # hash index
        insert_addr_for_read     = Signal(range(self.size))  # hash index
        
        #hash signals 
        req_sum_ab  = Signal(64)
        req_insert_data   = Signal(self.input_data_width)
        insert_sum_ab  = Signal(64)
        insert_data   = Signal(self.input_data_width)


        # CLEAR sequencer
        clr_running  = Signal()
        clr_addr     = Signal(range(self.size))
        clr_waiting1 = Signal()
        clr_waiting2 = Signal()
        m.d.comb += [
            wr.en.eq(0),
            rd.en.eq(0),
        ]
        m.d.sync += [
            req_hash_calculating1.eq(0),
            req_hash_calculating2.eq(req_hash_calculating1),
            req_memory_read.eq(req_hash_calculating2),
            req_ready.eq(req_memory_read),
            insert_hash_calculating1.eq(0),
            insert_hash_calculating2.eq(insert_hash_calculating1),
            insert_memory_read.eq(insert_hash_calculating2),
            insert_memory_write.eq(insert_memory_read),
            clr_waiting1.eq(0),
            clr_waiting2.eq(clr_waiting1),
        ]
        # ------------------------------------------------------------ #
        #  Stage-2: memory operations & CLEAR                          #
        # ------------------------------------------------------------ #
        # Hash index calculation
        m.d.sync += [
            req_sum_ab.eq(self.hash_a * req_insert_data + self.hash_b),
            req_addr_for_read.eq(req_sum_ab % self._P),
            insert_sum_ab.eq(self.hash_a * insert_data + self.hash_b),
            insert_addr_for_read.eq(insert_sum_ab % self._P),
        ]

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
        
        with m.If(clr_waiting2):
            m.d.sync += clr_running.eq(1)
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
            m.d.sync += insert_hash_calculating1.eq(1)
            m.d.sync += insert_data.eq(data)
            
        
        @def_method(m, self.query_resp)
        def _():
            return {"count": rd.data, "valid": req_ready}

        @def_method(m, self.query_req)
        def _(data):
            m.d.sync += req_hash_calculating1.eq(1)
            m.d.sync += req_insert_data.eq(data)
        

        @def_method(m, self.clear)
        def _():
            log.debug(m,True,"CLEAR")
            m.d.sync += clr_addr.eq(0)
            m.d.sync += clr_waiting1.eq(1)

        return m
