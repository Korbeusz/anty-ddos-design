# mur/count/CountHashTab.py
from amaranth import *
from transactron import *
from amaranth.lib.memory import Memory as memory
from transactron.lib import logging

log = logging.HardwareLogger("count.counthashtab")
__all__ = ["CountHashTab"]


class CountHashTab(Elaboratable):
    """
    CountHashTab is a single row in a CountMinSketch data structure.

    Attributes
    ----------
        size (int): Number of hash buckets (must be a power of 2)
        counter_width (int): Number of bits in each counter
        input_data_width (int): Number of bits in each input data
        hash_a (int): First hash coefficient
        hash_b (int): Second hash coefficient

    Methods
    -------
        insert(data: int): Insert data into the hash table
        query_req(data: int): Request a query for the count of data
        query_resp(): Get the count and valid flag from the last query
        clear(): Clear the hash table. Clearing takes at lest self.size + 2 cycles.
    """

    _P = 4_294_967_291

    def __init__(
        self,
        *,
        size: int,
        counter_width: int,
        input_data_width: int,
        hash_a: int = 1,
        hash_b: int = 0,
    ):

        if size & (size - 1) != 0:
            raise ValueError(f"size must be a power of 2, got {size}")
        self.size = size
        self.counter_width = counter_width
        self.input_data_width = input_data_width

        self.insert = Method(i=[("data", input_data_width)])
        self.query_req = Method(i=[("data", input_data_width)])
        self.query_resp = Method(o=[("count", counter_width), ("valid", 1)])
        self.clear = Method()

        self.hash_a = Signal(32, init=hash_a % self._P)
        self.hash_b = Signal(32, init=hash_b % self._P)

        self._mem = memory(shape=counter_width, depth=size, init=[0] * size)

    def elaborate(self, platform):
        m = TModule()
        m.submodules += self._mem

        wr = self._mem.write_port(domain="sync")
        rd = self._mem.read_port(domain="sync", transparent_for=(wr,))

        req_hash_calculating1 = Signal()
        req_hash_calculating2 = Signal()
        req_memory_read = Signal()
        req_save = Signal()
        req_ready = Signal()
        req_read_value = Signal(self.counter_width)
        req_addr_for_read = Signal(range(self.size))
        req_addr2 = Signal(range(self.size))

        insert_hash_calculating1 = Signal()
        insert_hash_calculating2 = Signal()
        insert_memory_read = Signal()
        insert_incrementing = Signal()
        insert_memory_write = Signal()
        insert_memory_write_address = Signal(range(self.size))
        insert_memory_write_address2 = Signal(range(self.size))
        insert_incremented_value = Signal(self.counter_width)
        insert_addr_for_read = Signal(range(self.size))

        req_sum_ab = Signal(64)
        req_insert_data = Signal(self.input_data_width)
        insert_sum_ab = Signal(64)
        insert_data = Signal(self.input_data_width)

        clr_running = Signal()
        clr_addr = Signal(range(self.size))
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
            req_save.eq(req_memory_read),
            req_ready.eq(req_save),
            insert_hash_calculating1.eq(0),
            insert_hash_calculating2.eq(insert_hash_calculating1),
            insert_memory_read.eq(insert_hash_calculating2),
            insert_incrementing.eq(insert_memory_read),
            insert_memory_write.eq(insert_incrementing),
            clr_waiting1.eq(0),
            clr_waiting2.eq(clr_waiting1),
        ]

        m.d.sync += [
            req_sum_ab.eq(self.hash_a * req_insert_data + self.hash_b),
            req_addr_for_read.eq(req_sum_ab % self._P),
            insert_sum_ab.eq(self.hash_a * insert_data + self.hash_b),
            insert_addr_for_read.eq(insert_sum_ab % self._P),
        ]

        with m.If(req_memory_read):

            m.d.comb += [rd.en.eq(1), rd.addr.eq(req_addr_for_read)]
            m.d.sync += req_addr2.eq(req_addr_for_read)

        with m.If(req_save):
            with m.If(
                insert_memory_write & (insert_memory_write_address2 == req_addr2)
            ):
                m.d.sync += req_read_value.eq(insert_incremented_value)
            with m.Else():
                m.d.sync += req_read_value.eq(rd.data)

        with m.If(insert_memory_read):
            m.d.comb += [rd.en.eq(1), rd.addr.eq(insert_addr_for_read)]
            m.d.sync += insert_memory_write_address.eq(insert_addr_for_read)

        with m.If(insert_incrementing):
            with m.If(
                insert_memory_write
                & (insert_memory_write_address2 == insert_memory_write_address)
            ):
                m.d.sync += insert_incremented_value.eq(insert_incremented_value + 1)
            with m.Else():
                m.d.sync += insert_incremented_value.eq(rd.data + 1)
            m.d.sync += insert_memory_write_address2.eq(insert_memory_write_address)

        with m.If(insert_memory_write):
            log.debug(
                m,
                True,
                "insert_memory_write {:x} v: {:x}",
                insert_memory_write_address2,
                insert_incremented_value,
            )
            m.d.comb += [
                wr.en.eq(1),
                wr.addr.eq(insert_memory_write_address2),
                wr.data.eq(insert_incremented_value),
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

        @def_method(m, self.insert)
        def _(data):
            log.debug(m, True, "INSERT")
            m.d.sync += insert_hash_calculating1.eq(1)
            m.d.sync += insert_data.eq(data)

        @def_method(m, self.query_resp)
        def _():
            return {"count": req_read_value, "valid": req_ready}

        @def_method(m, self.query_req)
        def _(data):
            log.debug(m, True, "QUERY")
            m.d.sync += req_hash_calculating1.eq(1)
            m.d.sync += req_insert_data.eq(data)

        @def_method(m, self.clear)
        def _():
            log.debug(m, True, "CLEAR")
            m.d.sync += clr_addr.eq(0)
            m.d.sync += clr_waiting1.eq(1)

        return m
