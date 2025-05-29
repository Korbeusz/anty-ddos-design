# mur/count/CountHashTab.py
from amaranth import *
from transactron import *
from amaranth.lib.memory import Memory as memory
from mur.count.hash import Hash

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

    _P = 65521

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

        self.insert_hash = Hash(input_width=input_data_width, a=hash_a, b=hash_b)
        self.query_hash = Hash(input_width=input_data_width, a=hash_a, b=hash_b)
        self.hash_a = Signal(32, init=hash_a % self._P)
        self.hash_b = Signal(32, init=hash_b % self._P)

        self._mem = memory(shape=counter_width, depth=size, init=[0] * size)

    def elaborate(self, platform):
        m = TModule()
        m.submodules += [self._mem, self.insert_hash, self.query_hash]

        wr = self._mem.write_port(domain="sync")
        rd = self._mem.read_port(domain="sync")

        req_start = Signal()
        req_save = Signal()
        req_ready = Signal()
        req_read_value = Signal(self.counter_width)

        inc_start = Signal()
        insert_incrementing = Signal()
        insert_writing = Signal()

        clr_running = Signal()
        clr_addr = Signal(range(self.size))
        clr_waiting = Signal(range(64))

        m.d.sync += [
            wr.en.eq(0),
            rd.en.eq(0),
        ]
        m.d.sync += [
            req_start.eq(0),
            req_save.eq(req_start),
            req_ready.eq(req_save),
            inc_start.eq(0),
            insert_incrementing.eq(inc_start),
            insert_writing.eq(insert_incrementing),
        ]

        with Transaction().body(m):
            res = self.query_hash.result(m)
            with m.If(res["valid"]):
                m.d.sync += [rd.en.eq(1), rd.addr.eq(res["hash"]), req_start.eq(1)]

        increment_addr = Signal(range(self.size))
        with m.If(req_start):
            m.d.sync += increment_addr.eq(rd.addr)

        with m.If(req_save):
            with m.If(insert_writing & (wr.addr == increment_addr)):
                m.d.sync += req_read_value.eq(wr.data)
            with m.Else():
                m.d.sync += req_read_value.eq(rd.data)

        with Transaction().body(m):
            res = self.insert_hash.result(m)
            with m.If(res["valid"]):
                m.d.sync += [
                    rd.en.eq(1),
                    rd.addr.eq(res["hash"]),
                    inc_start.eq(1),
                ]
        write_addr = Signal(range(self.size))
        with m.If(inc_start):
            m.d.sync += write_addr.eq(rd.addr)

        write_addr2 = Signal(range(self.size))
        write_data = Signal(self.counter_width)
        with m.If(insert_incrementing):
            # with m.If(insert_writing & (wr.addr == write_addr)):
            #     m.d.sync += [
            #         wr.en.eq(1),
            #         wr.addr.eq(write_addr),
            #         wr.data.eq(wr.data + 1),
            #     ]
            # with m.Else():
            m.d.sync += [write_data.eq(rd.data), write_addr2.eq(write_addr)]

        with m.If(insert_writing):
            m.d.sync += wr.data.eq(write_data + 1)
            m.d.sync += [wr.en.eq(1), wr.addr.eq(write_addr2)]

        with m.If(clr_waiting > 0):
            m.d.sync += clr_waiting.eq(clr_waiting - 1)
            with m.If(clr_waiting == 1):
                m.d.sync += clr_running.eq(1)
                m.d.sync += [
                    wr.en.eq(1),
                    wr.addr.eq(0),
                    wr.data.eq(0),
                ]
        with m.If(clr_running):
            m.d.sync += wr.addr.eq(wr.addr + 1)
            m.d.sync += wr.data.eq(0)
            m.d.sync += wr.en.eq(1)
            with m.If(wr.addr == self.size - 2):
                m.d.sync += clr_running.eq(0)

        @def_method(m, self.insert)
        def _(data):
            self.insert_hash.input(m, data)

        @def_method(m, self.query_resp)
        def _():
            return {"count": req_read_value, "valid": req_ready}

        @def_method(m, self.query_req)
        def _(data):
            self.query_hash.input(m, data)

        @def_method(m, self.clear)
        def _():
            m.d.sync += clr_addr.eq(0)
            m.d.sync += clr_waiting.eq(20)

        return m
