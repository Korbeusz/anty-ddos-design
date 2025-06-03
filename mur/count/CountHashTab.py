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
        log_block_size: int = 11,
        hash_a: int = 1,
        hash_b: int = 0,
    ):

        if size & (size - 1) != 0:
            raise ValueError(f"size must be a power of 2, got {size}")
        if not counter_width in (8, 16, 32):
            raise ValueError(
                f"counter_width must be 8, 16, or 32 bits, got {counter_width}"
            )
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

        self.log_block_size = log_block_size
        self._memoryblocks: list[memory] = []
        self._write_ports = []
        self._read_ports = []
        for i in range(size // (1 << self.log_block_size)):
            self._block = memory(
                shape=counter_width,
                depth=(1 << self.log_block_size),
                init=[0] * (1 << self.log_block_size),
            )
            setattr(self, f"_block_{i}", self._block)
            self._memoryblocks.append(self._block)
            wr = self._block.write_port(domain="sync")
            rd = self._block.read_port(domain="sync", transparent_for=[wr])
            setattr(self, f"_wr_{i}", wr)
            setattr(self, f"_rd_{i}", rd)
            self._write_ports.append(wr)
            self._read_ports.append(rd)

    def elaborate(self, platform):
        m = TModule()
        m.submodules += [self._memoryblocks, self.insert_hash, self.query_hash]

        req_start = Signal()
        req_save = Signal()
        req_ready = Signal()
        req_address = Signal(self.log_block_size)
        req_adress_before = Signal(self.log_block_size)
        req_adress_before_before = Signal(self.log_block_size)
        req_final_answer_ready = Signal()
        mem_idx_before = Signal(range(len(self._memoryblocks)))
        mem_idx = Signal(range(len(self._memoryblocks)))
        mem_idx_next = Signal(range(len(self._memoryblocks)))
        read_mult = [Signal() for _ in range(len(self._read_ports))]
        read_mult_before = [Signal() for _ in range(len(self._read_ports))]

        req_read_value = [
            Signal(self.counter_width) for _ in range(len(self._read_ports))
        ]

        inc_start = Signal()
        insert_incrementing = Signal()
        insert_writing = Signal()
        clr_addr = Signal(self.log_block_size)
        clr_running = Signal()
        clr_waiting = Signal(range(64))

        for wr, rd in zip(self._write_ports, self._read_ports):
            m.d.comb += rd.en.eq(1)
            m.d.sync += wr.en.eq(0)

        m.d.sync += [
            req_start.eq(0),
            req_save.eq(req_start),
            req_ready.eq(req_save),
            req_final_answer_ready.eq(req_ready),
            inc_start.eq(0),
            insert_incrementing.eq(inc_start),
            insert_writing.eq(insert_incrementing),
        ]

        m.d.sync += mem_idx.eq(mem_idx_next)
        m.d.sync += mem_idx_before.eq(mem_idx)
        m.d.sync += [
            req_adress_before.eq(req_address),
            req_adress_before_before.eq(req_adress_before),
        ]
        address_mask = (1 << self.log_block_size) - 1

        with Transaction().body(m):
            res = self.query_hash.result(m)
            m.d.sync += req_address.eq(res["hash"] & address_mask)
            with m.If(res["valid"]):
                for i, rd in enumerate(self._read_ports):
                    m.d.sync += rd.addr.eq(res["hash"] & address_mask)
                m.d.sync += [
                    req_start.eq(1),
                    mem_idx_next.eq((res["hash"] >> self.log_block_size)),
                ]

        for i, (rmul, rmulb) in enumerate(zip(read_mult, read_mult_before)):
            m.d.sync += rmul.eq(mem_idx == i)
            m.d.sync += rmulb.eq(rmul)

        for req_read, rd in zip(req_read_value, self._read_ports):
            m.d.sync += req_read.eq(rd.data)

        write_addr_next_next = Signal(self.log_block_size)
        write_addr_next = Signal(self.log_block_size)
        write_addr = Signal(self.log_block_size)

        m.d.sync += write_addr_next.eq(write_addr_next_next)
        m.d.sync += write_addr.eq(write_addr_next)
        with Transaction().body(m):
            res = self.insert_hash.result(m)
            with m.If(res["valid"]):
                for i, rd in enumerate(self._read_ports):
                    m.d.sync += rd.addr.eq(res["hash"] & address_mask)
                m.d.sync += [
                    inc_start.eq(1),
                    mem_idx_next.eq((res["hash"] >> self.log_block_size)),
                    write_addr_next_next.eq(res["hash"] & address_mask),
                ]

        extra_add_write = Signal()
        m.d.sync += extra_add_write.eq(0)
        with m.If(
            insert_writing
            & (write_addr_next == write_addr)
            & (mem_idx == mem_idx_before)
        ):
            m.d.sync += extra_add_write.eq(1)

        for rmul, req_read, wr in zip(read_mult, req_read_value, self._write_ports):
            with m.If(rmul):
                m.d.sync += wr.data.eq(req_read + 1 + extra_add_write)
                m.d.sync += [wr.en.eq(insert_writing), wr.addr.eq(write_addr)]

        with m.If(clr_waiting > 0):
            m.d.sync += clr_waiting.eq(clr_waiting - 1)
            with m.If(clr_waiting == 1):
                m.d.sync += clr_running.eq(1)
                for wr in self._write_ports:
                    m.d.sync += [
                        wr.en.eq(1),
                        wr.addr.eq(0),
                        wr.data.eq(0),
                    ]
        with m.If(clr_running):
            for wr in self._write_ports:
                m.d.sync += wr.addr.eq(wr.addr + 1)
                m.d.sync += wr.data.eq(0)
                m.d.sync += wr.en.eq(1)
                with m.If(wr.addr == (1 << self.log_block_size) - 2):
                    m.d.sync += clr_running.eq(0)

        @def_method(m, self.insert)
        def _(data):
            self.insert_hash.input(m, data)

        req_answer = Signal(self.counter_width)
        add_inc_before = Signal()
        add_inc_before2 = Signal()

        m.d.sync += add_inc_before.eq(0)
        m.d.sync += add_inc_before2.eq(0)
        for i, wr in enumerate(self._write_ports):
            with m.If(wr.en & (wr.addr == req_adress_before) & (i == mem_idx)):
                m.d.sync += add_inc_before.eq(1)
        with m.If(
            insert_writing
            & (req_adress_before == write_addr)
            & (mem_idx == mem_idx_before)
        ):
            m.d.sync += add_inc_before2.eq(1)

        for rmul, wr, rw in zip(read_mult, self._write_ports, req_read_value):
            with m.If(rmul):
                m.d.sync += req_answer.eq(rw + add_inc_before + add_inc_before2)

        @def_method(m, self.query_resp)
        def _():
            return {"count": req_answer, "valid": req_final_answer_ready}

        @def_method(m, self.query_req)
        def _(data):
            self.query_hash.input(m, data)

        @def_method(m, self.clear)
        def _():
            m.d.sync += clr_addr.eq(0)
            m.d.sync += clr_waiting.eq(20)

        return m
