from amaranth import *
from transactron import *
from transactron.core import Transaction
from transactron.core import *
from transactron.lib.fifo import BasicFifo
from transactron.lib.simultaneous import condition
from mur.count.RollingCountMinSketch import RollingCountMinSketch
from mur.count.VolCounter import VolCounter

#from transactron.lib import logging

#log = logging.HardwareLogger("cmsvolcontroller")
__all__ = ["CMSVolController"]


class CMSVolController(Elaboratable):
    """
    CMSVolController is a controller that manages the interaction between
    multiple CountMinSketch instances and a volume counter. It allows for
    inserting data into the sketches, querying the counts, and managing
    the volume counter. The controller uses a FIFO to manage the data flow
    and a rolling count-min sketch to maintain the counts.

    Attributes
    ----------
        depth (int): Number of hash tables (rows) in the sketch.
        width (int): The size of CountHashTab (number of hash buckets).
        counter_width (int): Number of bits in each counter.
        hash_params (list[tuple[int, int]] | None): List of tuples containing
            hash coefficients (a, b) for each row. If None, default values are used.
        discard_threshold (int): If the sum of the counts is lower than this threshold,
            then the corresponding packet values have not been seen in the window before
            so the packet is discarded.
        window (int): The size of the sliding window for the volume counter.
        volume_threshold (int): The threshold for the volume counter.
        fifo_depth (int): The depth of the FIFO used for data flow management.

    Methods
    -------
        push_a(data: int): Push source IP address into the FIFO. (32 bits)
        push_b(data: int): Push destination IP address into the FIFO. (32 bits)
        push_c(data: int): Push destination port into the FIFO. (16 bits)
        push_s(data: int): Push packet length into the FIFO. (16 bits)
        out(): Get the output from the FIFO. (32 bits)
    """

    def __init__(
        self,
        *,
        depth: int = 4,
        width: int = 32,
        counter_width: int = 32,
        hash_params: list[tuple[int, int]] | None = None,
        discard_threshold: int = 0,
        window: int = 1024,
        volume_threshold: int = 10_000,
        fifo_depth: int = 16,
    ) -> None:

        self.discover_threshold = discard_threshold
        lay32 = [("data", 32)]
        lay16 = [("data", 16)]
        lay5 = [("data", 5)]

        self._fifo_sip = BasicFifo(lay32, fifo_depth)
        self._fifo_dip = BasicFifo(lay32, fifo_depth)
        self._fifo_dport = BasicFifo(lay16, fifo_depth)
        self._fifo_len = BasicFifo(lay16, fifo_depth)
        self._fifo_out = BasicFifo(lay5, fifo_depth)
        self.out = self._fifo_out.read

        self.push_a = self._fifo_sip.write
        self.push_b = self._fifo_dip.write
        self.push_c = self._fifo_dport.write
        self.push_s = self._fifo_len.write

        self._insert_requested = Signal(32)
        self._query_requested = Signal(32)
        self._insert_received = Signal(32)
        self._query_received = Signal(32)

        self.rcms_sipdip = RollingCountMinSketch(
            depth=depth,
            width=width,
            counter_width=counter_width,
            input_data_width=32 + 32,
            hash_params=hash_params,
        )
        self.rcms_dportdip = RollingCountMinSketch(
            depth=depth,
            width=width,
            counter_width=counter_width,
            input_data_width=16 + 32,
            hash_params=hash_params,
        )
        self.rcms_siplen = RollingCountMinSketch(
            depth=depth,
            width=width,
            counter_width=counter_width,
            input_data_width=32 + 16,
            hash_params=hash_params,
        )
        self.vcnt = VolCounter(
            window=window,
            threshold=volume_threshold,
            input_width=16,
        )

    def elaborate(self, platform):
        m = TModule()

        m.submodules += [
            self._fifo_sip,
            self._fifo_dip,
            self._fifo_dport,
            self._fifo_len,
            self._fifo_out,
            self.vcnt,
            self.rcms_sipdip,
            self.rcms_dportdip,
            self.rcms_siplen,
        ]

        self._current_mode = Signal(1)
        with Transaction().body(m):
            sip = self._fifo_sip.read(m)
            dip = self._fifo_dip.read(m)
            dport = self._fifo_dport.read(m)
            s = self._fifo_len.read(m)

            self._current_mode = self.rcms_sipdip.input(
                m, data=Cat(sip["data"], dip["data"])
            )["mode"]
            self.rcms_dportdip.input(m, data=Cat(dport["data"], dip["data"]))
            self.rcms_siplen.input(m, data=Cat(sip["data"], s["data"]))
            with m.If(self._current_mode == 0):
                m.d.sync += self._insert_requested.eq(self._insert_requested + 1)
            with m.Else():
                m.d.sync += self._query_requested.eq(self._query_requested + 1)
            self.vcnt.add_sample(m, data=s["data"])

        with Transaction().body(m):
            res = self.vcnt.result(m)
            self.rcms_sipdip.set_mode(m, mode=res["mode"])
            self.rcms_dportdip.set_mode(m, mode=res["mode"])
            self.rcms_siplen.set_mode(m, mode=res["mode"])
            with m.If(res["mode"] == 0):
                self.rcms_sipdip.change_roles(m)
                self.rcms_dportdip.change_roles(m)
                self.rcms_siplen.change_roles(m)

        self._inserts_difference = Signal(5)
        m.d.comb += self._inserts_difference.eq(
            self._insert_requested - self._insert_received
        )
        self._all_query_received = Signal(1)
        m.d.comb += self._all_query_received.eq(
            self._query_requested == self._query_received
        )
        self._query_decision = Signal(32)
        self._out = Signal(5)
        self._out_valid = Signal(1)
        # for now design is simplified it should be sum calculated in pipeline
        q1_data = Signal()
        q2_data = Signal()
        q3_data = Signal()
        q_valid = Signal(1)
        m.d.sync += self._out_valid.eq(0)
        with Transaction().body(m):
            q = self.rcms_sipdip.output(m)
            m.d.sync += q1_data.eq((q["count"] > self.discover_threshold))
            m.d.sync += q2_data.eq(
                self.rcms_dportdip.output(m)["count"] > self.discover_threshold
            )
            m.d.sync += q3_data.eq(
                self.rcms_siplen.output(m)["count"] > self.discover_threshold
            )
            m.d.sync += q_valid.eq(q["valid"])
            #log.debug(m, q["valid"], "{:x}", q1_data | q2_data | q3_data)

        with m.If(self._all_query_received & self._inserts_difference):
            m.d.sync += self._out.eq(self._inserts_difference)
            m.d.sync += self._insert_received.eq(self._insert_requested)
            m.d.sync += self._out_valid.eq(1)
        with m.If(~self._all_query_received & q_valid):
            m.d.sync += self._out_valid.eq(1)
            m.d.sync += self._query_received.eq(self._query_received + 1)
            m.d.sync += self._out.eq(q1_data | q2_data | q3_data)
        with Transaction().body(m, request=self._out_valid):

            self._fifo_out.write(m, {"data": self._out})

        return m
