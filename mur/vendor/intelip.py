from amaranth import *
from amaranth.lib.data import *
from amaranth.lib.wiring import *
from amaranth.lib.fifo import AsyncFIFO
from mur.params import Params

from transactron.core import *

from .interfaces import *
from mur.extract.interfaces import ProtoParserLayouts
from mur.utils import swap_endianess


class IntelAvalonRxAdapter(Component):
    rx: IntelAvalonRxInterface

    def __init__(self):
        super().__init__({"rx": Out(IntelAvalonRxSignature())})

        self.read = Method(o=ProtoParserLayouts().parser_in_layout)

    def elaborate(self, platform):
        m = TModule()

        m.domains.rx = rx = ClockDomain()
        m.d.comb += rx.clk.eq(self.rx.clk_rxmac)
        m.d.comb += rx.rst.eq(ResetSignal())

        fifo_layout = StructLayout({"data": Params().word_bits, "error": 1, "eop": 6})

        m.submodules.rx_fifo = rx_fifo = AsyncFIFO(
            width=fifo_layout.size, depth=2, r_domain="sync", w_domain="rx"
        )

        fifo_in = Signal(fifo_layout)
        m.d.comb += fifo_in.data.eq(self.rx.l8_rx_data)
        m.d.comb += fifo_in.error.eq(
            self.rx.l8.rx_error.any() & self.rx.l8_rx_endofpacket
        )
        m.d.comb += fifo_in.eop.eq(
            Mux(
                self.rx.l8_rx_endofpacket,
                Params().word_bits // 8 - self.rx.l8_rx_empty - 1,
                0,
            )
        )

        m.d.comb += rx_fifo.w_data.eq(
            swap_endianess(m, fifo_in)
        )  # start at MSB -> start at LSB
        m.d.comb += rx_fifo.w_en.eq(self.rx.l8_rx_valid)

        @def_method(m, self.read, ready=rx_fifo.r_rdy)
        def _():
            m.d.comb += rx_fifo.r_en.eq(1)
            fifo_out = View(fifo_layout, rx_fifo.r_data)

            return {
                "data": fifo_out.data,
                "error": fifo_out.error,
                "end_of_packet": fifo_out.eop,
                "next_proto": 0,
            }

        return m


class IntelAvalonTxAdapter(Component):
    tx: IntelAvalonTxInterface

    def __init__(self):
        super().__init__({"tx": Out(IntelAvalonRxSignature())})

        self.write = Method(i=ProtoParserLayouts().tx_layout)

    def elaborate(self, platform):
        m = TModule()

        m.domains.tx = tx = ClockDomain()
        m.d.comb += tx.clk.eq(self.tx.clk_txmac)
        m.d.comb += tx.rst.eq(ResetSignal())

        fifo_layout = StructLayout({"data": Params().word_bits, "eop": 6})

        m.submodules.tx_fifo = tx_fifo = AsyncFIFO(
            width=fifo_layout.size, depth=2, r_domain="sync", w_domain="tx"
        )

        fifo_out = View(fifo_layout, tx_fifo.r_data)

        prev_eop = Signal()
        with m.If(tx_fifo.r_rdy & self.tx.l8_tx_ready):
            # l8_tx_ready is an ack to tx_valid that must be aways asserted if valid
            m.d.comb += tx_fifo.r_en.eq(1)
            m.d.tx += prev_eop.eq(fifo_out.eop.any())

        m.d.comb += self.tx.l8_tx_data.eq(swap_endianess(m, fifo_out.data))
        m.d.comb += self.tx.l8_tx_empty.eq(Params().word_bits // 8 - fifo_out.eop - 1)
        m.d.comb += self.tx.l8_tx_startofpacket.eq(prev_eop)
        m.d.comb += self.tx.l8_tx_endofpacket.eq(fifo_out.eop.any())
        m.d.comb += self.tx.l8_tx_valid.eq(tx_fifo.r_rdy)

        @def_method(m, self.write, ready=tx_fifo.w_rdy)
        def _(data, end_of_packet):
            fifo_in = Signal(fifo_layout)
            m.d.av_comb += fifo_in.data.eq(data)
            m.d.av_comb += fifo_in.eop.eq(end_of_packet)

            m.d.comb += tx_fifo.w_en.eq(1)
            m.d.av_comb += tx_fifo.w_data.eq(fifo_in)

        return m
