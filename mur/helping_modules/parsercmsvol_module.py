from amaranth import *
from amaranth.lib.wiring import Component, In, Out
from transactron.core import TModule, Transaction

from mur.final_build.ParserCMSVol import ParserCMSVol
from mur.params import Params
from synth_examples.genverilog import gen_verilog


class ParserCMSVolModule(Component):
    """Wrapper around :class:`ParserCMSVol` with a 520‑bit FIFO interface.

    The ports mirror those of :class:`PlaceholderModule` so the generated
    Verilog can drop into the same spot in ``alt_e100s20.v`` between the RX
    and TX async FIFOs.
    """

    def __init__(self):
        super().__init__(
            {
                "clk": In(1),
                "rst_n": In(1),
                "in_data": In(520),
                "in_valid": In(1),
                "in_empty": In(1),
                "rd_en_fifo": Out(1),
                "out_data": Out(520),
                "wr_en_fifo": Out(1),
                "out_full": In(1),
            }
        )

    def elaborate(self, platform):
        m = TModule()

        m.submodules.core = core = ParserCMSVol()
        word_bits = Params().word_bits  # 512

        # ------------------------------------------------------------------
        #  Input path: convert 520-bit FIFO word to ParserCMSVol layout
        # ------------------------------------------------------------------
        eop = self.in_data[518]
        empty = self.in_data[512:518]
        payload = self.in_data[0:512]

        eop_len = Signal(range(0, (word_bits // 8) + 1))
        m.d.comb += eop_len.eq(Mux(eop, (word_bits // 8) - empty, 0))

        # Default handshake outputs
        m.d.sync += [self.rd_en_fifo.eq(0), self.wr_en_fifo.eq(0)]

        with Transaction().body(m, request=self.in_valid & core.din.ready):
            core.din(
                m,
                {
                    "data": payload,
                    "end_of_packet": eop,
                    "end_of_packet_len": eop_len,
                },
            )
            m.d.sync += self.rd_en_fifo.eq(1)

        # ------------------------------------------------------------------
        #  Output path: convert ParserCMSVol word back to 520-bit format
        # ------------------------------------------------------------------
        in_packet = Signal(reset=0)

        with Transaction().body(m, request=core.dout.ready & ~self.out_full):
            word = core.dout(m)
            empty_out = (
                word["end_of_packet"].as_unsigned()
                * ((word_bits // 8) - word["end_of_packet_len"])
            )
            sop_out = ~in_packet
            m.d.sync += [
                self.out_data.eq(
                    Cat(
                        word["data"],
                        empty_out[:6],
                        word["end_of_packet"],
                        sop_out,
                    )
                ),
                self.wr_en_fifo.eq(1),
                in_packet.eq(~word["end_of_packet"]),
            ]

        with m.If(~self.rst_n):
            m.d.sync += in_packet.eq(0)

        return m


if __name__ == "__main__":
    gen_verilog(ParserCMSVolModule(), "parsercmsvol_module.v")
