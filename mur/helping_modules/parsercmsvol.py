from amaranth import *
from amaranth.lib.wiring import Component, In, Out
from transactron.core import TModule

from mur.final_build.ParserCMSVol import ParserCMSVol
from mur.extract.interfaces import ProtoParserLayouts
from synth_examples.genverilog import gen_verilog


class ParserCMSVolModule(Component):
    """Top wrapper placing :class:`ParserCMSVol` between two FIFOs.

    The external interface mirrors the original ``placeholder_module`` so that
    the generated Verilog can drop into ``alt_e100s20.v`` in the same spot.
    Input and output words are 520 bits wide with SOP/EOP/EMPTY fields encoded
    as in the vendor design.
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

        layouts = ProtoParserLayouts()
        parser = ParserCMSVol()
        m.submodules.parser = parser

        # Default strobes
        m.d.sync += [self.rd_en_fifo.eq(0), self.wr_en_fifo.eq(0)]

        # Break input word into fields ---------------------------------
        sop = self.in_data[519]
        eop = self.in_data[518]
        empty = self.in_data[512:518]
        dat = self.in_data[0:512]

        eop_len = Signal(7)
        m.d.comb += eop_len.eq(Mux(eop, 64 - empty, 0))

        # Simple ready/valid sequencing --------------------------------
        with m.If(self.in_valid & ~self.out_full):
            parser.din(m, {"data": dat, "end_of_packet": eop, "end_of_packet_len": eop_len})
            out = parser.dout(m)
            m.d.sync += [
                self.out_data.eq(
                    Cat(out["data"], out["end_of_packet_len"], out["end_of_packet"], sop)
                ),
                self.wr_en_fifo.eq(1),
            ]
        with m.Elif(~self.in_valid & ~self.in_empty & ~self.out_full):
            m.d.sync += self.rd_en_fifo.eq(1)

        return m


if __name__ == "__main__":
    gen_verilog(ParserCMSVolModule(), "parsercmsvol.v")
