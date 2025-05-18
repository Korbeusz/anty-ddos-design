from amaranth import *
from amaranth.lib.wiring import In, Out, Component

from transactron.core import *
from transactron.lib.connectors import Connect
from transactron.lib.fifo import BasicFifo
from transactron.lib.simultaneous import condition

from mur.extract.interfaces import ProtoParserLayouts
from mur.extract.parsers.ethernet import EthernetParser
from mur.extract.aligner import ParserAligner
from synth_examples.genverilog import gen_verilog


class ParserStepTop(Component):
    def __init__(self):
        self.layouts = ProtoParserLayouts()
        super().__init__(
            {
                # "inp": In(self.layouts.align_out_layout),
                "inp": In(320 + 6 + 2),
                "in_v": In(1),
                # "out": Out(self.layouts.align_out_layout),
                "out": Out(100),
                # "pout1": Out(EthernetParser.LAYOUT),
                "pout1": Out(EthernetParser.LAYOUT),
                # "pout2": Out(EthernetParser.LAYOUT),
                "pout2": Out(8),
            }
        )

    def elaborate(self, platform):
        m = TModule()

        m.submodules.fifo_in = fifo_in = BasicFifo(self.layouts.align_out_layout, 2)

        m.submodules.parser0_in = parser0_in = Connect(self.layouts.parser_in_layout)
        m.submodules.parser1_in = parser1_in = Connect(self.layouts.parser_in_layout)

        m.submodules.parser0_out = parser0_out = Connect(self.layouts.parser_out_layout)
        m.submodules.parser1_out = parser1_out = Connect(self.layouts.parser_out_layout)

        m.submodules.parser0_pout = parser0_pout = Connect(EthernetParser.LAYOUT)
        m.submodules.parser1_pout = parser1_pout = Connect(EthernetParser.LAYOUT)

        m.submodules.parser0 = EthernetParser(
            parser0_in.read, parser0_out.write, parser0_pout.write
        )
        m.submodules.parser1 = EthernetParser(
            parser1_in.read, parser1_out.write, parser1_pout.write
        )

        m.submodules.aligner = aligner = ParserAligner()

        with Transaction().body(m):
            packet = fifo_in.read(m)

            with condition(m) as cond:
                with cond(packet.next_proto == 1):
                    parser0_in.write(m, packet)
                    aligner.din(m, parser0_out.read(m))

                with cond(packet.next_proto == 2):
                    parser1_in.write(m, packet)
                    aligner.din(m, parser1_out.read(m))

        with Transaction().body(m, request=self.in_v):
            cast = Signal(fifo_in.layout)
            m.d.comb += cast.eq(self.inp)
            fifo_in.write(m, cast)

        with Transaction().body(m):
            m.d.sync += self.out.eq(aligner.dout(m))
            m.d.sync += self.pout1.eq(parser0_pout.read(m))
            m.d.sync += self.pout2.eq(parser1_pout.read(m))

        return m


if __name__ == "__main__":
    gen_verilog(ParserStepTop(), "parserstep.v")
