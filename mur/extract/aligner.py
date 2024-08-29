from amaranth import *
from transactron import *
from transactron.lib import logging

from mur.params import Params
from transactron.lib.connectors import ConnectTrans, Forwarder
from .interfaces import ProtoParserLayouts

log = logging.HardwareLogger("extract.aligner")


class ParserAligner(Elaboratable):
    """
    Pipeline step between packet extractors

    Take word of data with variable length of bytes consumed, and
    merge it with prefix (while buffering rest of bytes) of next word to produce full word of data

    Assumed stages of flow of data:
    1) Extractor on input consumes 0 or more full words of data
    2) At end of extractor range, only once, it consumes partial word of data.
    3) All next words are fully forwarded to next extractor (consumed = 0), and should be re-aligned to LSB
    """

    def __init__(self):
        layouts = ProtoParserLayouts()

        self.din_forwarder = Forwarder(layouts.parser_out_layout)
        self.din = self.din_forwarder.write

        self.din_int = Method(i=layouts.parser_out_layout)
        self.dout = Method(o=layouts.align_out_layout)

        self.params = Params()

    def elaborate(self, platform):
        m = TModule()

        # Forwarder is needed to hold input when buffer_end_pending condition is produced.
        # it should not limit throughput as it balances out with output data
        m.submodules.din_forwarder = self.din_forwarder
        m.submodules.din_forwarder_connector = ConnectTrans(self.din_forwarder.read, self.din_int)

        buffer = Signal(self.params.word_bits)
        buffer_consumed = Signal(range(self.params.word_bits // 8 + 1))
        buffer_end_pending = Signal(range(self.params.word_bits // 8 + 1))

        output = Signal(self.params.word_bits)
        output_end_of_packet = Signal(range(self.params.word_bits // 8 + 1))
        output_next_protocol = Signal(self.params.next_proto_bits)
        output_error = Signal()
        buffer_error = Signal()
        output_v = Signal()

        quadoctet_bits = 8 * 4
        quadoctet_count = self.params.word_bits // quadoctet_bits

        @def_method(m, self.dout, ready=output_v | buffer_end_pending.any())
        def _():
            m.d.sync += output_v.eq(0)
            with m.If(~output_v):
                m.d.sync += buffer_end_pending.eq(0)
            m.d.sync += output_end_of_packet.eq(0)

            log.debug(m, True, "aligned_output {} {:x} {:x}", output_v, output, buffer)

            end_of_packet = Mux(output_v, output_end_of_packet, buffer_end_pending)

            return {
                "data": Mux(output_v, output, buffer),
                "next_proto": output_next_protocol,
                "end_of_packet": end_of_packet,
                "error": Mux(end_of_packet, Mux(output_v, output_error, buffer_error), 0),
            }

        # second ready condition may be replaced with assert
        @def_method(m, self.din_int, ready=~buffer_end_pending.any() & ~(output_v & ~self.dout.run))
        def _(data, quadoctets_consumed, end_of_packet, next_proto, error):

            with m.If(quadoctets_consumed == 0):
                l_size = ((quadoctet_count - buffer_consumed) * quadoctet_bits).as_unsigned()
                r_size = ((buffer_consumed) * quadoctet_bits).as_unsigned()

                mask = (1 << l_size) - 1
                m.d.sync += output.eq(buffer & mask | data << l_size)

                m.d.sync += output_v.eq(1)

                with m.If(end_of_packet):
                    with m.If(end_of_packet <= buffer_consumed * 4):
                        m.d.sync += output_end_of_packet.eq(end_of_packet + (quadoctet_count - buffer_consumed) * 4)
                        m.d.sync += output_error.eq(error)
                    with m.Else():
                        m.d.sync += buffer.eq(data >> r_size)
                        m.d.sync += buffer_end_pending.eq(end_of_packet - buffer_consumed * 4)
                        m.d.sync += buffer_error.eq(error)
                with m.Else():
                    m.d.sync += buffer.eq(data >> r_size)

            with m.Elif(quadoctets_consumed != quadoctet_count):

                m.d.sync += output_next_protocol.eq(next_proto)

                with m.If(end_of_packet):
                    m.d.sync += output.eq(data >> (quadoctets_consumed * quadoctet_bits))
                    m.d.sync += output_v.eq(1)
                    m.d.sync += output_end_of_packet.eq(end_of_packet - quadoctets_consumed * 4)
                    m.d.sync += output_error.eq(error)
                with m.Else():
                    m.d.sync += buffer.eq(data >> (quadoctets_consumed * quadoctet_bits))
                    m.d.sync += buffer_consumed.eq(quadoctets_consumed)
            with m.Else():
                m.d.sync += buffer_consumed.eq(quadoctet_count)
                m.d.sync += output_next_protocol.eq(next_proto)

            log.debug(
                m, True, "din run \nout {:x} \nbuffer {:x} \nin {:x} c {:x}", output, buffer, data, quadoctets_consumed
            )

        return m
