from amaranth import *

from transactron import *
from transactron.lib.connectors import ConnectTrans, Forwarder

from mur.params import Params
from .interfaces import ProtoParserLayouts


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
        m.submodules.din_forwarder_connector = ConnectTrans(
            self.din_forwarder.read, self.din_int
        )

        buffer = Signal(self.params.word_bits)
        buffer_consumed = Signal(
            range(self.params.word_bits // 8 + 1)
        )  # Octet precision
        buffer_end_pending = Signal(
            range(self.params.word_bits // 8 + 1)
        )  # Octet precision
        buffer_end_pending_flag = Signal()

        output = Signal(self.params.word_bits)
        output_end_of_packet = Signal(
            range(self.params.word_bits // 8 + 1)
        )  # Octet precision
        output_end_of_packet_flag = Signal()
        output_next_protocol = Signal(self.params.next_proto_bits)
        output_v = Signal()

        octet_bits = 8  # Single octet (1 byte)
        octet_count = self.params.word_bits // octet_bits  # Number of octets in a word

        @def_method(m, self.dout, ready=output_v | buffer_end_pending_flag)
        def _():
            m.d.sync += output_v.eq(0)
            with m.If(~output_v):
                m.d.sync += buffer_end_pending_flag.eq(0)
                m.d.sync += buffer_end_pending.eq(0)
            m.d.sync += output_end_of_packet_flag.eq(0)
            m.d.sync += output_end_of_packet.eq(0)

            end_of_packet_len = Mux(output_v, output_end_of_packet, buffer_end_pending)
            end_of_packet_flag = Mux(
                output_v, output_end_of_packet_flag, buffer_end_pending_flag
            )

            return {
                "data": Mux(output_v, output, buffer),
                "next_proto": output_next_protocol,
                "end_of_packet": end_of_packet_flag,
                "end_of_packet_len": end_of_packet_len,
            }

        parser_fwd = Signal()
        r_size = Signal(range(octet_count * octet_bits + 1))
        l_size = Signal(range(octet_count * octet_bits + 1))
        mask = Signal(self.params.word_bits)
        remain = Signal(range(octet_count + 1))

        # second ready condition may be replaced with assert
        @def_method(
            m,
            self.din_int,
            ready=~buffer_end_pending_flag,
        )
        def _(
            data,
            octets_consumed,
            extract_range_end,
            next_proto,
            end_of_packet,
            end_of_packet_len,
            error_drop,
        ):
            with m.If(parser_fwd):

                # l_size = ((octet_count - buffer_consumed) * octet_bits).as_unsigned()
                # r_size = (buffer_consumed * octet_bits).as_unsigned()
                # mask = (1 << l_size) - 1
                m.d.sync += output.eq(buffer & mask | data << l_size)

                # for i in range(octet_count):
                #     with m.If(i < remain):
                #         m.d.sync += output.word_select(i, 8).eq(
                #             buffer.word_select(i, 8)
                #         )
                #     with m.Else():
                #         m.d.sync += output.word_select(i, 8).eq(
                #             data.word_select((i - remain).as_unsigned(), 8)
                #         )
                m.d.sync += output_v.eq(1)

                with m.If(end_of_packet):
                    m.d.sync += parser_fwd.eq(0)
                    with m.If(end_of_packet_len <= buffer_consumed):
                        m.d.sync += output_end_of_packet.eq(
                            end_of_packet_len + (octet_count - buffer_consumed)
                        )
                        m.d.sync += output_end_of_packet_flag.eq(1)
                    with m.Else():
                        m.d.sync += buffer.eq(data >> r_size)
                        m.d.sync += buffer_end_pending_flag.eq(1)
                        m.d.sync += buffer_end_pending.eq(
                            end_of_packet_len - buffer_consumed
                        )
                with m.Else():
                    m.d.sync += buffer.eq(data >> r_size)

            with m.Elif(extract_range_end):
                m.d.sync += parser_fwd.eq(~end_of_packet)
                m.d.sync += output_next_protocol.eq(next_proto)

                with m.If(error_drop):  # Drop errors should be forwarded in result flow
                    # output buffer is already in clean state
                    m.d.sync += parser_fwd.eq(
                        0
                    )  # don't do anything until next extract_range_end
                with m.Elif(end_of_packet):
                    m.d.sync += output.eq(data >> (octets_consumed << 3))
                    m.d.sync += output_v.eq(1)
                    m.d.sync += output_end_of_packet.eq(
                        end_of_packet_len - octets_consumed
                    )
                    m.d.sync += output_end_of_packet_flag.eq(1)
                with m.Else():
                    m.d.sync += buffer.eq(data >> (octets_consumed << 3))
                    m.d.sync += buffer_consumed.eq(octets_consumed)
                    m.d.sync += r_size.eq(octets_consumed * octet_bits)
                    m.d.sync += l_size.eq(((octet_count - octets_consumed) << 3))
                    m.d.sync += mask.eq(
                        (1 << ((octet_count - octets_consumed) << 3).as_unsigned()) - 1
                    )
                    m.d.sync += remain.eq(octet_count - octets_consumed)

            with m.Else():
                m.d.sync += buffer_consumed.eq(octet_count)
                m.d.sync += r_size.eq(octet_count * octet_bits)
                m.d.sync += l_size.eq(0)
                m.d.sync += mask.eq(0)
                m.d.sync += remain.eq(0)

        return m
