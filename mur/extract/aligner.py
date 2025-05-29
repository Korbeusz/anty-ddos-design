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
        self.layouts = ProtoParserLayouts()

        self.din = Method(i=self.layouts.parser_out_layout)
        self.dout = Method(o=self.layouts.align_out_layout)

        self.params = Params()

    def elaborate(self, platform):
        m = TModule()

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
        buffer_v = Signal()

        state_int = [Signal(self.layouts.parser_out_layout) for _ in range(2**4)]
        state_int_v = [Signal() for _ in range(2**4)]

        @def_method(m, self.dout, ready=output_v)
        def _():

            with m.If(buffer_end_pending_flag):
                m.d.sync += buffer_end_pending_flag.eq(0)
                m.d.sync += buffer_end_pending.eq(0)
                m.d.sync += buffer_v.eq(0)
                m.d.sync += output_v.eq(1)
                m.d.sync += output_end_of_packet_flag.eq(1)
                m.d.sync += output_end_of_packet.eq(buffer_end_pending)
                m.d.sync += output.eq(buffer)
            with m.Else():
                m.d.sync += output_v.eq(0)
                m.d.sync += output_end_of_packet_flag.eq(0)
                m.d.sync += output_end_of_packet.eq(0)
                m.d.sync += output.eq(0)

            return {
                "data": output,
                "end_of_packet": output_end_of_packet_flag,
                "end_of_packet_len": output_end_of_packet,
            }

        parser_fwd = Signal()
        r_size = Signal(range(octet_count // 2 + 1))
        remain = Signal(range(octet_count // 2 + 1))

        m.d.sync += state_int_v[len(state_int_v) - 1].eq(0)
        with m.If(state_int_v[len(state_int_v) - 1]):
            with m.If(parser_fwd):

                # l_size = ((octet_count - buffer_consumed) * octet_bits).as_unsigned()
                # r_size = (buffer_consumed * octet_bits).as_unsigned()
                # mask = (1 << l_size) - 1
                # m.d.sync += output.eq(buffer & mask | data << l_size)

                for i in range(octet_count // 2):
                    with m.If(i < remain):
                        m.d.sync += output.word_select(i, 16).eq(
                            buffer.word_select(i, 16)
                        )
                    with m.Else():
                        m.d.sync += output.word_select(i, 16).eq(
                            state_int[len(state_int) - 1].data.word_select(
                                (i - remain).as_unsigned(), 16
                            )
                        )
                m.d.sync += output_v.eq(1)

                with m.If(state_int[len(state_int) - 1].end_of_packet):
                    m.d.sync += parser_fwd.eq(0)
                    with m.If(
                        state_int[len(state_int) - 1].end_of_packet_len
                        <= buffer_consumed
                    ):
                        m.d.sync += output_end_of_packet.eq(
                            state_int[len(state_int) - 1].end_of_packet_len
                            + (octet_count - buffer_consumed)
                        )
                        m.d.sync += output_end_of_packet_flag.eq(1)
                        m.d.sync += buffer_v.eq(0)
                    with m.Else():
                        m.d.sync += buffer.eq(
                            state_int[len(state_int) - 1].data >> (r_size << 4)
                        )
                        m.d.sync += buffer_v.eq(1)
                        m.d.sync += buffer_end_pending_flag.eq(1)
                        m.d.sync += buffer_end_pending.eq(
                            state_int[len(state_int) - 1].end_of_packet_len
                            - buffer_consumed
                        )
                with m.Else():
                    m.d.sync += buffer.eq(
                        state_int[len(state_int) - 1].data >> (r_size << 4)
                    )
                    with m.If(output_v):
                        m.d.sync += buffer_v.eq(1)

            with m.Elif(state_int[len(state_int) - 1].extract_range_end):
                m.d.sync += parser_fwd.eq(~state_int[len(state_int) - 1].end_of_packet)

                with m.If(
                    state_int[len(state_int) - 1].error_drop
                ):  # Drop errors should be forwarded in result flow
                    # output buffer is already in clean state
                    m.d.sync += parser_fwd.eq(
                        0
                    )  # don't do anything until next extract_range_end
                with m.Elif(
                    state_int[len(state_int) - 1].end_of_packet
                    & ~buffer_end_pending_flag
                    & self.dout.run
                ):
                    m.d.sync += output.eq(state_int[len(state_int) - 1].data)
                    m.d.sync += output_v.eq(1)
                    m.d.sync += output_end_of_packet.eq(
                        state_int[len(state_int) - 1].end_of_packet_len
                        - (state_int[len(state_int) - 1].octets_consumed << 1)
                    )
                    m.d.sync += output_end_of_packet_flag.eq(1)

                with m.Elif(
                    state_int[len(state_int) - 1].end_of_packet
                    & buffer_end_pending_flag
                    & self.dout.run
                ):
                    m.d.sync += buffer.eq(state_int[len(state_int) - 1].data)
                    m.d.sync += buffer_v.eq(1)
                    m.d.sync += buffer_consumed.eq(
                        (state_int[len(state_int) - 1].octets_consumed << 1)
                    )
                    m.d.sync += r_size.eq(state_int[len(state_int) - 1].octets_consumed)
                    m.d.sync += remain.eq(
                        (octet_count >> 1)
                        - state_int[len(state_int) - 1].octets_consumed
                    )
                    m.d.sync += buffer_end_pending_flag.eq(1)
                    m.d.sync += buffer_end_pending.eq(
                        state_int[len(state_int) - 1].end_of_packet_len
                        - (state_int[len(state_int) - 1].octets_consumed << 1)
                    )
                with m.Elif(
                    state_int[len(state_int) - 1].end_of_packet
                    & ~buffer_end_pending_flag
                    & ~self.dout.run
                    & output_v
                ):
                    m.d.sync += buffer.eq(state_int[len(state_int) - 1].data)
                    m.d.sync += buffer_v.eq(1)
                    m.d.sync += buffer_consumed.eq(
                        (state_int[len(state_int) - 1].octets_consumed << 1)
                    )
                    m.d.sync += r_size.eq(state_int[len(state_int) - 1].octets_consumed)
                    m.d.sync += remain.eq(
                        (octet_count >> 1)
                        - state_int[len(state_int) - 1].octets_consumed
                    )
                    m.d.sync += buffer_end_pending_flag.eq(1)
                    m.d.sync += buffer_end_pending.eq(
                        state_int[len(state_int) - 1].end_of_packet_len
                        - (state_int[len(state_int) - 1].octets_consumed << 1)
                    )
                with m.Elif(
                    state_int[len(state_int) - 1].end_of_packet
                    & ~buffer_end_pending_flag
                    & ~self.dout.run
                    & ~output_v
                ):
                    m.d.sync += output.eq(state_int[len(state_int) - 1].data)
                    m.d.sync += output_v.eq(1)
                    m.d.sync += output_end_of_packet.eq(
                        state_int[len(state_int) - 1].end_of_packet_len
                        - (state_int[len(state_int) - 1].octets_consumed << 1)
                    )
                    m.d.sync += output_end_of_packet_flag.eq(1)
                with m.Else():
                    m.d.sync += buffer.eq(state_int[len(state_int) - 1].data)
                    m.d.sync += buffer_v.eq(1)
                    m.d.sync += buffer_consumed.eq(
                        (state_int[len(state_int) - 1].octets_consumed << 1)
                    )
                    m.d.sync += r_size.eq(state_int[len(state_int) - 1].octets_consumed)
                    m.d.sync += remain.eq(
                        (octet_count >> 1)
                        - state_int[len(state_int) - 1].octets_consumed
                    )

            with m.Else():
                m.d.sync += buffer_consumed.eq(octet_count)
                m.d.sync += r_size.eq(octet_count >> 1)
                m.d.sync += remain.eq(0)

        for i in range(len(state_int)):
            if i != 0:
                m.d.sync += state_int[i].data.eq(
                    state_int[i - 1].data >> state_int[i - 1].octets_consumed
                )
                m.d.sync += state_int[i].octets_consumed.eq(
                    state_int[i - 1].octets_consumed
                )
                m.d.sync += state_int[i].extract_range_end.eq(
                    state_int[i - 1].extract_range_end
                )
                m.d.sync += state_int[i].next_proto.eq(state_int[i - 1].next_proto)
                m.d.sync += state_int[i].end_of_packet.eq(
                    state_int[i - 1].end_of_packet
                )
                m.d.sync += state_int[i].end_of_packet_len.eq(
                    state_int[i - 1].end_of_packet_len
                )
                m.d.sync += state_int[i].error_drop.eq(state_int[i - 1].error_drop)

                m.d.sync += state_int_v[i].eq(state_int_v[i - 1])
            else:
                m.d.sync += state_int[i].eq(0)
                m.d.sync += state_int_v[i].eq(0)

        @def_method(m, self.din)
        def _(
            data,
            octets_consumed,
            extract_range_end,
            next_proto,
            end_of_packet,
            end_of_packet_len,
            error_drop,
        ):
            with m.If(extract_range_end):
                m.d.sync += state_int[0].data.eq(data >> octets_consumed)
            with m.Else():
                m.d.sync += state_int[0].data.eq(data)
            m.d.sync += state_int[0].octets_consumed.eq(octets_consumed)
            m.d.sync += state_int[0].extract_range_end.eq(extract_range_end)
            m.d.sync += state_int[0].next_proto.eq(next_proto)
            m.d.sync += state_int[0].end_of_packet.eq(end_of_packet)
            m.d.sync += state_int[0].end_of_packet_len.eq(end_of_packet_len)
            m.d.sync += state_int[0].error_drop.eq(error_drop)

            m.d.sync += state_int_v[0].eq(1)

        return m
