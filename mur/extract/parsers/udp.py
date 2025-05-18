from amaranth import *
from transactron.core import *
from transactron.utils.transactron_helpers import make_layout
from mur.utils import select_field_be
from mur.extract.interfaces import ProtoParserLayouts


class UDPParser(Elaboratable):
    class ResultLayouts:
        def __init__(self):
            # Define the layout of the UDP header fields
            self.fields = make_layout(
                ("source_port", 16),  # Bits 0-15
                ("destination_port", 16),  # Bits 16-31
                ("length", 16),  # Bits 32-47
                ("checksum", 16),  # Bits 48-63
            )

    def __init__(self, push_parsed: Method):
        self.push_parsed = push_parsed
        layouts = ProtoParserLayouts()
        self.step = Method(i=layouts.parser_in_layout, o=layouts.parser_out_layout)

    def elaborate(self, platform):
        m = TModule()
        parsing_finished = Signal()

        @def_method(m, self.step)
        def _(data, end_of_packet, end_of_packet_len):
            result_layouts = self.ResultLayouts()
            parsed = Signal(result_layouts.fields)
            runt_packet = Signal()

            # Extract UDP header fields
            m.d.av_comb += [
                select_field_be(m, parsed.source_port, data, 0),  # 16 bits
                select_field_be(m, parsed.destination_port, data, 16),  # 16 bits
                select_field_be(m, parsed.length, data, 32),  # 16 bits
                select_field_be(m, parsed.checksum, data, 48),  # 16 bits
            ]

            # Check for runt packet (less than 8 bytes)
            m.d.av_comb += runt_packet.eq((end_of_packet_len < 8) & end_of_packet)

            # Update parsing state
            m.d.sync += parsing_finished.eq(~end_of_packet)

            # Push parsed fields for the first chunk
            with m.If(~parsing_finished):
                self.push_parsed(m, fields=parsed, error_drop=runt_packet)

            # Set octets_consumed: 8 for first chunk if not runt, 0 otherwise
            octets_consumed = Mux(~parsing_finished & ~runt_packet, 8, 0)

            return {
                "data": data,
                "octets_consumed": octets_consumed,
                "extract_range_end": ~parsing_finished,
                "next_proto": 0,
                "end_of_packet_len": end_of_packet_len,
                "end_of_packet": end_of_packet,
                "error_drop": runt_packet,
            }

        return m
