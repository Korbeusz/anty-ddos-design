from amaranth import *
from transactron.core import *
from transactron.utils.transactron_helpers import make_layout
from mur.utils import select_field_be
from mur.extract.interfaces import ProtoParserLayouts

class TCPParser(Elaboratable):
    class ResultLayouts:
        def __init__(self):
            # Define the layout of the TCP header fields
            self.fields = make_layout(
                ("source_port", 16),          # Bits 0-15
                ("destination_port", 16),     # Bits 16-31
                ("sequence_number", 32),      # Bits 32-63
                ("acknowledgment_number", 32),# Bits 64-95
                ("data_offset", 4),           # Bits 96-99
                ("reserved", 4),              # Bits 100-103
                ("flags", 8),                 # Bits 104-111
                ("window_size", 16),          # Bits 112-127
                ("checksum", 16),             # Bits 128-143
                ("urgent_pointer", 16),       # Bits 144-159
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

            # Extract byte 12 (bits 96-103) for data_offset and reserved
            byte12 = Signal(8)
            m.d.av_comb += select_field_be(m, byte12, data, 96)  # byte12 = data[96:104]

            # Assign data_offset (high 4 bits) and reserved (low 4 bits)
            m.d.av_comb += parsed.data_offset.eq(byte12[4:8])  # Corrected: bits 4-7
            m.d.av_comb += parsed.reserved.eq(byte12[0:4])     # Corrected: bits 0-3

            # Extract fields with widths divisible by 8 using select_field_be
            m.d.av_comb += [
                select_field_be(m, parsed.source_port, data, 0),          # 16 bits
                select_field_be(m, parsed.destination_port, data, 16),    # 16 bits
                select_field_be(m, parsed.sequence_number, data, 32),     # 32 bits
                select_field_be(m, parsed.acknowledgment_number, data, 64),# 32 bits
                select_field_be(m, parsed.flags, data, 104),              # 8 bits
                select_field_be(m, parsed.window_size, data, 112),        # 16 bits
                select_field_be(m, parsed.checksum, data, 128),           # 16 bits
                select_field_be(m, parsed.urgent_pointer, data, 144),     # 16 bits
            ]

            # Calculate header lengtha in bytes (data_offset * 4)
            header_length_bytes = parsed.data_offset * 4

            # Check for runt packet
            m.d.av_comb += runt_packet.eq(((header_length_bytes > end_of_packet_len) | (end_of_packet_len < 20)) & end_of_packet)
            m.d.sync += parsing_finished.eq(~end_of_packet)

            # Push parsed fields when parsing is not finished
            with m.If(~parsing_finished):
                self.push_parsed(m, fields=parsed, error_drop=runt_packet)

            return {
                "data": data,
                "octets_consumed": header_length_bytes,
                "extract_range_end": ~parsing_finished,
                "next_proto": 0 ,
                "end_of_packet_len": end_of_packet_len,
                "end_of_packet": end_of_packet,
                "error_drop": runt_packet,
            }

        return m