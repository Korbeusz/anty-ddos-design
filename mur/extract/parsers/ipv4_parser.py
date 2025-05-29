from amaranth import *

from transactron.core import *
from transactron.utils.transactron_helpers import make_layout

from mur.params import Params
from mur.utils import select_field_be
from mur.extract.interfaces import ProtoParserLayouts

from enum import IntFlag, auto


class IPv4Parser(Elaboratable):
    class ResultLayouts:
        def __init__(self):
            self.fields = make_layout(
                ("version", 4),  # Bits 0-3
                ("header_length", 4),  # Bits 4-7
                ("type_of_service", 8),  # Bits 8-15
                ("total_length", 16),  # Bits 16-31
                ("identification", 16),  # Bits 32-47
                ("flags", 3),  # Bits 48-50
                ("fragment_offset", 13),  # Bits 51-63
                ("time_to_live", 8),  # Bits 64-71
                ("protocol", 8),  # Bits 72-79
                ("header_checksum", 16),  # Bits 80-95
                ("source_ip", 32),  # Bits 96-127
                ("destination_ip", 32),  # Bits 128-159
            )

    class ProtoOut(IntFlag):
        UNKNOWN = 0
        ICMP = auto()
        TCP = auto()
        UDP = auto()

    def __init__(self, push_parsed: Method):
        self.push_parsed = push_parsed
        self.params = Params()
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

            # Extract the first byte
            first_byte = Signal(8)
            m.d.av_comb += select_field_be(m, first_byte, data, 0)

            # Extract version and header_length from the first byte
            m.d.av_comb += parsed.version.eq(first_byte[4:8])  # Bits 4-7 (high nibble)
            m.d.av_comb += parsed.header_length.eq(
                first_byte[0:4]
            )  # Bits 0-3 (low nibble)

            # Calculate header length in bytes
            header_length_bytes = parsed.header_length * 2

            # Extract other fields (example, adjust as per your layout)
            m.d.av_comb += [
                select_field_be(m, parsed.type_of_service, data, 8),
                select_field_be(m, parsed.total_length, data, 16),
                select_field_be(m, parsed.identification, data, 32),
                select_field_be(m, parsed.time_to_live, data, 64),
                select_field_be(m, parsed.protocol, data, 72),
                select_field_be(m, parsed.header_checksum, data, 80),
                select_field_be(m, parsed.source_ip, data, 96),
                select_field_be(m, parsed.destination_ip, data, 128),
            ]

            # Extract flags and fragment_offset
            flags_frag = Signal(16)
            m.d.av_comb += select_field_be(m, flags_frag, data, 48)
            m.d.av_comb += parsed.flags.eq(flags_frag[13:16])  # Bits 13-15
            m.d.av_comb += parsed.fragment_offset.eq(flags_frag[0:13])  # Bits 0-12

            # Check for runt packet
            m.d.av_comb += runt_packet.eq(
                ((header_length_bytes << 1) > end_of_packet_len) & end_of_packet
            )
            m.d.sync += parsing_finished.eq(~end_of_packet)

            with m.If(~parsing_finished):
                self.push_parsed(m, fields=parsed, error_drop=runt_packet)
            proto_out = Signal(self.params.next_proto_bits)

            # Map protocol to next_proto
            with m.Switch(parsed.protocol):
                with m.Case(1):
                    m.d.av_comb += proto_out.eq(self.ProtoOut.ICMP)
                with m.Case(6):  # TCP
                    m.d.av_comb += proto_out.eq(self.ProtoOut.TCP)
                with m.Case(17):  # UDP
                    m.d.av_comb += proto_out.eq(self.ProtoOut.UDP)
                with m.Default():
                    m.d.av_comb += proto_out.eq(self.ProtoOut.UNKNOWN)  # Unknown/other

            return {
                "data": data,
                "octets_consumed": header_length_bytes,
                "extract_range_end": ~parsing_finished,
                "next_proto": proto_out,
                "end_of_packet_len": end_of_packet_len,
                "end_of_packet": end_of_packet,
                "error_drop": runt_packet,
            }

        return m
