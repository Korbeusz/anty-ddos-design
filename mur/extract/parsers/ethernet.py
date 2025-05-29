from amaranth import *

from transactron.core import *
from transactron.utils.transactron_helpers import make_layout

from mur.params import Params
from mur.utils import swap_endianess, select_field_be
from mur.extract.interfaces import ProtoParserLayouts

from enum import IntFlag, auto


class EthernetParser(Elaboratable):
    class ResultLayouts:
        def __init__(self):
            self.fields = make_layout(
                ("src_mac", 6 * 8),
                ("dst_mac", 6 * 8),
                ("vlan", 4 * 4),
                ("vlan_v", 1),
                ("ethertype", 2 * 8),
            )

    class ProtoOut(IntFlag):
        UNKNOWN = 0
        IPV4 = auto()
        IPV6 = auto()
        ARP = auto()

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

            m.d.av_comb += [
                select_field_be(m, parsed.dst_mac, data, 0),
                select_field_be(m, parsed.src_mac, data, 6 * 8),
            ]

            m.d.av_comb += parsed.vlan_v.eq(
                swap_endianess(m, data.bit_select(12 * 8, 2 * 8)) == 0x8100
            )

            m.d.av_comb += select_field_be(
                m, parsed.vlan, Mux(parsed.vlan_v, data, 0), 14 * 8
            )
            m.d.av_comb += select_field_be(
                m, parsed.ethertype, data, Mux(parsed.vlan_v, 16 * 8, 12 * 8)
            )

            proto_out = Signal(self.params.next_proto_bits)
            with m.Switch(parsed.ethertype):
                with m.Case(0x0800):
                    m.d.av_comb += proto_out.eq(self.ProtoOut.IPV4)
                with m.Case(0x86DD):
                    m.d.av_comb += proto_out.eq(self.ProtoOut.IPV6)
                with m.Case(0x0806):
                    m.d.av_comb += proto_out.eq(self.ProtoOut.ARP)
                with m.Default():
                    m.d.av_comb += proto_out.eq(self.ProtoOut.UNKNOWN)

            m.d.sync += parsing_finished.eq(
                ~end_of_packet
            )  # end of packet is always needed if module seen start of it

            packet_length = Mux(parsed.vlan_v, 9, 7)

            m.d.av_comb += runt_packet.eq(
                ((packet_length << 1) > end_of_packet_len) & end_of_packet
            )

            with m.If(~parsing_finished):
                self.push_parsed(
                    m, fields=parsed, error_drop=runt_packet
                )  # full header available in one aligned word (comb)

            # RATIONALE for out interface:
            # runt packet should probably drop it
            # but unknown packet should be forwarded with known filtering - no err, probably separate flag no_next_proto
            # what with crc err -> drop
            # error_drop -> bypass path, qo shouldn't be considered
            # now are there any recoverable errors that we want to report? not for now? what to do with them
            # two kinds of recoverable erros -> one keep offset to next header known and other not. Should be handled differently
            return {
                "data": data,
                "octets_consumed": packet_length,
                "extract_range_end": ~parsing_finished,
                "next_proto": proto_out,
                "end_of_packet_len": end_of_packet_len,
                "end_of_packet": end_of_packet,
                "error_drop": runt_packet,
            }

        return m
