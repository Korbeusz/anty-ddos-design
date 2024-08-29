from amaranth import *
from mur.params import Params
from transactron import *
from transactron.utils.transactron_helpers import make_layout
from enum import IntFlag, auto


class EthernetParser(Elaboratable):
    LAYOUT = make_layout(
        ("src_mac", 6 * 8),
        ("dst_mac", 6 * 8),
        ("vlan", 4 * 8),
        ("vlan_v", 1),
        ("ethertype", 2 * 8),
        ("valid", 1),
    )

    class ProtoOut(IntFlag):
        UNKNOWN = 0
        IPV4 = auto()
        IPV6 = auto()
        ARP = auto()

    def __init__(self, din: Method, dout: Method, parsedout: Method):
        self.din = din
        self.dout = dout
        self.parsedout = parsedout
        self.params = Params()

    def elaborate(self, platform):
        m = TModule()

        finished = Signal()
        parser_error = Signal()
        parser_error_comb = Signal()  # TODO: rework error interface
        # split to recoverable and non-recoverable errors? disable updating hashes on malformed packets?

        with Transaction().body(m):  # TODO: switch to method
            din = self.din(m)

            parsed = Signal(self.LAYOUT)

            m.d.av_comb += parsed.src_mac.eq(din.data.bit_select(0, 6 * 8))
            m.d.av_comb += parsed.dst_mac.eq(din.data.bit_select(6 * 8, 6 * 8))

            m.d.av_comb += parsed.vlan_v.eq(din.data.bit_select(12 * 8, 2 * 8) == 0x8100)
            m.d.av_comb += parsed.vlan.eq(din.data.bit_select(14 * 8, 2 * 8))

            m.d.av_comb += parsed.ethertype.eq(din.data.bit_select(Mux(parsed.vlan_v, 16 * 8, 12 * 8), 2 * 8))

            proto_out = Signal(self.params.next_proto_bits)
            with m.Switch(parsed.ethertype):
                with m.Case(0x0800):
                    m.d.av_comb += proto_out.eq(self.PROTO_OUT.IPV4)
                with m.Case(0x86DD):
                    m.d.av_comb += proto_out.eq(self.PROTO_OUT.IPV6)
                with m.Case(0x0806):
                    m.d.av_comb += proto_out.eq(self.PROTO_OUT.ARP)
                with m.Default():
                    m.d.av_comb += proto_out.eq(self.PROTO_OUT.UNKNOWN)

            m.d.comb += parsed.valid.eq(~finished)

            m.d.sync += finished.eq(1)

            packet_length = Mux(parsed.vlan_v, 18 // 4, 14 // 4)
            with m.If(~finished & din.end_of_packet.any() & (packet_length < din.end_of_packet)):
                m.d.sync += parser_error.eq(1)
                m.d.av_comb += parser_error_comb.eq(1)

            with m.If(din.end_of_packet.any()):
                m.d.sync += finished.eq(0)

            self.dout(
                m,
                {
                    "data": din.data,
                    "quadoctets_consumed": Mux(finished, 0, packet_length // 4),  # move to separate flags?
                    "next_proto": proto_out,
                    "end_of_packet": din.end_of_packet,
                    "error": din.error | parser_error | parser_error_comb,
                },
            )

            self.parsedout(m, parsed)
        return m
