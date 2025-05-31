from amaranth import *
from transactron import *

from transactron.core import Transaction
from transactron.lib.fifo import BasicFifo
from transactron.lib.simultaneous import condition

from mur.params import Params
from mur.extract.interfaces import ProtoParserLayouts
from mur.extract.parsers.ethernet import EthernetParser
from mur.extract.parsers.ipv4_parser import IPv4Parser
from mur.extract.parsers.udp import UDPParser
from mur.extract.parsers.tcp import TCPParser
from mur.extract.aligner import ParserAligner

from mur.count.CMSVolController import CMSVolController

__all__ = ["ParserCMSVol"]


class ParserCMSVol(Elaboratable):
    """
    ParserCMSVol megres fucnctionallity of Parser and CMSVolController.
    It parses packets and pushes the parsed data to the CMSVolController.
    The output of the CMSVolController is then used to filter packets based their previous occurrences.

    Attributes
    ----------
        depth (int): Number of hash tables (rows) in the sketch.
        width (int): The size of CountHashTab (number of hash buckets).
        counter_width (int): Number of bits in each counter.
        hash_params (list[tuple[int, int]] | None): List of tuples containing
            hash coefficients (a, b) for each row. If None, default values are used.
        window (int): The size of the sliding window for the volume counter.
        volume_threshold (int): The threshold for the volume counter.
        discard_threshold (int): If the sum of the counts is lower than this threshold,
            then the corresponding packet values have not been seen in the window before
            so the packet is discarded.
        cms_fifo_depth (int): The depth of the FIFO used in the CMSVolController.
        chunk_fifo_depth (int): The depth of the processed packets FIFO.

    Methods
    -------
        din(data: int): Push data into the input FIFO.
        dout(): Get the output from the filtered FIFO.

    """

    def __init__(
        self,
        *,
        depth: int = 4,
        width: int = 16_384,
        counter_width: int = 32,
        hash_params: list[tuple[int, int]] | None = None,
        window: int = 2**16,
        volume_threshold: int = 100_000,
        discard_threshold: int = 0,
        cms_fifo_depth: int = 16,
        chunk_fifo_depth: int = 64,
    ) -> None:
        self.params = Params()
        layouts = ProtoParserLayouts()

        self._fifo_parsing_in = BasicFifo(layouts.parser_in_layout, chunk_fifo_depth)
        self._fifo_output_unfiltered = BasicFifo(
            layouts.parser_in_layout, chunk_fifo_depth
        )
        self._fifo_output_filtered = BasicFifo(
            layouts.parser_in_layout, chunk_fifo_depth
        )

        self.din = Method(i=layouts.parser_in_layout)
        self.dout = Method(o=layouts.parser_in_layout)

        self._eth_parser = EthernetParser(push_parsed=self._push_dummy())
        self._aligner1 = ParserAligner()
        self._ip_parser = IPv4Parser(push_parsed=self._push_parsed_ip())
        self._aligner2 = ParserAligner()
        self._udp_parser = UDPParser(push_parsed=self._push_parsed_udp())
        self._tcp_parser = TCPParser(push_parsed=self._push_parsed_tcp())
        self._number_of_full_packets_processed = Signal(32, init=0)
        self._number_of_full_packets_outputted = Signal(32, init=0)

        self._cms = CMSVolController(
            depth=depth,
            width=width,
            counter_width=counter_width,
            hash_params=hash_params,
            window=window,
            volume_threshold=volume_threshold,
            discard_threshold=discard_threshold,
            fifo_depth=cms_fifo_depth,
        )

    def _push_dummy(self):
        lay = [
            ("fields", EthernetParser.ResultLayouts().fields),
            ("error_drop", 1),
        ]
        self._dummy = Method(i=lay)
        return self._dummy

    def _push_parsed_ip(self):
        lay = [
            ("fields", IPv4Parser.ResultLayouts().fields),
            ("error_drop", 1),
        ]
        self._push_ip = Method(i=lay)
        return self._push_ip

    def _push_parsed_udp(self):
        lay = [
            ("fields", UDPParser.ResultLayouts().fields),
            ("error_drop", 1),
        ]
        self._push_udp = Method(i=lay)
        return self._push_udp

    def _push_parsed_tcp(self):
        lay = [
            ("fields", TCPParser.ResultLayouts().fields),
            ("error_drop", 1),
        ]
        self._push_tcp = Method(i=lay)
        return self._push_tcp

    def elaborate(self, platform):
        m = TModule()
        m.submodules += [
            self._fifo_parsing_in,
            self._fifo_output_unfiltered,
            self._fifo_output_filtered,
            self._eth_parser,
            self._aligner1,
            self._ip_parser,
            self._aligner2,
            self._udp_parser,
            self._tcp_parser,
            self._cms,
        ]

        @def_method(m, self._dummy)
        def _(arg):
            pass

        @def_method(m, self._push_ip)
        def _(arg):
            with m.If(arg.error_drop == 0):
                proto = arg.fields.protocol
                self._cms.push_a(m, {"data": arg.fields.source_ip})
                self._cms.push_b(m, {"data": arg.fields.destination_ip})
                self._cms.push_s(m, {"data": arg.fields.total_length})

        @def_method(m, self._push_udp)
        def _(arg):
            with m.If(arg.error_drop == 0):
                self._cms.push_c(m, {"data": arg.fields.destination_port})

        @def_method(m, self._push_tcp)
        def _(arg):
            with m.If(arg.error_drop == 0):
                self._cms.push_c(m, {"data": arg.fields.destination_port})

        layouts = ProtoParserLayouts()

        # COPY INPUT
        @def_method(m, self.din)
        def _(arg):
            self._fifo_parsing_in.write(m, arg)
            self._fifo_output_unfiltered.write(m, arg)

        # PARSING
        packet_chunk = Signal(layouts.parser_in_layout)
        packet_chunk_valid = Signal(1, init=0)
        eth_out = Signal(layouts.parser_out_layout)
        eth_out_valid = Signal(1, init=0)
        with Transaction().body(m, request=eth_out_valid):
            self._aligner1.din(m, eth_out)
            m.d.sync += eth_out_valid.eq(0)
        self.ethernet_parser_trans = Transaction(name="ethernet_parser")
        with self.ethernet_parser_trans.body(m, request=packet_chunk_valid):
            m.d.sync += eth_out.eq(self._eth_parser.step(m, packet_chunk))
            m.d.sync += eth_out_valid.eq(1)
            m.d.sync += packet_chunk_valid.eq(0)
        with Transaction().body(m):
            m.d.sync += packet_chunk.eq(self._fifo_parsing_in.read(m))
            m.d.sync += packet_chunk_valid.eq(1)

        aligner1_out = Signal(layouts.parser_in_layout)
        aligner1_valid = Signal(1, init=0)
        ip_out = Signal(layouts.parser_out_layout)
        ip_out_valid = Signal(1, init=0)
        self.ip_trans = Transaction(name="ip_parser")
        with Transaction().body(m, request=ip_out_valid):
            self._aligner2.din(m, ip_out)
            m.d.sync += ip_out_valid.eq(0)
        with self.ip_trans.body(m, request=aligner1_valid):
            m.d.sync += ip_out.eq(self._ip_parser.step(m, aligner1_out))
            m.d.sync += ip_out_valid.eq(1)
            m.d.sync += aligner1_valid.eq(0)

        with Transaction().body(m):
            al1_out = self._aligner1.dout(m)
            m.d.sync += aligner1_out.eq(
                Cat(
                    al1_out["data"],
                    al1_out["end_of_packet"],
                    al1_out["end_of_packet_len"],
                )
            )
            m.d.sync += aligner1_valid.eq(1)

        aligner2_out = Signal(layouts.parser_in_layout)
        aligner2_valid = Signal(1, init=0)
        self.udp_trans = Transaction(name="udp_parser")
        with self.udp_trans.body(m, request=aligner2_valid):
            self._udp_parser.step(m, aligner2_out)
            m.d.sync += aligner2_valid.eq(0)

        with Transaction().body(m):
            al2_out = self._aligner2.dout(m)
            m.d.sync += aligner2_out.eq(
                Cat(
                    al2_out["data"],
                    al2_out["end_of_packet"],
                    al2_out["end_of_packet_len"],
                )
            )
            m.d.sync += aligner2_valid.eq(1)

        # FILTERING
        decision = Signal(5, init=0)
        decision_valid = Signal(1, init=0)
        next_decision_valid = Signal(1, init=0)
        new_full_packet_in_filtered_queue = Signal(1, init=0)
        output_filtered = Signal(layouts.parser_in_layout)
        output_filtered_valid = Signal(1, init=0)
        m.d.comb += next_decision_valid.eq(1)
        m.d.sync += new_full_packet_in_filtered_queue.eq(0)
        with Transaction().body(
            m, request=output_filtered_valid & (decision_valid & (decision > 0))
        ):
            self._fifo_output_filtered.write(m, output_filtered)
            m.d.sync += output_filtered_valid.eq(0)

        with m.If(
            output_filtered["end_of_packet"]
            & output_filtered_valid
            & (decision_valid & (decision > 0))
        ):
            m.d.sync += decision.eq(decision - 1)
            with m.If(decision == 1):
                m.d.sync += decision_valid.eq(0)
                m.d.comb += next_decision_valid.eq(0)
            m.d.sync += self._number_of_full_packets_processed.eq(
                self._number_of_full_packets_processed + 1
            )
            m.d.sync += new_full_packet_in_filtered_queue.eq(1)
        with Transaction().body(
            m,
            request=~output_filtered_valid | (decision_valid & (decision > 0)),
        ):
            m.d.sync += output_filtered.eq(self._fifo_output_unfiltered.read(m))
            m.d.sync += output_filtered_valid.eq(1)

        with m.If(decision_valid & (decision == 0) & output_filtered_valid):
            m.d.sync += output_filtered_valid.eq(0)
            with m.If(output_filtered["end_of_packet"]):
                m.d.sync += decision_valid.eq(0)
                m.d.comb += next_decision_valid.eq(0)
        with Transaction().body(
            m,
            request=decision_valid & (decision == 0),
        ):
            m.d.sync += output_filtered.eq(self._fifo_output_unfiltered.read(m))
            m.d.sync += output_filtered_valid.eq(1)

        with Transaction().body(m, request=~decision_valid | ~next_decision_valid):
            m.d.sync += decision.eq(self._cms.out(m)["data"])
            m.d.sync += decision_valid.eq(1)

        full_packet_in_filtered_queue = Signal(1, init=0)
        m.d.sync += full_packet_in_filtered_queue.eq(
            self._number_of_full_packets_outputted
            != self._number_of_full_packets_processed
        )
        difference_is_one = Signal(1, init=0)
        m.d.sync += difference_is_one.eq(
            self._number_of_full_packets_outputted + 1
            == self._number_of_full_packets_processed
        )
        outputted_packet = Signal(1, init=0)
        m.d.sync += outputted_packet.eq(0)

        @def_method(
            m,
            self.dout,
            ready=(
                (
                    full_packet_in_filtered_queue
                    & ~(outputted_packet & difference_is_one)
                )
                | new_full_packet_in_filtered_queue
            ),
        )
        def _():
            word = self._fifo_output_filtered.read(m)
            with m.If(word["end_of_packet"] == 1):
                m.d.sync += self._number_of_full_packets_outputted.eq(
                    self._number_of_full_packets_outputted + 1
                )
                m.d.sync += outputted_packet.eq(1)
            return word

        return m
