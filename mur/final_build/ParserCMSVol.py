from __future__ import annotations

"""parser_cms_pipeline.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Unified top‑level that combines:

* **Packet parsing + re‑alignment** pipeline (Ethernet → IPv4 → UDP/TCP)
  taken from *test_parsing.parser_aligner*.
* **CMSVolController** statistics back‑end that provides rolling Count‑Min
  Sketches and volume monitoring.

**External interface**
----------------------
* **din**  – identical to *parser_aligner*: `Method(i=ProtoParserLayouts.parser_in_layout)`.
* **out**  – identical to *CMSVolController*: `Method(o=[("data", 32), ("valid", 1)])`.

Every successfully parsed IPv4 packet contributes **four words** to the
CMSVolController (src‑IP, dst‑IP, dst‑port, tot‑len).  For non‑UDP/TCP
protocols the destination‑port is fixed to **0 × 0000**.
"""

from amaranth import *

from transactron import *
from transactron.core import Transaction
from transactron.lib.fifo import BasicFifo
from transactron.lib.simultaneous import condition
from transactron.lib import logging

from mur.params import Params
from mur.extract.interfaces import ProtoParserLayouts
from mur.extract.parsers.ethernet import EthernetParser
from mur.extract.parsers.ipv4_parser import IPv4Parser
from mur.extract.parsers.udp import UDPParser
from mur.extract.parsers.tcp import TCPParser
from mur.extract.aligner import ParserAligner

from mur.count.CMSVolController import CMSVolController

__all__ = ["ParserCMSVol"]

log = logging.HardwareLogger("top.parser_cms_pipeline")


class ParserCMSVol(Elaboratable):
    """Top‑level module that parses packets and feeds **CMSVolController**."""

    # ------------------------------------------------------------------
    #  Constructor – expose *din* & *out*
    # ------------------------------------------------------------------
    def __init__(
        self,
        *,
        # Parser / aligner FIFO depth
        fifo_depth_in: int = 16,
        # CMSVolController parameters ----------------------------------
        depth: int = 4,
        width: int = 16_384,
        counter_width: int = 32,
        hash_params: list[tuple[int, int]] | None = None,
        window: int = 2 ** 16,
        volume_threshold: int = 100_000,
        discard_threshold: int = 0,
        cms_fifo_depth: int = 16,
        fifo_output_depth: int = 1024,
    ) -> None:
        self.params = Params()
        layouts = ProtoParserLayouts()

        # -------------------- Ingress FIFO -----------------------------
        self._fifo_parsing_in = BasicFifo(layouts.parser_in_layout, fifo_depth_in)
        self._fifo_output_unfiltered = BasicFifo(layouts.parser_in_layout, fifo_output_depth)
        self._fifo_output_filtered = BasicFifo(layouts.parser_in_layout, fifo_output_depth)
        self._fifo_in = BasicFifo(layouts.parser_in_layout, fifo_depth_in)
        self.din = self._fifo_in.write       # external handle
        self.dout = Method(o=layouts.parser_in_layout)  # external handle
        # --------------------- Parsers & helpers -----------------------
        self._eth_parser  = EthernetParser(push_parsed=self._push_dummy())
        self._aligner1    = ParserAligner()
        self._ip_parser   = IPv4Parser(push_parsed=self._push_parsed_ip())
        self._aligner2    = ParserAligner()
        self._udp_parser  = UDPParser(push_parsed=self._push_parsed_udp())
        self._tcp_parser  = TCPParser(push_parsed=self._push_parsed_tcp())
        self._number_of_full_packets_processed = Signal(32, init=0)
        self._number_of_full_packets_outputted = Signal(32, init=0)

        # --------------------- CMS / volume engine ---------------------
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
        self.out = self._cms.out            # external handle

    # ------------------------------------------------------------------
    #  Internal dummy / push handlers
    # ------------------------------------------------------------------
    def _push_dummy(self):
        """No‑op push handler for Ethernet parser."""
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

    # ------------------------------------------------------------------
    #  Elaborate – wire everything together
    # ------------------------------------------------------------------
    def elaborate(self, platform):
        m = TModule()

        # --------------------------------------------------------------
        # Register sub‑modules so the simulator/net‑lister sees them
        # --------------------------------------------------------------
        m.submodules += [
            self._fifo_parsing_in, self._fifo_in,self._fifo_output_unfiltered,
            self._fifo_output_filtered,
            self._eth_parser, self._aligner1,
            self._ip_parser,  self._aligner2,
            self._udp_parser, self._tcp_parser,
            self._cms,
        ]

        # ----------------- Dummy push for Ethernet --------------------
        @def_method(m, self._dummy)
        def _(arg):
            pass  # Ethernet fields are not used for statistics

        # ----------------------- IPv4 push ----------------------------
        @def_method(m, self._push_ip)
        def _(arg):
            # Skip erroneous packets (runt etc.)
            with m.If(arg.error_drop == 0):
                proto = arg.fields.protocol        # 8‑bit L4 protocol ID

                # Push SRC/DST IP + total‑length *immediately* ------------
                self._cms.push_a(m, {"data": arg.fields.source_ip})
                self._cms.push_b(m, {"data": arg.fields.destination_ip})
                self._cms.push_s(m, {"data": arg.fields.total_length})

        # ----------------------- UDP push -----------------------------
        @def_method(m, self._push_udp)
        def _(arg):
            with m.If(arg.error_drop == 0):
                self._cms.push_c(m, {"data": arg.fields.destination_port})

        # ----------------------- TCP push -----------------------------
        @def_method(m, self._push_tcp)
        def _(arg):
            with m.If(arg.error_drop == 0):
                self._cms.push_c(m, {"data": arg.fields.destination_port})
        
        with Transaction().body(m):
            tmp = self._fifo_in.read(m)
            self._fifo_parsing_in.write(m,tmp)
            self._fifo_output_unfiltered.write(m,tmp)

        # --------------------------------------------------------------
        # Streaming datapath (3 sequential transactions)
        # --------------------------------------------------------------
        layouts = ProtoParserLayouts()

        # 1. Ethernet parser ------------------------------------------
        with Transaction().body(m):
            word0   = self._fifo_parsing_in.read(m)
            eth_out = self._eth_parser.step(m, word0)
            self._aligner1.din(m, eth_out)

        # 2. IPv4 parser ----------------------------------------------
        with Transaction().body(m):
            al1   = self._aligner1.dout(m)
            ip_in = {
                "data":              al1["data"],
                "end_of_packet":     al1["end_of_packet"],
                "end_of_packet_len": al1["end_of_packet_len"],
            }
            ip_out = self._ip_parser.step(m, ip_in)
            self._aligner2.din(m, ip_out)

        # 3. UDP / TCP selection --------------------------------------
        with Transaction().body(m):
            al2 = self._aligner2.dout(m)
            tr_in = {
                "data":              al2["data"],
                "end_of_packet":     al2["end_of_packet"],
                "end_of_packet_len": al2["end_of_packet_len"],
            }
            IpProtoOut = IPv4Parser.ProtoOut
            with condition(m) as branch:
                with branch(al2["next_proto"] == IpProtoOut.UDP):
                    self._udp_parser.step(m, tr_in)
                with branch(al2["next_proto"] == IpProtoOut.TCP):
                    self._tcp_parser.step(m, tr_in)
            # Unknown/other protocols fall through (no L4 parser)
        # We want to filter input data using results from the CMS
        packet_passing = Signal(32,init=0)
        packet_dropping = Signal(1,init=0)
        decision = Signal(32,init=0)
        with Transaction().body(m,request=(packet_passing == 0)& ~packet_dropping):
            decision = self._cms.out(m)["data"]
            with m.If(decision == 0):
                m.d.sync += packet_dropping.eq(1)
            with m.Else():
                m.d.sync += packet_passing.eq(decision)
        
        with Transaction().body(m, request=packet_passing):
            tmp = self._fifo_output_unfiltered.read(m)
            self._fifo_output_filtered.write(m,tmp)
            with m.If(tmp["end_of_packet"] == 1):
                m.d.sync += packet_passing.eq(packet_passing - 1)
                m.d.sync += self._number_of_full_packets_processed.eq(self._number_of_full_packets_processed + 1)
        
        with Transaction().body(m,request=packet_dropping):
            tmp = self._fifo_output_unfiltered.read(m)
            with m.If(tmp["end_of_packet"] == 1):
                m.d.sync += packet_dropping.eq(0)
        
        full_packet_in_filtered_queue = Signal(1,init=0)
        m.d.comb += full_packet_in_filtered_queue.eq(self._number_of_full_packets_outputted != self._number_of_full_packets_processed) 
        @def_method(m, self.dout,ready=full_packet_in_filtered_queue)
        def _():
            word = self._fifo_output_filtered.read(m)
            with m.If(word["end_of_packet"] == 1):
                m.d.sync += self._number_of_full_packets_outputted.eq(self._number_of_full_packets_outputted + 1)
            return word

        return m
