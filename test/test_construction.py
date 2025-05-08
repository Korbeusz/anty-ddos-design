from transactron.testing import *
from mur.extract.parsers.ethernet import EthernetParser
from mur.extract.parsers.ipv4_parser import IPv4Parser
from mur.extract.parsers.tcp import TCPParser
from mur.extract.parsers.udp import UDPParser
from mur.extract.aligner import ParserAligner
from transactron.core import *
from transactron.lib.connectors import ConnectTrans
from transactron.lib.fifo import BasicFifo
from mur.extract.interfaces import ProtoParserLayouts
from scapy.all import rdpcap
from random import randint, random, seed
from transactron.lib import logging

log = logging.HardwareLogger("test.construction")

# ------------------------------------------------------------
# DUT wrapper: Ethernet → Aligner → IPv4 → Aligner → UDP/TCP
# ------------------------------------------------------------
class parser_aligner(Elaboratable):
    """Top‑level that chains Ethernet, IPv4, UDP and TCP parsers with
    the required aligners.  The UDP or TCP parser is selected based on
    the *next_proto* field from the IPv4 layer (no extra aligner
    needed).  Parsed headers for every layer can be retrieved through
    dedicated *get_* methods.
    """

    def __init__(self):
        self.layouts = ProtoParserLayouts()

        # FIFO to inject raw packet words
        self.fifo_in = BasicFifo(self.layouts.parser_in_layout, 4)
        self.din = self.fifo_in.write

        # Stages ---------------------------------------------------
        self.eth_parser  = EthernetParser(push_parsed=self._push_parsed_eth())
        self.aligner1    = ParserAligner()
        self.ip_parser   = IPv4Parser(push_parsed=self._push_parsed_ip())
        self.aligner2    = ParserAligner()
        self.udp_parser  = UDPParser(push_parsed=self._push_parsed_udp())
        self.tcp_parser  = TCPParser(push_parsed=self._push_parsed_tcp())

        # ---------------- saved Ethernet / IPv4 / UDP / TCP fields -------------
        self._last_eth = Signal(self.eth_parser.ResultLayouts().fields)
        self._new_eth  = Signal()
        self.get_eth   = Method(o=self.eth_parser.ResultLayouts().fields)

        self._last_ip  = Signal(self.ip_parser.ResultLayouts().fields)
        self._new_ip   = Signal()
        self.get_ip    = Method(o=self.ip_parser.ResultLayouts().fields)

        self._last_udp = Signal(self.udp_parser.ResultLayouts().fields)
        self._new_udp  = Signal()
        self.get_udp   = Method(o=self.udp_parser.ResultLayouts().fields)

        self._last_tcp = Signal(self.tcp_parser.ResultLayouts().fields)
        self._new_tcp  = Signal()
        self.get_tcp   = Method(o=self.tcp_parser.ResultLayouts().fields)

        # Public output (payload after transport header – **unused in this TB**)
        self.dout = self.aligner2.dout

    # ------------------------------------------------------------
    #  Internal helper: push_parsed handlers (Ethernet / IPv4 / UDP / TCP)
    # ------------------------------------------------------------
    def _push_parsed_eth(self):
        lay = [
            ("fields", EthernetParser.ResultLayouts().fields),
            ("error_drop", 1),
        ]
        self.push_parsed_eth = Method(i=lay, o=lay)
        return self.push_parsed_eth

    def _push_parsed_ip(self):
        lay = [
            ("fields", IPv4Parser.ResultLayouts().fields),
            ("error_drop", 1),
        ]
        self.push_parsed_ip = Method(i=lay, o=lay)
        return self.push_parsed_ip

    def _push_parsed_udp(self):
        lay = [
            ("fields", UDPParser.ResultLayouts().fields),
            ("error_drop", 1),
        ]
        self.push_parsed_udp = Method(i=lay, o=lay)
        return self.push_parsed_udp

    def _push_parsed_tcp(self):
        lay = [
            ("fields", TCPParser.ResultLayouts().fields),
            ("error_drop", 1),
        ]
        self.push_parsed_tcp = Method(i=lay, o=lay)
        return self.push_parsed_tcp

    # ------------------------------------------------------------
    #  Elaborate – wire everything together
    # ------------------------------------------------------------
    def elaborate(self, platform):
        m = TModule()

        # Sub‑modules ---------------------------------------------
        m.submodules += [
            self.fifo_in,
            self.eth_parser,
            self.aligner1,
            self.ip_parser,
            self.aligner2,
            self.udp_parser,
            self.tcp_parser,
        ]

        # Save parsed Ethernet header -----------------------------
        @def_method(m, self.push_parsed_eth, ready=~self._new_eth)
        def _(arg):
            m.d.sync += [self._last_eth.eq(arg.fields), self._new_eth.eq(1)]

        @def_method(m, self.get_eth, ready=self._new_eth)
        def _():
            m.d.sync += self._new_eth.eq(0)
            return self._last_eth

        # Save parsed IPv4 header ---------------------------------
        @def_method(m, self.push_parsed_ip, ready=~self._new_ip)
        def _(arg):
            m.d.sync += [self._last_ip.eq(arg.fields), self._new_ip.eq(1)]

        @def_method(m, self.get_ip, ready=self._new_ip)
        def _():
            m.d.sync += self._new_ip.eq(0)
            return self._last_ip

        # Save parsed UDP header ----------------------------------
        @def_method(m, self.push_parsed_udp, ready=~self._new_udp)
        def _(arg):
            m.d.sync += [self._last_udp.eq(arg.fields), self._new_udp.eq(1)]

        @def_method(m, self.get_udp, ready=self._new_udp)
        def _():
            m.d.sync += self._new_udp.eq(0)
            return self._last_udp

        # Save parsed TCP header ----------------------------------
        @def_method(m, self.push_parsed_tcp, ready=~self._new_tcp)
        def _(arg):
            m.d.sync += [self._last_tcp.eq(arg.fields), self._new_tcp.eq(1)]

        @def_method(m, self.get_tcp, ready=self._new_tcp)
        def _():
            m.d.sync += self._new_tcp.eq(0)
            return self._last_tcp

        # ------------------- Streaming datapath ------------------
        # Transaction 1: Ethernet parser
        with Transaction().body(m):
            word0 = self.fifo_in.read(m)
            eth_out = self.eth_parser.step(m, word0)
            self.aligner1.din(m, eth_out)

        # Transaction 2: IPv4 parser
        with Transaction().body(m):
            al1 = self.aligner1.dout(m)
            ip_in = {
                "data":              al1["data"],
                "end_of_packet":     al1["end_of_packet"],
                "end_of_packet_len": al1["end_of_packet_len"],
            }
            ip_out = self.ip_parser.step(m, ip_in)
            self.aligner2.din(m, ip_out)

        # Transaction 3: UDP / TCP parser selection ------------
        with Transaction().body(m):
            al2 = self.aligner2.dout(m)
            tr_in = {
                "data":              al2["data"],
                "end_of_packet":     al2["end_of_packet"],
                "end_of_packet_len": al2["end_of_packet_len"],
            }

            IpProtoOut = IPv4Parser.ProtoOut
            with m.Switch(al2["next_proto"]):
                with m.Case(IpProtoOut.UDP):
                    self.udp_parser.step(m, tr_in)
                with m.Case(IpProtoOut.TCP):
                    self.tcp_parser.step(m, tr_in)
                with m.Default():
                    pass  # Unsupported transport protocol – ignore

        return m

# ------------------------------------------------------------------
# Helper utilities (byte‑twiddling reference model)
# ------------------------------------------------------------------

def bytes_to_int_le(b: bytes) -> int:
    return int.from_bytes(b, "little")


def split_chunks(buf: bytes, size: int = 64):
    return [(buf[i:i+size]).ljust(size, b"\0") for i in range(0, len(buf), size)] or [b"".ljust(size, b"\0")]


# ------------------ L2 / L3 reference parsers ----------------------

def parse_ethernet(pkt: bytes):
    parsed = {
        "dst_mac": int.from_bytes(pkt[0:6], "big") if len(pkt) >= 6 else 0,
        "src_mac": int.from_bytes(pkt[6:12], "big") if len(pkt) >= 12 else 0,
        "vlan":     0,
        "vlan_v":   0,
        "ethertype": 0,
        "error_drop": 0,
    }
    if len(pkt) < 14:
        parsed["error_drop"] = 1
        return parsed

    ethertype = int.from_bytes(pkt[12:14], "big")
    off = 14
    if ethertype == 0x8100:  # VLAN tagged
        if len(pkt) < 18:
            parsed["error_drop"] = 1
            return parsed
        parsed["vlan_v"] = 1
        parsed["vlan"] = int.from_bytes(pkt[14:16], "big")
        ethertype = int.from_bytes(pkt[16:18], "big")
        off = 18

    parsed["ethertype"] = ethertype
    parsed["header_len"] = off
    return parsed


def parse_ipv4(pkt: bytes, ip_off: int):
    blank = {k: 0 for k in [
        "version","header_length","type_of_service","total_length","identification","flags",
        "fragment_offset","time_to_live","protocol","header_checksum","source_ip","destination_ip"]}
    parsed = {**blank, "error_drop": 0}
    if len(pkt) < ip_off + 20:  # minimum IPv4 hdr
        parsed["error_drop"] = 1
        return parsed

    first = pkt[ip_off]
    parsed["version"] = first >> 4
    ihl = first & 0x0F
    parsed["header_length"] = ihl
    hdr_bytes = ihl * 4
    if len(pkt) < ip_off + hdr_bytes:
        parsed["error_drop"] = 1
        return parsed

    parsed["type_of_service"] = pkt[ip_off+1]
    parsed["total_length"] = int.from_bytes(pkt[ip_off+2:ip_off+4], "big")
    parsed["identification"] = int.from_bytes(pkt[ip_off+4:ip_off+6], "big")
    flags_frag = int.from_bytes(pkt[ip_off+6:ip_off+8], "big")
    parsed["flags"] = flags_frag >> 13
    parsed["fragment_offset"] = flags_frag & 0x1FFF
    parsed["time_to_live"] = pkt[ip_off+8]
    proto = pkt[ip_off+9]
    parsed["protocol"] = proto
    parsed["header_checksum"] = int.from_bytes(pkt[ip_off+10:ip_off+12], "big")
    parsed["source_ip"] = int.from_bytes(pkt[ip_off+12:ip_off+16], "big")
    parsed["destination_ip"] = int.from_bytes(pkt[ip_off+16:ip_off+20], "big")
    parsed["header_len"] = hdr_bytes
    return parsed

# ------------------ L4 reference parsers ---------------------------

def parse_udp(pkt: bytes, l4_off: int):
    blank = {k: 0 for k in ["source_port", "destination_port", "length", "checksum"]}
    parsed = {**blank, "error_drop": 0}
    if len(pkt) < l4_off + 8:
        parsed["error_drop"] = 1
        return parsed
    parsed["source_port"]      = int.from_bytes(pkt[l4_off:l4_off+2], "big")
    parsed["destination_port"] = int.from_bytes(pkt[l4_off+2:l4_off+4], "big")
    parsed["length"]           = int.from_bytes(pkt[l4_off+4:l4_off+6], "big")
    parsed["checksum"]         = int.from_bytes(pkt[l4_off+6:l4_off+8], "big")
    parsed["header_len"]       = 8
    return parsed


def parse_tcp(pkt: bytes, l4_off: int):
    blank = {k: 0 for k in [
        "source_port", "destination_port", "sequence_number", "acknowledgment_number",
        "data_offset", "reserved", "flags", "window_size", "checksum", "urgent_pointer"]}
    parsed = {**blank, "error_drop": 0}
    if len(pkt) < l4_off + 20:  # minimum TCP header
        parsed["error_drop"] = 1
        return parsed

    parsed["source_port"]          = int.from_bytes(pkt[l4_off:l4_off+2], "big")
    parsed["destination_port"]     = int.from_bytes(pkt[l4_off+2:l4_off+4], "big")
    parsed["sequence_number"]      = int.from_bytes(pkt[l4_off+4:l4_off+8], "big")
    parsed["acknowledgment_number"] = int.from_bytes(pkt[l4_off+8:l4_off+12], "big")

    byte12 = pkt[l4_off+12]
    parsed["data_offset"] = byte12 >> 4
    parsed["reserved"]    = byte12 & 0x0F
    parsed["flags"]       = pkt[l4_off+13]
    parsed["window_size"] = int.from_bytes(pkt[l4_off+14:l4_off+16], "big")
    parsed["checksum"]    = int.from_bytes(pkt[l4_off+16:l4_off+18], "big")
    parsed["urgent_pointer"] = int.from_bytes(pkt[l4_off+18:l4_off+20], "big")

    hdr_len = parsed["data_offset"] * 4
    parsed["header_len"] = hdr_len
    if len(pkt) < l4_off + hdr_len:
        parsed["error_drop"] = 1
    return parsed

# ------------------------------------------------------------------
#                      Test‑bench class
# ------------------------------------------------------------------
class TestEthernetIPv4TCPUDPParser(TestCaseWithSimulator):
    def setup_method(self):
        seed(42)
        pkts = rdpcap("example_pcaps/tcp_udp.pcapng")

        self.inputs    = []
        self.exp_eth   = []
        self.exp_ip    = []
        self.exp_udp   = []  # Expected UDP headers in arrival order
        self.exp_tcp   = []  # Expected TCP headers in arrival order

        for sc in pkts:
            raw = bytes(sc)
            eth = parse_ethernet(raw)
            ip  = parse_ipv4(raw, eth.get("header_len", 0)) if eth["ethertype"] == 0x0800 else {"error_drop":1}

            # --- push raw words into FIFO -----------------------
            in_chunks = split_chunks(raw, 64)
            for i, ch in enumerate(in_chunks):
                last = i == len(in_chunks) - 1
                eop_len = len(raw) % 64 if last else 0
                eop_len = 64 if last and eop_len == 0 and raw else eop_len
                self.inputs.append({
                    "data": bytes_to_int_le(ch),
                    "end_of_packet": last,
                    "end_of_packet_len": eop_len,
                })

            # Expected headers -----------------------------------
            self.exp_eth.append(eth)
            self.exp_ip.append(ip)

            if ip.get("error_drop", 1) == 0:
                l4_off = eth["header_len"] + ip["header_len"]
                if ip["protocol"] == 17:  # UDP
                    self.exp_udp.append(parse_udp(raw, l4_off))
                elif ip["protocol"] == 6:  # TCP
                    self.exp_tcp.append(parse_tcp(raw, l4_off))

    # ------------ driver / checker processes ---------------------
    async def _drive_din(self, sim):
        for word in self.inputs:
            while random() > 0.7:
                await sim.tick()
            await self.eptc.din.call(sim, word)

    async def _check_parsed(self, sim):
        udp_idx = 0
        tcp_idx = 0
        for eth, ip in zip(self.exp_eth, self.exp_ip):
            # Ethernet ------------------------------------------
            while random() > 0.7:
                await sim.tick()
            got_eth = await self.eptc.get_eth.call(sim)
            assert int(got_eth["ethertype"]) == eth["ethertype"]

            # IPv4 ----------------------------------------------
            while random() > 0.7:
                await sim.tick()
            got_ip = await self.eptc.get_ip.call(sim)
            assert int(got_ip["protocol"]) == ip["protocol"]

            # UDP / TCP -----------------------------------------
            if ip.get("error_drop", 1):
                continue
            if ip["protocol"] == 17:  # UDP
                exp_udp = self.exp_udp[udp_idx]
                udp_idx += 1
                while random() > 0.7:
                    await sim.tick()
                got_udp = await self.eptc.get_udp.call(sim)
                assert int(got_udp["source_port"]) == exp_udp["source_port"]
                assert int(got_udp["destination_port"]) == exp_udp["destination_port"]
            elif ip["protocol"] == 6:  # TCP
                exp_tcp = self.exp_tcp[tcp_idx]
                tcp_idx += 1
                while random() > 0.7:
                    await sim.tick()
                got_tcp = await self.eptc.get_tcp.call(sim)
                assert int(got_tcp["source_port"]) == exp_tcp["source_port"]
                assert int(got_tcp["destination_port"]) == exp_tcp["destination_port"]

    # --------------------------- test entry ----------------------
    def test_random(self):
        self.eptc = SimpleTestCircuit(parser_aligner())
        with self.run_simulation(self.eptc) as sim:
            sim.add_testbench(self._drive_din)
            sim.add_testbench(self._check_parsed)
