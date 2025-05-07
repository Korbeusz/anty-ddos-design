from transactron.testing import *
from mur.extract.parsers.ethernet import EthernetParser
from mur.extract.parsers.ipv4_parser import IPv4Parser
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
# Constants mirroring hardware enum values
# ------------------------------------------------------------
class EthProtoOut:
    IPV4 = 1
    IPV6 = 2
    OTHER = 0

class IpProtoOut:
    ICMP = 1
    TCP  = 2
    UDP  = 3
    OTHER = 0

# ------------------------------------------------------------
# DUT wrapper: Ethernet → Aligner → IPv4 → Aligner
# ------------------------------------------------------------
class parser_aligner(Elaboratable):
    """Small top‑level that chains the two parsers with two aligners
    and exposes a *single* streaming output after the IPv4 header."""

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

        # Public output (payload after IPv4 header)
        self.dout = self.aligner2.dout

        # ---------------- saved Ethernet / IPv4 fields ------------
        self._last_eth = Signal(self.eth_parser.ResultLayouts().fields)
        self._new_eth  = Signal()
        self.get_eth   = Method(o=self.eth_parser.ResultLayouts().fields)

        self._last_ip  = Signal(self.ip_parser.ResultLayouts().fields)
        self._new_ip   = Signal()
        self.get_ip    = Method(o=self.ip_parser.ResultLayouts().fields)

    # ------------------------------------------------------------
    #  Internal helper: push_parsed handlers (Ethernet / IPv4)
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
        ]

        # Save parsed Ethernet header -----------------------------
        @def_method(m, self.push_parsed_eth, ready=~self._new_eth)
        def _(arg):
            log.debug(m, True, "PUSH_ETH", arg.fields)
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

        # ------------------- Streaming datapath ------------------
        with Transaction().body(m):
            word0 = self.fifo_in.read(m)
            eth_out = self.eth_parser.step(m, word0)
            self.aligner1.din(m, eth_out)
            log.debug(m, True, "TRANSACTION1")

        with Transaction().body(m):
            # Strip *next_proto* so it matches parser_in_layout
            al1 = self.aligner1.dout(m)
            ip_in = {
                "data":            al1["data"],
                "end_of_packet":   al1["end_of_packet"],
                "end_of_packet_len": al1["end_of_packet_len"],
            }
            ip_out = self.ip_parser.step(m, ip_in)
            self.aligner2.din(m, ip_out)
            log.debug(m, True, "TRANSACTION2")

        return m

# ------------------------------------------------------------------
# Helper utilities (byte‑twiddling reference model)
# ------------------------------------------------------------------

def bytes_to_int_le(b: bytes) -> int:
    return int.from_bytes(b, "little")


def split_chunks(buf: bytes, size: int = 64):
    return [(buf[i:i+size]).ljust(size, b"\0") for i in range(0, len(buf), size)] or [b"".ljust(size, b"\0")]


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


def packet_to_expected_dout(pkt: bytes, eth: dict, ip: dict, chunk: int = 64):
    """Strip Ethernet + IPv4 headers and split remainder into 64‑byte words."""
    if eth["error_drop"] or ip["error_drop"]:
        return []

    payload = pkt[eth["header_len"] + ip["header_len"]:]
    chunks = split_chunks(payload, chunk)
    dout = []
    for i, ch in enumerate(chunks):
        last = i == len(chunks) - 1
        eop_len = len(payload) % chunk if last else 0
        eop_len = chunk if last and eop_len == 0 and payload else eop_len

        if i == 0:
            proto_map = {1: IpProtoOut.ICMP, 6: IpProtoOut.TCP, 17: IpProtoOut.UDP}
            next_proto = proto_map.get(ip["protocol"], IpProtoOut.OTHER)
        else:
            next_proto = 0

        dout.append({
            "data": bytes_to_int_le(ch),
            "end_of_packet": last,
            "end_of_packet_len": eop_len,
            "next_proto": next_proto,
        })
    return dout

# ------------------------------------------------------------------
#                   Test‑bench class
# ------------------------------------------------------------------
class TestEthernetIPv4Parser(TestCaseWithSimulator):
    def setup_method(self):
        seed(42)
        pkts = rdpcap("example_pcaps/onepacket.pcapng")
        self.inputs  = []
        self.exp_eth = []
        self.exp_ip  = []
        self.exp_dout = []

        for sc in pkts:
            raw = bytes(sc)
            eth = parse_ethernet(raw)
            ip  = parse_ipv4(raw, eth.get("header_len", 0)) if eth["ethertype"] == 0x0800 else {"error_drop":1}

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

            self.exp_eth.append(eth)
            self.exp_ip.append(ip)
            self.exp_dout.extend(packet_to_expected_dout(raw, eth, ip))

    # ------------ driver / checker processes ---------------------
    async def _drive_din(self, sim):
        for word in self.inputs:
            while random() > 0.7:
                await sim.tick()
            await self.eptc.din.call(sim, word)

    async def _check_dout(self, sim):
        for exp in self.exp_dout:
            while random() > 0.7:
                await sim.tick()
            got = await self.eptc.dout.call(sim)
            assert got == exp, f"dout mismatch: got {got} exp {exp}"

    async def _check_parsed(self, sim):
        for eth, ip in zip(self.exp_eth, self.exp_ip):
            # Ethernet first --------------------------------------
            while random() > 0.7:
                await sim.tick()
            got_eth = await self.eptc.get_eth.call(sim)
            assert int(got_eth["ethertype"]) == eth["ethertype"]

            # Then IPv4 -------------------------------------------
            while random() > 0.7:
                await sim.tick()
            got_ip = await self.eptc.get_ip.call(sim)
            assert int(got_ip["protocol"]) == ip["protocol"]

    # --------------------------- test entry ----------------------
    def test_random(self):
        self.eptc = SimpleTestCircuit(parser_aligner())
        with self.run_simulation(self.eptc) as sim:
            sim.add_testbench(self._drive_din)
            sim.add_testbench(self._check_dout)
            sim.add_testbench(self._check_parsed)
