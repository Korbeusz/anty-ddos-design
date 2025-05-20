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
from scapy.all import Ether, IP, TCP, UDP, Raw
from random import randint, random, seed
from transactron.lib.simultaneous import condition
CYCLE_TIME = 0.0005


# ------------------------------------------------------------
# DUT wrapper: Ethernet → Aligner → IPv4 → Aligner → UDP/TCP
# ------------------------------------------------------------
class parser_aligner(Elaboratable):
    """Top‑level that chains Ethernet, IPv4, UDP and TCP parsers with
    the required aligners.  Apart from the original header capture, this
    variant also streams selected fields (IPv4 src/dst/len and transport
    destination port) into dedicated FIFOs so the test‑bench can verify
    them one‑by‑one.
    """

    def __init__(self):
        self.layouts = ProtoParserLayouts()

        # FIFO to inject raw packet words --------------------------------
        self.fifo_in = BasicFifo(self.layouts.parser_in_layout, 16)
        self.din = self.fifo_in.write

        # ── NEW: simple FIFO layouts ------------------------------------
        lay32 = [("data", 32)]
        lay16 = [("data", 16)]

        self.ip_src_fifo = BasicFifo(lay32, 16)
        self.ip_dst_fifo = BasicFifo(lay32, 16)
        self.ip_len_fifo = BasicFifo(lay16, 16)
        self.dst_port_fifo = BasicFifo(lay16, 16)

        # Expose *read* side as handy Methods for the TB -----------------
        self.get_src_ip = self.ip_src_fifo.read
        self.get_dst_ip = self.ip_dst_fifo.read
        self.get_tot_len = self.ip_len_fifo.read
        self.get_dst_port = self.dst_port_fifo.read

        # Stages ---------------------------------------------------------
        # Ethernet parser is wired with a *no‑op* push method because no
        # Ethernet‑level fields are checked in this upgraded TB.
        self.eth_parser = EthernetParser(push_parsed=self._push_dummy())
        self.aligner1 = ParserAligner()
        self.ip_parser = IPv4Parser(push_parsed=self._push_parsed_ip())
        self.aligner2 = ParserAligner()
        self.udp_parser = UDPParser(push_parsed=self._push_parsed_udp())
        self.tcp_parser = TCPParser(push_parsed=self._push_parsed_tcp())

        self.dout = self.aligner2.dout

    # ------------------------------------------------------------
    #  Internal helpers: dummy & real push_parsed handlers
    # ------------------------------------------------------------
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
        self.push_parsed_ip = Method(i=lay)
        return self.push_parsed_ip

    def _push_parsed_udp(self):
        lay = [
            ("fields", UDPParser.ResultLayouts().fields),
            ("error_drop", 1),
        ]
        self.push_parsed_udp = Method(i=lay)
        return self.push_parsed_udp

    def _push_parsed_tcp(self):
        lay = [
            ("fields", TCPParser.ResultLayouts().fields),
            ("error_drop", 1),
        ]
        self.push_parsed_tcp = Method(i=lay)
        return self.push_parsed_tcp

    # ------------------------------------------------------------
    #  Elaborate – wire everything together
    # ------------------------------------------------------------
    def elaborate(self, platform):
        m = TModule()

        # Sub‑modules ----------------------------------------------------
        m.submodules += [
            self.fifo_in,
            self.eth_parser,
            self.aligner1,
            self.ip_parser,
            self.aligner2,
            self.udp_parser,
            self.tcp_parser,
            self.ip_src_fifo,
            self.ip_dst_fifo,
            self.ip_len_fifo,
            self.dst_port_fifo,
        ]

        @def_method(m, self._dummy)
        def _(arg):
            # Dummy method for Ethernet parser
            pass

        # IPv4 – save header + stream selected fields into FIFOs ---------
        @def_method(m, self.push_parsed_ip)
        def _(arg):
            with m.If(arg.error_drop == 0):
                self.ip_src_fifo.write(m, {"data": arg.fields.source_ip})
                self.ip_dst_fifo.write(m, {"data": arg.fields.destination_ip})
                self.ip_len_fifo.write(m, {"data": arg.fields.total_length})

        # UDP – save + dst‑port FIFO ------------------------------------
        @def_method(m, self.push_parsed_udp)
        def _(arg):
            with m.If(arg.error_drop == 0):
                self.dst_port_fifo.write(m, {"data": arg.fields.destination_port})

        # TCP – save + dst‑port FIFO ------------------------------------
        @def_method(m, self.push_parsed_tcp)
        def _(arg):
            with m.If(arg.error_drop == 0):
                self.dst_port_fifo.write(m, {"data": arg.fields.destination_port})

        # ------------------- Streaming datapath ------------------------
        # 1. Ethernet parser -------------------------------------------
        with Transaction().body(m):
            word0 = self.fifo_in.read(m)
            eth_out = self.eth_parser.step(m, word0)
            self.aligner1.din(m, eth_out)

        # 2. IPv4 parser -----------------------------------------------
        with Transaction().body(m):
            al1 = self.aligner1.dout(m)
            ip_in = {
                "data": al1["data"],
                "end_of_packet": al1["end_of_packet"],
                "end_of_packet_len": al1["end_of_packet_len"],
            }
            ip_out = self.ip_parser.step(m, ip_in)
            self.aligner2.din(m, ip_out)

        # 3. UDP / TCP selection ---------------------------------------
        with Transaction().body(m):
            al2 = self.aligner2.dout(m)
            tr_in = {
                "data": al2["data"],
                "end_of_packet": al2["end_of_packet"],
                "end_of_packet_len": al2["end_of_packet_len"],
            }
            IpProtoOut = IPv4Parser.ProtoOut
            with condition(m) as branch:
                with branch(al2["next_proto"] == IpProtoOut.UDP):
                    self.udp_parser.step(m, tr_in)
                with branch(al2["next_proto"] == IpProtoOut.TCP):
                    self.tcp_parser.step(m, tr_in)

        return m


def bytes_to_int_le(b: bytes) -> int:
    return int.from_bytes(b, "little")


def split_chunks(buf: bytes, size: int = 64):
    return [
        (buf[i : i + size]).ljust(size, b"\0") for i in range(0, len(buf), size)
    ] or [b"".ljust(size, b"\0")]


# ------------------ L2 / L3 reference parsers ----------------------


def parse_ethernet(pkt: bytes):
    parsed = {
        "dst_mac": int.from_bytes(pkt[0:6], "big") if len(pkt) >= 6 else 0,
        "src_mac": int.from_bytes(pkt[6:12], "big") if len(pkt) >= 12 else 0,
        "vlan": 0,
        "vlan_v": 0,
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
    blank = {
        k: 0
        for k in [
            "version",
            "header_length",
            "type_of_service",
            "total_length",
            "identification",
            "flags",
            "fragment_offset",
            "time_to_live",
            "protocol",
            "header_checksum",
            "source_ip",
            "destination_ip",
        ]
    }
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

    parsed["type_of_service"] = pkt[ip_off + 1]
    parsed["total_length"] = int.from_bytes(pkt[ip_off + 2 : ip_off + 4], "big")
    parsed["identification"] = int.from_bytes(pkt[ip_off + 4 : ip_off + 6], "big")
    flags_frag = int.from_bytes(pkt[ip_off + 6 : ip_off + 8], "big")
    parsed["flags"] = flags_frag >> 13
    parsed["fragment_offset"] = flags_frag & 0x1FFF
    parsed["time_to_live"] = pkt[ip_off + 8]
    proto = pkt[ip_off + 9]
    parsed["protocol"] = proto
    parsed["header_checksum"] = int.from_bytes(pkt[ip_off + 10 : ip_off + 12], "big")
    parsed["source_ip"] = int.from_bytes(pkt[ip_off + 12 : ip_off + 16], "big")
    parsed["destination_ip"] = int.from_bytes(pkt[ip_off + 16 : ip_off + 20], "big")
    parsed["header_len"] = hdr_bytes
    return parsed


# ------------------ L4 reference parsers ---------------------------


def parse_udp(pkt: bytes, l4_off: int):
    blank = {k: 0 for k in ["source_port", "destination_port", "length", "checksum"]}
    parsed = {**blank, "error_drop": 0}
    if len(pkt) < l4_off + 8:
        parsed["error_drop"] = 1
        return parsed
    parsed["source_port"] = int.from_bytes(pkt[l4_off : l4_off + 2], "big")
    parsed["destination_port"] = int.from_bytes(pkt[l4_off + 2 : l4_off + 4], "big")
    parsed["length"] = int.from_bytes(pkt[l4_off + 4 : l4_off + 6], "big")
    parsed["checksum"] = int.from_bytes(pkt[l4_off + 6 : l4_off + 8], "big")
    parsed["header_len"] = 8
    return parsed


def parse_tcp(pkt: bytes, l4_off: int):
    blank = {
        k: 0
        for k in [
            "source_port",
            "destination_port",
            "sequence_number",
            "acknowledgment_number",
            "data_offset",
            "reserved",
            "flags",
            "window_size",
            "checksum",
            "urgent_pointer",
        ]
    }
    parsed = {**blank, "error_drop": 0}
    if len(pkt) < l4_off + 20:  # minimum TCP header
        parsed["error_drop"] = 1
        return parsed

    parsed["source_port"] = int.from_bytes(pkt[l4_off : l4_off + 2], "big")
    parsed["destination_port"] = int.from_bytes(pkt[l4_off + 2 : l4_off + 4], "big")
    parsed["sequence_number"] = int.from_bytes(pkt[l4_off + 4 : l4_off + 8], "big")
    parsed["acknowledgment_number"] = int.from_bytes(
        pkt[l4_off + 8 : l4_off + 12], "big"
    )

    byte12 = pkt[l4_off + 12]
    parsed["data_offset"] = byte12 >> 4
    parsed["reserved"] = byte12 & 0x0F
    parsed["flags"] = pkt[l4_off + 13]
    parsed["window_size"] = int.from_bytes(pkt[l4_off + 14 : l4_off + 16], "big")
    parsed["checksum"] = int.from_bytes(pkt[l4_off + 16 : l4_off + 18], "big")
    parsed["urgent_pointer"] = int.from_bytes(pkt[l4_off + 18 : l4_off + 20], "big")

    hdr_len = parsed["data_offset"] * 4
    parsed["header_len"] = hdr_len
    if len(pkt) < l4_off + hdr_len:
        parsed["error_drop"] = 1
    return parsed


class TestEthernetIPv4TCPUDPParser(TestCaseWithSimulator):
    def setup_method(self):
        """Generate random TCP and UDP packets for the parser chain."""
        seed(42)

        def rand_ip():
            return f"192.168.{randint(0,255)}.{randint(1,254)}"

        num_pkts = 20
        pkts = []
        for i in range(num_pkts):
            eth = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            ip = IP(src=rand_ip(), dst=rand_ip())
            if random() < 0.5:
                l4 = UDP(sport=randint(1024, 65535), dport=randint(1024, 65535))
            else:
                l4 = TCP(sport=randint(1024, 65535), dport=randint(1024, 65535))
            payload = bytes(randint(0, 255) for _ in range(randint(0, 60)))
            pkt = eth / ip / l4 / Raw(payload)
            pkt.time = i * 0.001
            pkts.append(pkt)

        self.inputs = []
        self.exp_eth = []
        self.exp_ip = []
        self.exp_udp = []
        self.exp_tcp = []
        base_sc = pkts[0].time
        for sc in pkts:
            raw = bytes(sc)
            eth = parse_ethernet(raw)
            ip = (
                parse_ipv4(raw, eth.get("header_len", 0))
                if eth["ethertype"] == 0x0800
                else {"error_drop": 1}
            )

            pkt_ts = sc.time - base_sc
            in_chunks = split_chunks(raw, 64)
            for i, ch in enumerate(in_chunks):
                last = i == len(in_chunks) - 1
                eop_len = len(raw) % 64 if last else 0
                eop_len = 64 if last and eop_len == 0 and raw else eop_len
                self.inputs.append(
                    {
                        "data": bytes_to_int_le(ch),
                        "end_of_packet": last,
                        "end_of_packet_len": eop_len,
                        "timestamp": pkt_ts,
                    }
                )

            self.exp_eth.append(eth)
            self.exp_ip.append(ip)

            if ip.get("error_drop", 1) == 0:
                l4_off = eth["header_len"] + ip["header_len"]
                if ip["protocol"] == 17:
                    self.exp_udp.append(parse_udp(raw, l4_off))
                elif ip["protocol"] == 6:
                    self.exp_tcp.append(parse_tcp(raw, l4_off))

    # ------------ driver / checker processes ---------------------
    # Only move to the next word if the res in not None
    async def _drive_din(self, sim):
        cycle = 0
        print("length of inputs: ", len(self.inputs))
        while self.inputs:
            t_sim = cycle * CYCLE_TIME

            if t_sim < self.inputs[0]["timestamp"]:
                await sim.tick()
                cycle += 1
                continue

            word = {k: v for k, v in self.inputs[0].items() if k != "timestamp"}
            res = await self.eptc.din.call_try(sim, word)
            cycle += 1
            if res is not None:
                self.inputs.pop(0)
            else:
                print("din waiting")

    async def _check_parsed(self, sim):
        udp_idx = 0
        tcp_idx = 0
        for eth, ip in zip(self.exp_eth, self.exp_ip):

            # IPv4 ----------------------------------------------
            while random() > 0.7:
                await sim.tick()

            if ip.get("error_drop", 1) == 0:
                # --- NEW: check src/dst/len via FIFOs ----------
                got_src, got_dst, got_len = (
                    await CallTrigger(sim)
                    .call(self.eptc.get_src_ip)
                    .call(self.eptc.get_dst_ip)
                    .call(self.eptc.get_tot_len)
                    .until_all_done()
                )
                assert int(got_src["data"]) == ip["source_ip"]
                assert int(got_dst["data"]) == ip["destination_ip"]
                assert int(got_len["data"]) == ip["total_length"]

            # Destination‑port check moved to separate process
            if ip.get("error_drop", 1):
                continue
            if ip["protocol"] == 17:  # UDP
                udp_idx += 1
            elif ip["protocol"] == 6:  # TCP
                tcp_idx += 1

    # NEW --------------------------------------------------------
    async def _check_dst_port(self, sim):
        """Independent process that checks destination ports from the
        dedicated FIFO, one‑by‑one, in the original packet order."""
        udp_idx = 0
        tcp_idx = 0
        for ip in self.exp_ip:
            if ip.get("error_drop", 1):
                continue
            if ip["protocol"] == 17:  # UDP
                exp_udp = self.exp_udp[udp_idx]
                udp_idx += 1
                while random() > 0.7:
                    await sim.tick()
                got_dp = await self.eptc.get_dst_port.call(sim)
                assert int(got_dp["data"]) == exp_udp["destination_port"]
            elif ip["protocol"] == 6:  # TCP
                exp_tcp = self.exp_tcp[tcp_idx]
                tcp_idx += 1
                while random() > 0.7:
                    await sim.tick()
                got_dp = await self.eptc.get_dst_port.call(sim)
                assert int(got_dp["data"]) == exp_tcp["destination_port"]

    # --------------------------- test entry ----------------------
    def test_random(self):
        self.eptc = SimpleTestCircuit(parser_aligner())
        with self.run_simulation(self.eptc) as sim:
            sim.add_testbench(self._drive_din)
            sim.add_testbench(self._check_parsed)
            sim.add_testbench(self._check_dst_port)
