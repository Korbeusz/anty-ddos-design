from amaranth import Module, Elaboratable
from transactron.testing import TestbenchIO

from random import randint, random, seed

from scapy.all import Ether, IP, TCP, UDP, Raw  # type: ignore
from transactron.testing import TestCaseWithSimulator, SimpleTestCircuit
from transactron.lib import Adapter
from transactron.lib.adapters import AdapterTrans

from mur.extract.parsers.ethernet import EthernetParser
from mur.extract.parsers.ipv4_parser import IPv4Parser
from mur.extract.parsers.udp import UDPParser
from mur.extract.parsers.tcp import TCPParser

# Reference helpers copied from test_parsing.py -------------------------

def bytes_to_int_le(b: bytes) -> int:
    return int.from_bytes(b, "little")


def split_chunks(buf: bytes, size: int = 64):
    return [buf[i : i + size].ljust(size, b"\0") for i in range(0, len(buf), size)] or [b"".ljust(size, b"\0")]


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
    if ethertype == 0x8100:
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
        "version", "header_length", "type_of_service", "total_length", "identification",
        "flags", "fragment_offset", "time_to_live", "protocol", "header_checksum",
        "source_ip", "destination_ip"]}
    parsed = {**blank, "error_drop": 0}
    if len(pkt) < ip_off + 20:
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


def parse_udp(pkt: bytes, off: int):
    blank = {k: 0 for k in ["source_port", "destination_port", "length", "checksum"]}
    parsed = {**blank, "error_drop": 0}
    if len(pkt) < off + 8:
        parsed["error_drop"] = 1
        return parsed
    parsed["source_port"] = int.from_bytes(pkt[off : off + 2], "big")
    parsed["destination_port"] = int.from_bytes(pkt[off + 2 : off + 4], "big")
    parsed["length"] = int.from_bytes(pkt[off + 4 : off + 6], "big")
    parsed["checksum"] = int.from_bytes(pkt[off + 6 : off + 8], "big")
    parsed["header_len"] = 8
    return parsed


def parse_tcp(pkt: bytes, off: int):
    blank = {k: 0 for k in [
        "source_port", "destination_port", "sequence_number", "acknowledgment_number",
        "data_offset", "reserved", "flags", "window_size", "checksum", "urgent_pointer"]}
    parsed = {**blank, "error_drop": 0}
    if len(pkt) < off + 20:
        parsed["error_drop"] = 1
        return parsed

    parsed["source_port"] = int.from_bytes(pkt[off : off + 2], "big")
    parsed["destination_port"] = int.from_bytes(pkt[off + 2 : off + 4], "big")
    parsed["sequence_number"] = int.from_bytes(pkt[off + 4 : off + 8], "big")
    parsed["acknowledgment_number"] = int.from_bytes(pkt[off + 8 : off + 12], "big")
    byte12 = pkt[off + 12]
    parsed["data_offset"] = byte12 >> 4
    parsed["reserved"] = byte12 & 0x0F
    parsed["flags"] = pkt[off + 13]
    parsed["window_size"] = int.from_bytes(pkt[off + 14 : off + 16], "big")
    parsed["checksum"] = int.from_bytes(pkt[off + 16 : off + 18], "big")
    parsed["urgent_pointer"] = int.from_bytes(pkt[off + 18 : off + 20], "big")
    hdr_len = parsed["data_offset"] * 4
    parsed["header_len"] = hdr_len
    if len(pkt) < off + hdr_len:
        parsed["error_drop"] = 1
    return parsed

# Generic test harness --------------------------------------------------
class GenericParserCircuit(Elaboratable):
    def __init__(self, parser_cls):
        self.parser_cls = parser_cls
        push_layout = [
            ("fields", self.parser_cls.ResultLayouts().fields),
            ("error_drop", 1),
        ]
        self.mock_push = TestbenchIO(Adapter.create(i=push_layout))
        self.parser = self.parser_cls(push_parsed=self.mock_push.adapter.iface)
        self.step_adapter = TestbenchIO(AdapterTrans(self.parser.step))

    def elaborate(self, platform):
        m = Module()
        m.submodules.mock_push = self.mock_push
        m.submodules.parser = self.parser
        m.submodules.step_adapter = self.step_adapter
        return m


class TestRandomParsers(TestCaseWithSimulator):
    def drive_and_check(self, parser_cls, packets, parse_fn, ip_offset=0):
        seed(42)
        self.inputs = []
        self.expected = []
        for pkt in packets:
            chunks = split_chunks(pkt)
            for i, ch in enumerate(chunks):
                last = i == len(chunks) - 1
                eop_len = len(pkt) % 64 if last else 0
                eop_len = 64 if last and eop_len == 0 and pkt else eop_len
                self.inputs.append({
                    "data": bytes_to_int_le(ch),
                    "end_of_packet": last,
                    "end_of_packet_len": eop_len,
                })
            self.expected.append(parse_fn(pkt, ip_offset) if ip_offset else parse_fn(pkt))
        self.dut = GenericParserCircuit(parser_cls)

        async def _drive(sim):
            for word in self.inputs:
                await self.dut.step_adapter.call(sim, word)
                if random() < 0.3:
                    await sim.tick()

        async def _collect(sim):
            for exp in self.expected:
                res = await self.dut.mock_push.call(sim)
                fields = res["fields"]
                err = int(res["error_drop"])
                assert err == exp["error_drop"]
                if err:
                    continue
                for k, v in exp.items():
                    if k == "error_drop" or k == "header_len":
                        continue
                    assert int(fields[k]) == v

        with self.run_simulation(self.dut) as sim:
            sim.add_testbench(_drive)
            sim.add_testbench(_collect)

    # Packet generators -------------------------------------------------
    def gen_eth_packet(self):
        vlan = random() < 0.5
        dst = bytes(randint(0, 255) for _ in range(6))
        src = bytes(randint(0, 255) for _ in range(6))
        if vlan:
            ethertype = b"\x81\x00"
            vlan_tci = randint(0, 0xFFFF).to_bytes(2, "big")
            inner = randint(0, 1)
            inner_et = [b"\x08\x00", b"\x86\xdd"][inner]
            header = dst + src + ethertype + vlan_tci + inner_et
            min_len = 18
        else:
            et = [b"\x08\x00", b"\x86\xdd"]
            header = dst + src + et[randint(0, 1)]
            min_len = 14
        payload = bytes(randint(0, 255) for _ in range(randint(0, 40)))
        pkt = header + payload
        if random() < 0.2:
            pkt = pkt[:randint(0, min_len - 1)]
        return pkt

    def gen_ip_packet(self):
        src = f"192.168.0.{randint(1,254)}"
        dst = f"192.168.1.{randint(1,254)}"
        ihl = randint(5, 6)
        proto = [1, 6, 17][randint(0,2)]
        payload = bytes(randint(0,255) for _ in range(randint(0,40)))
        ip = IP(src=src, dst=dst, ihl=ihl, proto=proto)/Raw(payload)
        raw = bytes(ip)
        return raw
    def gen_udp_packet(self):
        length = randint(8, 40)
        payload = bytes(randint(0,255) for _ in range(length - 8))
        udp = UDP(sport=randint(0,65535), dport=randint(0,65535), len=length, chksum=0)/Raw(payload)
        raw = bytes(udp)
        if random() < 0.2:
            raw = raw[:randint(0,7)]
        return raw

    def gen_tcp_packet(self):
        doff = randint(5, 6)
        payload = bytes(randint(0,255) for _ in range(randint(0,40)))
        tcp = TCP(sport=randint(0,65535), dport=randint(0,65535), seq=randint(0,100), ack=randint(0,100), dataofs=doff, flags=0)/Raw(payload)
        raw = bytes(tcp)
        if random() < 0.2:
            raw = raw[:randint(0, min(19, len(raw)))]
        return raw

    # Actual tests ------------------------------------------------------
    def test_ethernet_random(self):
        packets = [self.gen_eth_packet() for _ in range(5)]
        self.drive_and_check(EthernetParser, packets, parse_ethernet)

    def test_ipv4_random(self):
        packets = [self.gen_ip_packet() for _ in range(5)]
        self.drive_and_check(IPv4Parser, packets, lambda p, o=0: parse_ipv4(p, 0))

    def test_udp_random(self):
        packets = [self.gen_udp_packet() for _ in range(5)]
        self.drive_and_check(UDPParser, packets, lambda p, o=0: parse_udp(p, 0))

    def test_tcp_random(self):
        packets = [self.gen_tcp_packet() for _ in range(5)]
        self.drive_and_check(TCPParser, packets, lambda p, o=0: parse_tcp(p, 0))

