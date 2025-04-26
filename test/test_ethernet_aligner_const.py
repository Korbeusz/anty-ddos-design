from transactron.testing import *
from mur.extract.parsers.ethernet import EthernetParser
from mur.extract.aligner import ParserAligner
from transactron.lib import Adapter
from transactron.core import *
from transactron.lib.adapters import AdapterTrans
from transactron.lib.connectors import ConnectTrans, Forwarder
from transactron.lib.fifo import BasicFifo
from mur.extract.interfaces import ProtoParserLayouts
from scapy.all import rdpcap
from random import randint, random, seed
# Define protocol output constants to match hardware (assumed values)
class ProtoOut:
    IPV4 = 1
    IPV6 = 2
    OTHER = 0

class parser_aligner(Elaboratable):
    def __init__(self):
        self.layouts = ProtoParserLayouts()
        self.answer = Signal(self.layouts.parser_in_layout)
        self.fifo_in = BasicFifo(self.layouts.parser_in_layout, 3)
        self.aligner = ParserAligner()
        self.din = self.fifo_in.write
        self.dout = self.aligner.dout
        pushed_parsed_ethernet_layout = [
            ("fields", EthernetParser.ResultLayouts().fields),  # sub-layout
            ("error_drop", 1),
        ]
        self.last_packet = Signal(EthernetParser.ResultLayouts().fields)
        self.push_parsed_ethernet = Method(i=pushed_parsed_ethernet_layout, o=pushed_parsed_ethernet_layout)
        self.new_ethernet = Signal()
        self.get_ethernet = Method(o=EthernetParser.ResultLayouts().fields)

    def elaborate(self, platform):
        m = TModule()

        m.submodules.fifo_in = self.fifo_in
        m.submodules.aligner = self.aligner
        m.submodules.parser = self.parser = EthernetParser(push_parsed=self.push_parsed_ethernet)

        @def_method(m, self.push_parsed_ethernet, ready=~self.new_ethernet)
        def _(arg):
            m.d.sync += self.last_packet.eq(arg.fields)
            m.d.sync += self.new_ethernet.eq(1)

        @def_method(m, self.get_ethernet, ready=self.new_ethernet)
        def _():
            m.d.sync += self.new_ethernet.eq(0)
            return self.last_packet

        with Transaction().body(m):
            packet = self.fifo_in.read(m)
            self.aligner.din(m, self.parser.step(m, packet))

        return m

def bytes_to_int_le(data: bytes) -> int:
    """Convert bytes to a little-endian integer."""
    return int.from_bytes(data, byteorder="little")

def split_packet_into_chunks(packet_bytes, chunk_size=64):
    """Split packet bytes into chunks of specified size, padding the last chunk if needed."""
    chunks = []
    for i in range(0, len(packet_bytes), chunk_size):
        chunk = packet_bytes[i:i + chunk_size]
        if len(chunk) < chunk_size:
            chunk = chunk.ljust(chunk_size, b'\x00')
        chunks.append(chunk)
    return chunks

def packet_to_input_chunks(packet_bytes, chunk_size=64):
    """Convert packet bytes to a list of input dictionaries for the testbench."""
    chunks = split_packet_into_chunks(packet_bytes, chunk_size)
    input_chunks = []
    for i, chunk in enumerate(chunks):
        is_last = (i == len(chunks) - 1)
        end_of_packet = is_last
        if is_last:
            packet_len = len(packet_bytes)
            end_of_packet_len = packet_len % chunk_size
            if end_of_packet_len == 0 and packet_len > 0:
                end_of_packet_len = chunk_size
        else:
            end_of_packet_len = 0
        input_chunk = {
            "data": bytes_to_int_le(chunk),
            "end_of_packet": end_of_packet,
            "end_of_packet_len": end_of_packet_len
        }
        input_chunks.append(input_chunk)
    return input_chunks

def parse_ethernet_header(packet_bytes):
    """Reference parser to compute expected parsed fields from packet bytes."""
    parsed = {
        "dst_mac": 0,
        "src_mac": 0,
        "vlan": 0,
        "vlan_v": 0,
        "ethertype": 0,
        "error_drop": 0
    }
    if len(packet_bytes) < 14:  # Minimum Ethernet header size
        parsed["error_drop"] = 1
        if len(packet_bytes) >= 6:
            parsed["dst_mac"] = int.from_bytes(packet_bytes[:6], 'big')
            if len(packet_bytes) >= 12:
                parsed["src_mac"] = int.from_bytes(packet_bytes[6:12], 'big')
        return parsed
    parsed["dst_mac"] = int.from_bytes(packet_bytes[:6], 'big')
    parsed["src_mac"] = int.from_bytes(packet_bytes[6:12], 'big')
    ethertype = int.from_bytes(packet_bytes[12:14], 'big')
    if ethertype == 0x8100:  # VLAN tag
        if len(packet_bytes) < 18:  # VLAN header size
            parsed["error_drop"] = 1
            if len(packet_bytes) >= 16:
                parsed["vlan"] = int.from_bytes(packet_bytes[14:16], 'big')
                parsed["vlan_v"] = 1
            return parsed
        parsed["vlan"] = int.from_bytes(packet_bytes[14:16], 'big')
        parsed["vlan_v"] = 1
        ethertype = int.from_bytes(packet_bytes[16:18], 'big')
    parsed["ethertype"] = ethertype
    return parsed

def packet_to_expected_dout(packet_bytes, parsed, chunk_size=64):
    """Compute expected dout outputs by removing the header and splitting payload."""
    if parsed["error_drop"]:
        return []
    header_len = 14 if not parsed["vlan_v"] else 18
    payload = packet_bytes[header_len:]
    chunks = split_packet_into_chunks(payload, chunk_size)
    dout_chunks = []
    for i, chunk in enumerate(chunks):
        is_last = (i == len(chunks) - 1)
        end_of_packet = is_last
        if is_last:
            payload_len = len(payload)
            end_of_packet_len = payload_len % chunk_size
            if end_of_packet_len == 0 and payload_len > 0:
                end_of_packet_len = chunk_size
        else:
            end_of_packet_len = 0
        next_proto = (ProtoOut.IPV4 if parsed["ethertype"] == 0x0800 else
                      ProtoOut.IPV6 if parsed["ethertype"] == 0x86dd else
                      ProtoOut.OTHER)
        if i:
            next_proto = 0
        dout_chunk = {
            "data": bytes_to_int_le(chunk),
            "end_of_packet": end_of_packet,
            "end_of_packet_len": end_of_packet_len,
            "next_proto": next_proto
        }
        dout_chunks.append(dout_chunk)
    return dout_chunks

class TestEthernetParser(TestCaseWithSimulator):
    def setup_method(self):
        """Initialize testbench by reading packets from PCAP file and preparing inputs/outputs."""
        # Load packets from PCAP file
        packets = rdpcap('../example_pcaps/sample_packets.pcap')
        self.input_packets = []
        self.expected_parsed = []
        self.all_expected_dout = []

        for pkt in packets:
            packet_bytes = bytes(pkt)  # Get raw Ethernet frame bytes
            input_chunks = packet_to_input_chunks(packet_bytes)
            parsed = parse_ethernet_header(packet_bytes)
            expected_dout = packet_to_expected_dout(packet_bytes, parsed)
            self.input_packets.extend(input_chunks)
            self.expected_parsed.append(parsed)
            self.all_expected_dout.extend(expected_dout)

    async def din_process(self, sim: TestbenchContext):
        """Feed input chunks to the parser_aligner sequentially."""
        for pkt in self.input_packets:
            while random() >= 0.7:
                await sim.tick()
            await self.eptc.din.call(sim, pkt)

    async def dout_process(self, sim: TestbenchContext):
        """Collect and verify dout outputs against expected values."""
        for i, expected in enumerate(self.all_expected_dout):
            while random() >= 0.7:
                await sim.tick()
            out = await self.eptc.dout.call(sim)
            print(f"[dout] Packet chunk {i}: Received: {out}, Expected: {expected}")
            assert out["data"] == expected["data"], \
                f"Data mismatch at chunk {i}: got 0x{out['data']:x}, expected 0x{expected['data']:x}"
            assert out["end_of_packet"] == expected["end_of_packet"], \
                f"End_of_packet mismatch at chunk {i}: got {out['end_of_packet']}, expected {expected['end_of_packet']}"
            assert out["end_of_packet_len"] == expected["end_of_packet_len"], \
                f"End_of_packet_len mismatch at chunk {i}: got {out['end_of_packet_len']}, expected {expected['end_of_packet_len']}"
            assert out["next_proto"] == expected["next_proto"], \
                f"Next_proto mismatch at chunk {i}: got {out['next_proto']}, expected {expected['next_proto']}"

    async def pushed_parsed_out(self, sim: TestbenchContext):
        """Collect and verify parsed fields against expected values."""
        for i, expected in enumerate(self.expected_parsed):
            while random() >= 0.7:
                await sim.tick()
            parsed_fields = await self.eptc.get_ethernet.call(sim)
            print(f".get_ethernet] Packet {i}: Received fields={parsed_fields}")
            assert parsed_fields["dst_mac"] == expected["dst_mac"], \
                f"dst_mac mismatch at packet {i}: got {hex(parsed_fields['dst_mac'])}, expected {hex(expected['dst_mac'])}"
            assert parsed_fields["src_mac"] == expected["src_mac"], \
                f"src_mac mismatch at packet {i}: got {hex(parsed_fields['src_mac'])}, expected {hex(expected['src_mac'])}"
            if expected["vlan_v"]:
                assert parsed_fields["vlan"] == expected["vlan"], \
                    f"vlan mismatch at packet {i}: got {hex(parsed_fields['vlan'])}, expected {hex(expected['vlan'])}"
            assert parsed_fields["vlan_v"] == expected["vlan_v"], \
                f"vlan_v mismatch at packet {i}: got {parsed_fields['vlan_v']}, expected {expected['vlan_v']}"
            assert parsed_fields["ethertype"] == expected["ethertype"], \
                f"ethertype mismatch at packet {i}: got {hex(parsed_fields['ethertype'])}, expected {hex(expected['ethertype'])}"
            print(f" ✓ Packet {i} parsed fields match expected.")

    def test_ethernet_parser(self):
        """Run the simulation with the test circuit."""
        self.eptc = self.dut = SimpleTestCircuit(parser_aligner())
        with self.run_simulation(self.eptc) as sim:
            sim.add_testbench(self.din_process)
            sim.add_testbench(self.dout_process)
            sim.add_testbench(self.pushed_parsed_out)