from transactron.testing import *
from transactron.lib import Adapter
from transactron.core import *
from transactron.lib.adapters import AdapterTrans
from random import random
from mur.extract.parsers.udp import UDPParser

class UDPParserTestCircuit(Elaboratable):
    def __init__(self):
        pass

    def elaborate(self, platform):
        m = Module()
        pushed_parsed_layout = [
            ("fields", UDPParser.ResultLayouts().fields),
            ("error_drop", 1),
        ]
        m.submodules.mock_push_parsed = self.mock_push_parsed = TestbenchIO(
            Adapter.create(i=pushed_parsed_layout)
        )
        m.submodules.parser = self.parser = UDPParser(push_parsed=self.mock_push_parsed.adapter.iface)
        m.submodules.step_adapter = self.step_adapter = TestbenchIO(AdapterTrans(self.parser.step))
        return m

def bytes_to_int_le(data: bytes) -> int:
    return int.from_bytes(data, byteorder="little")

class TestUDPParser(TestCaseWithSimulator):
    def setup_method(self):
        # Test Case #1: Single-chunk UDP packet (16 bytes: 8 header + 8 payload)
        udp_bytes_1 = bytes.fromhex(
            "12345678"  # source_port=0x1234, destination_port=0x5678
            "0010"      # length=16
            "0000"      # checksum=0
            "1122334455667788"  # 8 bytes payload
        ).ljust(64, b'\x00')
        udp_in_1 = {
            "data": bytes_to_int_le(udp_bytes_1),
            "end_of_packet": True,
            "end_of_packet_len": 16
        }
        udp_expected_1 = {
            "source_port": 0x1234,
            "destination_port": 0x5678,
            "length": 16,
            "checksum": 0,
            "error_drop": 0
        }

        # Test Case #2: Multi-chunk UDP packet (100 bytes: 8 header + 92 payload)
        udp_bytes_2 = bytes.fromhex(
            "12345678"  # source_port=0x1234, destination_port=0x5678
            "0064"      # length=100
            "0000"      # checksum=0
            "22" * 92   # 92 bytes payload
        )
        udp_expected_2 = {
            "source_port": 0x1234,
            "destination_port": 0x5678,
            "length": 100,
            "checksum": 0,
            "error_drop": 0
        }
        chunk1_2 = udp_bytes_2[:64]  # 64 bytes: header + 56 payload
        chunk2_2 = udp_bytes_2[64:100].ljust(64, b'\x00')  # 36 bytes payload
        multi_udp_in_2_chunk1 = {
            "data": bytes_to_int_le(chunk1_2),
            "end_of_packet": False,
            "end_of_packet_len": 0,
        }
        multi_udp_in_2_chunk2 = {
            "data": bytes_to_int_le(chunk2_2),
            "end_of_packet": True,
            "end_of_packet_len": 36,
        }

        # Test Case #3: Runt packet (6 bytes)
        short_bytes_3 = bytes.fromhex("123456")  # Partial header
        short_in_3 = {
            "data": bytes_to_int_le(short_bytes_3.ljust(64, b'\x00')),
            "end_of_packet": True,
            "end_of_packet_len": 6,
        }

        # Test Case #4: Minimal UDP packet (8 bytes, no payload)
        udp_bytes_4 = bytes.fromhex(
            "12345678"  # source_port=0x1234, destination_port=0x5678
            "0008"      # length=8
            "0000"      # checksum=0
        ).ljust(64, b'\x00')
        udp_in_4 = {
            "data": bytes_to_int_le(udp_bytes_4),
            "end_of_packet": True,
            "end_of_packet_len": 8
        }
        udp_expected_4 = {
            "source_port": 0x1234,
            "destination_port": 0x5678,
            "length": 8,
            "checksum": 0,
            "error_drop": 0
        }

        self.input_packets = [
            udp_in_1,
            multi_udp_in_2_chunk1,
            multi_udp_in_2_chunk2,
            short_in_3,
            udp_in_4
        ]

        self.expected_parsed = [
            udp_expected_1,    # udp_in_1
            udp_expected_2,    # multi_udp_in_2
            {"error_drop": 1}, # short_in_3
            udp_expected_4     # udp_in_4
        ]

        self.expected_step_outputs = [
            # udp_in_1
            {
                "octets_consumed": 8,
                "extract_range_end": 1,
                "end_of_packet_len": 16,
                "end_of_packet": 1,
                "error_drop": 0,
            },
            # multi_udp_in_2_chunk1
            {
                "octets_consumed": 8,
                "extract_range_end": 1,
                "end_of_packet_len": 0,
                "end_of_packet": 0,
                "error_drop": 0,
            },
            # multi_udp_in_2_chunk2
            {
                "octets_consumed": 0,
                "extract_range_end": 0,
                "end_of_packet_len": 36,
                "end_of_packet": 1,
                "error_drop": 0,
            },
            # short_in_3
            {
                "octets_consumed": 0,
                "extract_range_end": 1,
                "end_of_packet_len": 6,
                "end_of_packet": 1,
                "error_drop": 1,
            },
            # udp_in_4
            {
                "octets_consumed": 8,
                "extract_range_end": 1,
                "end_of_packet_len": 8,
                "end_of_packet": 1,
                "error_drop": 0,
            },
        ]

    async def din_process(self, sim: TestbenchContext):
        for i, (pkt, expected) in enumerate(zip(self.input_packets, self.expected_step_outputs)):
            while random() >= 0.7:
                await sim.tick()
            out_step = await self.eptc.step_adapter.call(sim, pkt)
            print(f"[step] data=0x{pkt['data']:x} eop={pkt['end_of_packet']} "
                  f"eop_len={pkt['end_of_packet_len']} => {out_step}")
            assert out_step["error_drop"] == expected["error_drop"], f"Step {i}: Error drop mismatch"
            assert out_step["data"] == pkt["data"], f"Step {i}: Data mismatch"
            assert out_step["end_of_packet"] == pkt["end_of_packet"], f"Step {i}: End of packet mismatch"
            assert out_step["end_of_packet_len"] == pkt["end_of_packet_len"], f"Step {i}: End of packet len mismatch"
            assert out_step["extract_range_end"] == expected["extract_range_end"], f"Step {i}: Extract range end mismatch"
            if out_step["extract_range_end"]:
                assert out_step["octets_consumed"] == expected["octets_consumed"], f"Step {i}: Octets consumed mismatch"
            print(f"din nr {i}")
        print("ending din")

    async def dout_process(self, sim: TestbenchContext):
        while random() >= 0.7:
            await sim.tick()
        for i, expected in enumerate(self.expected_parsed):
            pushed_parsed_layout = await self.eptc.mock_push_parsed.call(sim)
            parsed_fields = pushed_parsed_layout["fields"]
            error_drop = pushed_parsed_layout["error_drop"]
            print(f"[push_parsed] Received result #{i} => fields={parsed_fields}, error_drop={error_drop}")
            assert error_drop == expected["error_drop"], \
                f"Error drop mismatch: got {error_drop}, expected {expected['error_drop']}"
            if error_drop:
                print(f" ✓ Parsed result #{i} matches expected.")
                continue
            assert parsed_fields["source_port"] == expected["source_port"], \
                f"source_port mismatch: got {parsed_fields['source_port']}, expected {expected['source_port']}"
            assert parsed_fields["destination_port"] == expected["destination_port"], \
                f"destination_port mismatch: got {parsed_fields['destination_port']}, expected {expected['destination_port']}"
            assert parsed_fields["length"] == expected["length"], \
                f"length mismatch: got {parsed_fields['length']}, expected {expected['length']}"
            assert parsed_fields["checksum"] == expected["checksum"], \
                f"checksum mismatch: got {parsed_fields['checksum']}, expected {expected['checksum']}"
            print(f" ✓ Parsed result #{i} matches expected.")
        print("ending expected")

    def test_udp_parser(self):
        self.eptc = UDPParserTestCircuit()
        with self.run_simulation(self.eptc) as sim:
            sim.add_testbench(self.din_process)
            sim.add_testbench(self.dout_process)