from transactron.testing import *
from mur.extract.parsers.ipv4_parser import IPv4Parser
from transactron.lib import Adapter
from transactron.core import *
from transactron.lib.adapters import AdapterTrans
from random import randint, random, seed


class IPv4ParserTestCircuit(Elaboratable):
    def __init__(self):
        pass

    def elaborate(self, platform):
        m = Module()

        pushed_parsed_layout = [
            ("fields", IPv4Parser.ResultLayouts().fields),  # sub-layout
            ("error_drop", 1),
        ]

        m.submodules.mock_push_parsed = self.mock_push_parsed = TestbenchIO(
            Adapter.create(i=pushed_parsed_layout)
        )
        m.submodules.parser = self.parser = IPv4Parser(
            push_parsed=self.mock_push_parsed.adapter.iface
        )
        m.submodules.step_adapter = self.step_adapter = TestbenchIO(
            AdapterTrans(self.parser.step)
        )
        return m


def bytes_to_int_le(data: bytes) -> int:
    """Helper to convert a bytes object to a little-endian integer for 'data'."""
    return int.from_bytes(data, byteorder="little")


class TestIPv4Parser(TestCaseWithSimulator):

    def setup_method(self):
        # ### Input #1: Single-chunk IPv4 packet with IHL=5 (64 bytes total)
        ipv4_bytes_1 = bytes.fromhex(
            "450000401234000040060000c0a801010a000001"  # 20 bytes header
            + "11" * 44  # 44 bytes payload
        )
        ipv4_in_1 = {
            "data": bytes_to_int_le(ipv4_bytes_1),
            "end_of_packet": True,
            "end_of_packet_len": 64,
        }
        ipv4_expected_1 = {
            "version": 4,
            "header_length": 5,
            "type_of_service": 0,
            "total_length": 64,
            "identification": 0x1234,
            "flags": 0,
            "fragment_offset": 0,
            "time_to_live": 64,
            "protocol": 6,
            "header_checksum": 0,
            "source_ip": 0xC0A80101,
            "destination_ip": 0x0A000001,
            "options": 0,  # No options
            "error_drop": 0,
        }

        # ### Input #2: Multi-chunk IPv4 packet with IHL=6 (68 bytes total)
        ipv4_bytes_2 = bytes.fromhex(
            "460000441234000040060000c0a801010a000001"  # 24 bytes header (IHL=6)
            + "01020304"  # 4 bytes options
            + "11" * 44  # 44 bytes payload
        )
        chunk1_2 = ipv4_bytes_2[:64]  # First 64 bytes
        chunk2_2 = ipv4_bytes_2[64:]  # Last 4 bytes

        multi_ipv4_in_2_chunk1 = {
            "data": bytes_to_int_le(chunk1_2),
            "end_of_packet": False,
            "end_of_packet_len": 0,
        }
        multi_ipv4_in_2_chunk2 = {
            "data": bytes_to_int_le(chunk2_2.ljust(64, b"\x00")),
            "end_of_packet": True,
            "end_of_packet_len": 4,
        }
        ipv4_expected_2 = {
            "version": 4,
            "header_length": 6,
            "type_of_service": 0,
            "total_length": 68,
            "identification": 0x1234,
            "flags": 0,
            "fragment_offset": 0,
            "time_to_live": 64,
            "protocol": 6,
            "header_checksum": 0,
            "source_ip": 0xC0A80101,
            "destination_ip": 0x0A000001,
            "options": 0x01020304,  # Present but not checked
            "error_drop": 0,
        }

        # ### Input #3: Multi-chunk IPv4 packet with IHL=5 (100 bytes total)
        ipv4_bytes_3 = bytes.fromhex(
            "450000641234000040060000c0a801010a000001"  # 20 bytes header
            + "22" * 80  # 80 bytes payload
        )
        chunk1_3 = ipv4_bytes_3[:64]
        chunk2_3 = ipv4_bytes_3[64:]

        multi_ipv4_in_3_chunk1 = {
            "data": bytes_to_int_le(chunk1_3.ljust(64, b"\x00")),
            "end_of_packet": False,
            "end_of_packet_len": 0,
        }
        multi_ipv4_in_3_chunk2 = {
            "data": bytes_to_int_le(chunk2_3.ljust(64, b"\x00")),
            "end_of_packet": True,
            "end_of_packet_len": 36,
        }
        multi_ipv4_expected_3 = {
            "version": 4,
            "header_length": 5,
            "type_of_service": 0,
            "total_length": 100,
            "identification": 0x1234,
            "flags": 0,
            "fragment_offset": 0,
            "time_to_live": 64,
            "protocol": 6,
            "header_checksum": 0,
            "source_ip": 0xC0A80101,
            "destination_ip": 0x0A000001,
            "options": 0,
            "error_drop": 0,
        }

        # ### Input #4: Runt packet (12 bytes total, incomplete header)
        short_bytes_4 = bytes.fromhex("450000401234")  # 12 bytes (partial header)
        short_in_4 = {
            "data": bytes_to_int_le(short_bytes_4.ljust(64, b"\x00")),
            "end_of_packet": True,
            "end_of_packet_len": 12,
        }
        short_expected_4 = {
            "version": 4,
            "header_length": 5,
            "type_of_service": 0,
            "total_length": 0,
            "identification": 0,
            "flags": 0,
            "fragment_offset": 0,
            "time_to_live": 0,
            "protocol": 0,
            "header_checksum": 0,
            "source_ip": 0,
            "destination_ip": 0,
            "options": 0,
            "error_drop": 1,
        }

        # ### Input #5: Single-chunk IPv4 packet with IHL=15 (64 bytes total)
        ipv4_bytes_5 = bytes.fromhex(
            "4F0000401234000040060000c0a801010a000001"  # 20 bytes fixed header
            + "00" * 40  # 40 bytes options
            + "11" * 4  # 4 bytes payload
        )
        ipv4_in_5 = {
            "data": bytes_to_int_le(ipv4_bytes_5),
            "end_of_packet": True,
            "end_of_packet_len": 64,
        }
        ipv4_expected_5 = {
            "version": 4,
            "header_length": 15,
            "type_of_service": 0,
            "total_length": 64,
            "identification": 0x1234,
            "flags": 0,
            "fragment_offset": 0,
            "time_to_live": 64,
            "protocol": 6,
            "header_checksum": 0,
            "source_ip": 0xC0A80101,
            "destination_ip": 0x0A000001,
            "options": 0,
            "error_drop": 0,
        }

        # ### Input #6: Three-chunk IPv4 packet with IHL=5 (192 bytes total)
        ipv4_bytes_6 = bytes.fromhex(
            "450000C01234000040060000c0a801010a000001"  # 20 bytes header, total_length=192 (0x00C0)
            + "33" * 172  # 172 bytes payload
        )
        chunk1_6 = ipv4_bytes_6[:64]
        chunk2_6 = ipv4_bytes_6[64:128]
        chunk3_6 = ipv4_bytes_6[128:]

        multi_ipv4_in_6_chunk1 = {
            "data": bytes_to_int_le(chunk1_6),
            "end_of_packet": False,
            "end_of_packet_len": 0,
        }
        multi_ipv4_in_6_chunk2 = {
            "data": bytes_to_int_le(chunk2_6),
            "end_of_packet": False,
            "end_of_packet_len": 0,
        }
        multi_ipv4_in_6_chunk3 = {
            "data": bytes_to_int_le(chunk3_6),
            "end_of_packet": True,
            "end_of_packet_len": 64,
        }
        ipv4_expected_6 = {
            "version": 4,
            "header_length": 5,
            "type_of_service": 0,
            "total_length": 192,
            "identification": 0x1234,
            "flags": 0,
            "fragment_offset": 0,
            "time_to_live": 64,
            "protocol": 6,
            "header_checksum": 0,
            "source_ip": 0xC0A80101,
            "destination_ip": 0x0A000001,
            "options": 0,
            "error_drop": 0,
        }

        # ### Input #7: Two-chunk IPv4 packet with IHL=5 (128 bytes total)
        ipv4_bytes_7 = bytes.fromhex(
            "450000801234000040110000c0a801010a000001"  # 20 bytes header, total_length=128 (0x0080)
            + "44" * 108  # 108 bytes payload
        )
        chunk1_7 = ipv4_bytes_7[:64]  # First 64 bytes
        chunk2_7 = ipv4_bytes_7[64:128]  # Last 64 bytes

        multi_ipv4_in_7_chunk1 = {
            "data": bytes_to_int_le(chunk1_7),
            "end_of_packet": False,
            "end_of_packet_len": 0,
        }
        multi_ipv4_in_7_chunk2 = {
            "data": bytes_to_int_le(chunk2_7),
            "end_of_packet": True,
            "end_of_packet_len": 64,
        }
        ipv4_expected_7 = {
            "version": 4,
            "header_length": 5,
            "type_of_service": 0,
            "total_length": 128,
            "identification": 0x1234,
            "flags": 0,
            "fragment_offset": 0,
            "time_to_live": 64,
            "protocol": 17,
            "header_checksum": 0,
            "source_ip": 0xC0A80101,
            "destination_ip": 0x0A000001,
            "options": 0,
            "error_drop": 0,
        }

        # ### All inputs, in the order we'll feed them
        self.input_packets = [
            ipv4_in_1,
            multi_ipv4_in_2_chunk1,
            multi_ipv4_in_2_chunk2,
            multi_ipv4_in_3_chunk1,
            multi_ipv4_in_3_chunk2,
            short_in_4,
            ipv4_in_5,
            multi_ipv4_in_6_chunk1,
            multi_ipv4_in_6_chunk2,
            multi_ipv4_in_6_chunk3,
            multi_ipv4_in_7_chunk1,  # New chunk 1
            # multi_ipv4_in_7_chunk2,  # New chunk 2
        ]

        # ### Expected pushes (one per entire packet)
        self.expected_parsed = [
            ipv4_expected_1,
            ipv4_expected_2,
            multi_ipv4_expected_3,
            short_expected_4,
            ipv4_expected_5,
            ipv4_expected_6,
            ipv4_expected_7,  # New expected result
        ]

        # ### Expected step outputs (one per chunk)
        self.expected_step_outputs = [
            # 1. ipv4_in_1 (IHL=5)
            {
                "octets_consumed": 10,
                "extract_range_end": 1,
                "next_proto": IPv4Parser.ProtoOut.TCP,
                "end_of_packet_len": 64,
                "end_of_packet": 1,
                "error_drop": 0,
            },
            # 2. multi_ipv4_in_2_chunk1 (IHL=6)
            {
                "octets_consumed": 12,
                "extract_range_end": 1,
                "next_proto": IPv4Parser.ProtoOut.TCP,
                "end_of_packet_len": 0,
                "end_of_packet": 0,
                "error_drop": 0,
            },
            # 3. multi_ipv4_in_2_chunk2
            {
                "octets_consumed": 0,
                "extract_range_end": 0,
                "next_proto": 0,
                "end_of_packet_len": 4,
                "end_of_packet": 1,
                "error_drop": 0,
            },
            # 4. multi_ipv4_in_3_chunk1 (IHL=5)
            {
                "octets_consumed": 10,
                "extract_range_end": 1,
                "next_proto": IPv4Parser.ProtoOut.TCP,
                "end_of_packet_len": 0,
                "end_of_packet": 0,
                "error_drop": 0,
            },
            # 5. multi_ipv4_in_3_chunk2
            {
                "octets_consumed": 0,
                "extract_range_end": 0,
                "next_proto": 0,
                "end_of_packet_len": 36,
                "end_of_packet": 1,
                "error_drop": 0,
            },
            # 6. short_in_4
            {
                "octets_consumed": 10,
                "extract_range_end": 1,
                "next_proto": 0,
                "end_of_packet_len": 12,
                "end_of_packet": 1,
                "error_drop": 1,
            },
            # 7. ipv4_in_5 (IHL=15)
            {
                "octets_consumed": 30,
                "extract_range_end": 1,
                "next_proto": IPv4Parser.ProtoOut.TCP,
                "end_of_packet_len": 64,
                "end_of_packet": 1,
                "error_drop": 0,
            },
            # 8. multi_ipv4_in_6_chunk1 (IHL=5)
            {
                "octets_consumed": 10,
                "extract_range_end": 1,
                "next_proto": IPv4Parser.ProtoOut.TCP,
                "end_of_packet_len": 0,
                "end_of_packet": 0,
                "error_drop": 0,
            },
            # 9. multi_ipv4_in_6_chunk2
            {
                "octets_consumed": 0,
                "extract_range_end": 0,
                "next_proto": 0,
                "end_of_packet_len": 0,
                "end_of_packet": 0,
                "error_drop": 0,
            },
            # 10. multi_ipv4_in_6_chunk3
            {
                "octets_consumed": 0,
                "extract_range_end": 0,
                "next_proto": 0,
                "end_of_packet_len": 64,
                "end_of_packet": 1,
                "error_drop": 0,
            },
            # 11. multi_ipv4_in_7_chunk1 (IHL=5)
            {
                "octets_consumed": 10,
                "extract_range_end": 1,
                "next_proto": IPv4Parser.ProtoOut.UDP,
                "end_of_packet_len": 0,
                "end_of_packet": 0,
                "error_drop": 0,
            },
            # 12. multi_ipv4_in_7_chunk2
            {
                "octets_consumed": 0,
                "extract_range_end": 0,
                "next_proto": 0,
                "end_of_packet_len": 64,
                "end_of_packet": 1,
                "error_drop": 0,
            },
        ]

    async def din_process(self, sim: TestbenchContext):
        """
        Feed each chunk in self.input_packets to the IPv4Parser's 'step' method
        and verify the output against expected values.
        """
        for i, (pkt, expected) in enumerate(
            zip(self.input_packets, self.expected_step_outputs)
        ):
            while random() >= 0.7:
                await sim.tick()
            out_step = await self.eptc.step_adapter.call(sim, pkt)
            print(
                f"[step] data=0x{pkt['data']:x} eop={pkt['end_of_packet']} "
                f"eop_len={pkt['end_of_packet_len']} => {out_step}"
            )
            assert (
                out_step["error_drop"] == expected["error_drop"]
            ), f"Step {i}: Error drop mismatch"

            # Check fields always present
            assert out_step["data"] == pkt["data"], f"Step {i}: Data mismatch"
            assert (
                out_step["end_of_packet"] == pkt["end_of_packet"]
            ), f"Step {i}: End of packet mismatch"
            assert (
                out_step["end_of_packet_len"] == pkt["end_of_packet_len"]
            ), f"Step {i}: End of packet len mismatch"
            assert (
                out_step["extract_range_end"] == expected["extract_range_end"]
            ), f"Step {i}: Extract range end mismatch"

            # Check parsing-specific fields when extract_range_end is 1
            if out_step["extract_range_end"]:
                assert (
                    out_step["octets_consumed"] == expected["octets_consumed"]
                ), f"Step {i}: Octets consumed mismatch"
                assert (
                    out_step["next_proto"] == expected["next_proto"]
                ), f"Step {i}: Next proto mismatch"
            print(f"din nr {i}")
        print("ending din")

    async def dout_process(self, sim: TestbenchContext):
        """
        We expect one push from the parser per complete packet,
        including runts (error_drop=1).
        """
        while random() >= 0.7:
            await sim.tick()
        for i, expected in enumerate(self.expected_parsed):
            pushed_parsed_layout = await self.eptc.mock_push_parsed.call(sim)
            parsed_fields = pushed_parsed_layout["fields"]
            error_drop = pushed_parsed_layout["error_drop"]

            print(
                f"[push_parsed] Received result #{i} => fields={parsed_fields}, error_drop={error_drop}"
            )

            assert (
                error_drop == expected["error_drop"]
            ), f"Error drop mismatch: got {error_drop}, expected {expected['error_drop']}"
            if error_drop:
                print(f" ✓ Parsed result #{i} matches expected.")
                continue
            assert (
                parsed_fields["version"] == expected["version"]
            ), f"version mismatch: got {parsed_fields['version']}, expected {expected['version']}"
            assert (
                parsed_fields["header_length"] == expected["header_length"]
            ), f"header_length mismatch: got {parsed_fields['header_length']}, expected {expected['header_length']}"
            assert (
                parsed_fields["type_of_service"] == expected["type_of_service"]
            ), f"type_of_service mismatch: got {parsed_fields['type_of_service']}, expected {expected['type_of_service']}"
            assert (
                parsed_fields["total_length"] == expected["total_length"]
            ), f"total_length mismatch: got {parsed_fields['total_length']}, expected {expected['total_length']}"
            assert (
                parsed_fields["identification"] == expected["identification"]
            ), f"identification mismatch: got {parsed_fields['identification']}, expected {expected['identification']}"
            assert (
                parsed_fields["flags"] == expected["flags"]
            ), f"flags mismatch: got {parsed_fields['flags']}, expected {expected['flags']}"
            assert (
                parsed_fields["fragment_offset"] == expected["fragment_offset"]
            ), f"fragment_offset mismatch: got {parsed_fields['fragment_offset']}, expected {expected['fragment_offset']}"
            assert (
                parsed_fields["time_to_live"] == expected["time_to_live"]
            ), f"time_to_live mismatch: got {parsed_fields['time_to_live']}, expected {expected['time_to_live']}"
            assert (
                parsed_fields["protocol"] == expected["protocol"]
            ), f"protocol mismatch: got {parsed_fields['protocol']}, expected {expected['protocol']}"
            assert (
                parsed_fields["header_checksum"] == expected["header_checksum"]
            ), f"header_checksum mismatch: got {parsed_fields['header_checksum']}, expected {expected['header_checksum']}"
            assert (
                parsed_fields["source_ip"] == expected["source_ip"]
            ), f"source_ip mismatch: got {hex(parsed_fields['source_ip'])}, expected {hex(expected['source_ip'])}"
            assert (
                parsed_fields["destination_ip"] == expected["destination_ip"]
            ), f"destination_ip mismatch: got {hex(parsed_fields['destination_ip'])}, expected {hex(expected['destination_ip'])}"
            print(f" ✓ Parsed result #{i} matches expected.")
        print("ending expected")

    def test_ipv4_parser(self):
        """
        Build the test circuit around the IPv4Parser and run the simulation.
        """
        self.eptc = IPv4ParserTestCircuit()
        with self.run_simulation(self.eptc) as sim:
            sim.add_testbench(self.din_process)
            sim.add_testbench(self.dout_process)
