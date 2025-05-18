from transactron.testing import *
from mur.extract.parsers.tcp import TCPParser
from transactron.lib import Adapter
from transactron.core import *
from transactron.lib.adapters import AdapterTrans
from random import randint, random, seed


class TCPParserTestCircuit(Elaboratable):
    def __init__(self):
        pass

    def elaborate(self, platform):
        m = Module()
        pushed_parsed_layout = [
            ("fields", TCPParser.ResultLayouts().fields),
            ("error_drop", 1),
        ]
        m.submodules.mock_push_parsed = self.mock_push_parsed = TestbenchIO(
            Adapter.create(i=pushed_parsed_layout)
        )
        m.submodules.parser = self.parser = TCPParser(
            push_parsed=self.mock_push_parsed.adapter.iface
        )
        m.submodules.step_adapter = self.step_adapter = TestbenchIO(
            AdapterTrans(self.parser.step)
        )
        return m


def bytes_to_int_le(data: bytes) -> int:
    return int.from_bytes(data, byteorder="little")


class TestTCPParser(TestCaseWithSimulator):
    def setup_method(self):
        # **Existing Test Case #1: Single-chunk TCP packet, data_offset=5 (20 bytes header, 64 bytes total)**
        tcp_bytes_1 = bytes.fromhex(
            "12345678"  # source_port=0x1234, destination_port=0x5678
            "00000001"  # sequence_number=1
            "00000002"  # acknowledgment_number=2
            "5000"  # data_offset=5, reserved=0, flags=0
            "0000"  # window_size=0
            "0000"  # checksum=0
            "0000" + "11" * 44  # urgent_pointer=0  # 44 bytes payload
        )
        tcp_in_1 = {
            "data": bytes_to_int_le(tcp_bytes_1),
            "end_of_packet": True,
            "end_of_packet_len": 64,
        }
        tcp_expected_1 = {
            "source_port": 0x1234,
            "destination_port": 0x5678,
            "sequence_number": 1,
            "acknowledgment_number": 2,
            "data_offset": 5,
            "reserved": 0,
            "flags": 0,
            "window_size": 0,
            "checksum": 0,
            "urgent_pointer": 0,
            "error_drop": 0,
        }

        # **Existing Test Case #2: Multi-chunk TCP packet, data_offset=5 (100 bytes total)**
        tcp_bytes_2 = bytes.fromhex(
            "12345678"  # source_port=0x1234, destination_port=0x5678
            "00000001"  # sequence_number=1
            "00000002"  # acknowledgment_number=2
            "5000"  # data_offset=5, reserved=0, flags=0
            "0000"  # window_size=0
            "0000"  # checksum=0
            "0000" + "22" * 80  # urgent_pointer=0  # 80 bytes payload
        )
        chunk1_2 = tcp_bytes_2[:64]
        chunk2_2 = tcp_bytes_2[64:100]
        multi_tcp_in_2_chunk1 = {
            "data": bytes_to_int_le(chunk1_2),
            "end_of_packet": False,
            "end_of_packet_len": 0,
        }
        multi_tcp_in_2_chunk2 = {
            "data": bytes_to_int_le(chunk2_2.ljust(64, b"\x00")),
            "end_of_packet": True,
            "end_of_packet_len": 36,
        }

        # **Existing Test Case #3: Single-chunk with options, data_offset=6 (24 bytes header, 64 bytes total)**
        tcp_bytes_3 = bytes.fromhex(
            "12345678"  # source_port=0x1234, destination_port=0x5678
            "00000001"  # sequence_number=1
            "00000002"  # acknowledgment_number=2
            "6000"  # data_offset=6, reserved=0, flags=0
            "0000"  # window_size=0
            "0000"  # checksum=0
            "0000"  # urgent_pointer=0
            "01020304" + "33" * 40  # 4 bytes options  # 40 bytes payload
        )
        tcp_in_3 = {
            "data": bytes_to_int_le(tcp_bytes_3),
            "end_of_packet": True,
            "end_of_packet_len": 64,
        }
        tcp_expected_3 = {
            "source_port": 0x1234,
            "destination_port": 0x5678,
            "sequence_number": 1,
            "acknowledgment_number": 2,
            "data_offset": 6,
            "reserved": 0,
            "flags": 0,
            "window_size": 0,
            "checksum": 0,
            "urgent_pointer": 0,
            "error_drop": 0,
        }

        # **Existing Test Case #4: Runt packet (12 bytes total)**
        short_bytes_4 = bytes.fromhex("123456780000000100000002")  # 12 bytes
        short_in_4 = {
            "data": bytes_to_int_le(short_bytes_4.ljust(64, b"\x00")),
            "end_of_packet": True,
            "end_of_packet_len": 12,
        }

        # **New Test Case #5: Single-chunk TCP packet with maximal header, data_offset=15 (60 bytes header, 64 bytes total)**
        tcp_bytes_max_header = bytes.fromhex(
            "12345678"  # source_port=0x1234, destination_port=0x5678
            "00000001"  # sequence_number=1
            "00000002"  # acknowledgment_number=2
            "F000"  # data_offset=15 (0xF), reserved=0, flags=0
            "0000"  # window_size=0
            "0000"  # checksum=0
            "0000"  # urgent_pointer=0
            + "00" * 40  # 40 bytes of options
            + "AABBCCDD"  # 4 bytes payload
        )
        assert len(tcp_bytes_max_header) == 64, "Max header packet must be 64 bytes"
        tcp_in_max_header = {
            "data": bytes_to_int_le(tcp_bytes_max_header),
            "end_of_packet": True,
            "end_of_packet_len": 64,
        }
        tcp_expected_max_header = {
            "source_port": 0x1234,
            "destination_port": 0x5678,
            "sequence_number": 1,
            "acknowledgment_number": 2,
            "data_offset": 15,
            "reserved": 0,
            "flags": 0,
            "window_size": 0,
            "checksum": 0,
            "urgent_pointer": 0,
            "error_drop": 0,
        }
        step_output_max_header = {
            "octets_consumed": 60,
            "extract_range_end": 1,
            "end_of_packet_len": 64,
            "end_of_packet": 1,
            "error_drop": 0,
        }

        # **New Test Case #6: Four-chunk TCP packet, data_offset=5 (20 bytes header, 220 bytes total)**
        tcp_bytes_four_chunk = bytes.fromhex(
            "12345678"  # source_port=0x1234, destination_port=0x5678
            "00000001"  # sequence_number=1
            "00000002"  # acknowledgment_number=2
            "5000"  # data_offset=5, reserved=0, flags=0
            "0000"  # window_size=0
            "0000"  # checksum=0
            "0000" + "44" * 200  # urgent_pointer=0  # 200 bytes payload
        )

        assert len(tcp_bytes_four_chunk) == 220, "Four-chunk packet must be 220 bytes"
        chunk1_4 = tcp_bytes_four_chunk[:64]  # 64 bytes: 20 header + 44 payload
        chunk2_4 = tcp_bytes_four_chunk[64:128]  # 64 bytes payload
        chunk3_4 = tcp_bytes_four_chunk[128:192]  # 64 bytes payload
        chunk4_4 = tcp_bytes_four_chunk[192:220].ljust(
            64, b"\x00"
        )  # 28 bytes payload, padded to 64
        multi_tcp_in_4_chunk1 = {
            "data": bytes_to_int_le(chunk1_4),
            "end_of_packet": False,
            "end_of_packet_len": 0,
        }
        multi_tcp_in_4_chunk2 = {
            "data": bytes_to_int_le(chunk2_4),
            "end_of_packet": False,
            "end_of_packet_len": 0,
        }
        multi_tcp_in_4_chunk3 = {
            "data": bytes_to_int_le(chunk3_4),
            "end_of_packet": False,
            "end_of_packet_len": 0,
        }
        multi_tcp_in_4_chunk4 = {
            "data": bytes_to_int_le(chunk4_4),
            "end_of_packet": True,
            "end_of_packet_len": 28,
        }
        tcp_expected_four_chunk = tcp_expected_1  # Same header as tcp_in_1
        step_output_4_chunk1 = {
            "octets_consumed": 20,
            "extract_range_end": 1,
            "end_of_packet_len": 0,
            "end_of_packet": 0,
            "error_drop": 0,
        }
        step_output_4_chunk2 = {
            "octets_consumed": 0,
            "extract_range_end": 0,
            "end_of_packet_len": 0,
            "end_of_packet": 0,
            "error_drop": 0,
        }
        step_output_4_chunk3 = {
            "octets_consumed": 0,
            "extract_range_end": 0,
            "end_of_packet_len": 0,
            "end_of_packet": 0,
            "error_drop": 0,
        }
        step_output_4_chunk4 = {
            "octets_consumed": 0,
            "extract_range_end": 0,
            "end_of_packet_len": 28,
            "end_of_packet": 1,
            "error_drop": 0,
        }
        # Test Case #7: Single-chunk TCP packet with no payload, data_offset=5**
        header_hex = "1234567800000064000000C85F320400ABCD1234"
        tcp_bytes_no_payload = bytes.fromhex(header_hex) + b"\x00" * 44
        tcp_in_no_payload = {
            "data": bytes_to_int_le(tcp_bytes_no_payload),
            "end_of_packet": True,
            "end_of_packet_len": 20,
        }
        tcp_expected_no_payload = {
            "source_port": 0x1234,
            "destination_port": 0x5678,
            "sequence_number": 100,
            "acknowledgment_number": 200,
            "data_offset": 5,
            "reserved": 0xF,
            "flags": 0x32,  # SYN, ACK, URG
            "window_size": 1024,
            "checksum": 0xABCD,
            "urgent_pointer": 0x1234,
            "error_drop": 0,
        }
        step_output_no_payload = {
            "octets_consumed": 20,
            "extract_range_end": 1,
            "end_of_packet_len": 20,
            "end_of_packet": 1,
            "error_drop": 0,
        }
        # **All input packets**
        self.input_packets = [
            tcp_in_1,
            multi_tcp_in_2_chunk1,
            multi_tcp_in_2_chunk2,
            tcp_in_3,
            short_in_4,
            tcp_in_max_header,
            multi_tcp_in_4_chunk1,
            multi_tcp_in_4_chunk2,
            multi_tcp_in_4_chunk3,
            multi_tcp_in_4_chunk4,
            tcp_in_no_payload,
        ]

        # **Expected parsed outputs (one per packet, for first chunk only)**
        self.expected_parsed = [
            tcp_expected_1,  # tcp_in_1
            tcp_expected_1,  # multi_tcp_in_2
            tcp_expected_3,  # tcp_in_3
            {"error_drop": 1},  # short_in_4
            tcp_expected_max_header,  # tcp_in_max_header
            tcp_expected_1,  # multi_tcp_in_4
            tcp_expected_no_payload,
        ]

        # **Expected step outputs (one per chunk)**
        self.expected_step_outputs = [
            # tcp_in_1 (data_offset=5)
            {
                "octets_consumed": 20,
                "extract_range_end": 1,
                "end_of_packet_len": 64,
                "end_of_packet": 1,
                "error_drop": 0,
            },
            # multi_tcp_in_2_chunk1 (data_offset=5)
            {
                "octets_consumed": 20,
                "extract_range_end": 1,
                "end_of_packet_len": 0,
                "end_of_packet": 0,
                "error_drop": 0,
            },
            # multi_tcp_in_2_chunk2
            {
                "octets_consumed": 0,
                "extract_range_end": 0,
                "end_of_packet_len": 36,
                "end_of_packet": 1,
                "error_drop": 0,
            },
            # tcp_in_3 (data_offset=6)
            {
                "octets_consumed": 24,
                "extract_range_end": 1,
                "end_of_packet_len": 64,
                "end_of_packet": 1,
                "error_drop": 0,
            },
            # short_in_4
            {
                "octets_consumed": 0,
                "extract_range_end": 1,
                "end_of_packet_len": 12,
                "end_of_packet": 1,
                "error_drop": 1,
            },
            # tcp_in_max_header (data_offset=15)
            step_output_max_header,
            # multi_tcp_in_4_chunk1 (data_offset=5)
            step_output_4_chunk1,
            # multi_tcp_in_4_chunk2
            step_output_4_chunk2,
            # multi_tcp_in_4_chunk3
            step_output_4_chunk3,
            # multi_tcp_in_4_chunk4
            step_output_4_chunk4,
            step_output_no_payload,
        ]

    async def din_process(self, sim: TestbenchContext):
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
            if out_step["extract_range_end"]:
                assert (
                    out_step["octets_consumed"] == expected["octets_consumed"]
                ), f"Step {i}: Octets consumed mismatch"
            print(f"din nr {i}")
        print("ending din")

    async def dout_process(self, sim: TestbenchContext):
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
                parsed_fields["source_port"] == expected["source_port"]
            ), f"source_port mismatch: got {parsed_fields['source_port']}, expected {expected['source_port']}"
            assert (
                parsed_fields["destination_port"] == expected["destination_port"]
            ), f"destination_port mismatch: got {parsed_fields['destination_port']}, expected {expected['destination_port']}"
            assert (
                parsed_fields["sequence_number"] == expected["sequence_number"]
            ), f"sequence_number mismatch: got {parsed_fields['sequence_number']}, expected {expected['sequence_number']}"
            assert (
                parsed_fields["acknowledgment_number"]
                == expected["acknowledgment_number"]
            ), f"acknowledgment_number mismatch: got {parsed_fields['acknowledgment_number']}, expected {expected['acknowledgment_number']}"
            assert (
                parsed_fields["data_offset"] == expected["data_offset"]
            ), f"data_offset mismatch: got {parsed_fields['data_offset']}, expected {expected['data_offset']}"
            assert (
                parsed_fields["reserved"] == expected["reserved"]
            ), f"reserved mismatch: got {parsed_fields['reserved']}, expected {expected['reserved']}"
            assert (
                parsed_fields["flags"] == expected["flags"]
            ), f"flags mismatch: got {parsed_fields['flags']}, expected {expected['flags']}"
            assert (
                parsed_fields["window_size"] == expected["window_size"]
            ), f"window_size mismatch: got {parsed_fields['window_size']}, expected {expected['window_size']}"
            assert (
                parsed_fields["checksum"] == expected["checksum"]
            ), f"checksum mismatch: got {parsed_fields['checksum']}, expected {expected['checksum']}"
            assert (
                parsed_fields["urgent_pointer"] == expected["urgent_pointer"]
            ), f"urgent_pointer mismatch: got {parsed_fields['urgent_pointer']}, expected {expected['urgent_pointer']}"
            print(f" ✓ Parsed result #{i} matches expected.")
        print("ending expected")

    def test_tcp_parser(self):
        self.eptc = TCPParserTestCircuit()
        with self.run_simulation(self.eptc) as sim:
            sim.add_testbench(self.din_process)
            sim.add_testbench(self.dout_process)
