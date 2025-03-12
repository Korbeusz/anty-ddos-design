from transactron.testing import *
from mur.extract.parsers.ethernet import EthernetParser
from transactron.lib import Adapter
from transactron.core import *
from transactron.lib.adapters import AdapterTrans
from random import randint, random, seed

class EthernetParserTestCircuit(Elaboratable):
    def __init__(self):
        pass

    def elaborate(self, platform):
        m = Module()

        pushed_parsed_layout = [
            ("fields", EthernetParser.ResultLayouts().fields),  # sub-layout
            ("error_drop", 1),
        ]

        m.submodules.mock_push_parsed = self.mock_push_parsed = TestbenchIO(
            Adapter.create(i=pushed_parsed_layout)
        )
        m.submodules.parser = self.parser = EthernetParser(push_parsed=self.mock_push_parsed.adapter.iface)
        m.submodules.step_adapter = self.step_adapter = TestbenchIO(AdapterTrans(self.parser.step))
        return m


def bytes_to_int_le(data: bytes) -> int:
    """Helper to convert a bytes object to a *little-endian* integer for 'data'."""
    return int.from_bytes(data, byteorder="little")


class TestEthernetParser(TestCaseWithSimulator):

    def setup_method(self):
        # --------------------------------------------------------------------
        # Input #1: Single-chunk Non-VLAN IPv4 packet (64 bytes total)
        # --------------------------------------------------------------------
        non_vlan_bytes_1 = bytes.fromhex(
            "123456789abc"    # DST MAC (6 bytes)
            "aabbccddeeff"    # SRC MAC (6 bytes)
            "0800"            # Ethertype = IPv4 (2 bytes)
            + "11"
            + "00" * 49       # 50 bytes payload => total 64 bytes
        )
        non_vlan_in_1 = {
            "data":              bytes_to_int_le(non_vlan_bytes_1),
            "end_of_packet":     True,
            "end_of_packet_len": 64
        }
        non_vlan_expected_1 = {
            "dst_mac":   0x123456789abc,
            "src_mac":   0xaabbccddeeff,
            "vlan":      0x0,
            "vlan_v":    0x0,
            "ethertype": 0x0800,
            "error_drop": 0
        }

        # --------------------------------------------------------------------
        # Input #2: Single-chunk VLAN IPv6 packet (64 bytes total)
        # --------------------------------------------------------------------
        vlan_bytes_2 = bytes.fromhex(
            "112233445566"  # DST MAC
            "aabbccddeeff"  # SRC MAC
            "8100"          # VLAN Ethertype
            "1122"          # VLAN TCI
            "86dd"          # Next Ethertype = IPv6
            + "11" * 46     # total 64 bytes
        )
        vlan_in_2 = {
            "data":              bytes_to_int_le(vlan_bytes_2),
            "end_of_packet":     True,
            "end_of_packet_len": 64,
        }
        vlan_expected_2 = {
            "dst_mac":   0x112233445566,
            "src_mac":   0xaabbccddeeff,
            "vlan":      0x1122,
            "vlan_v":    0x1,
            "ethertype": 0x86dd,
            "error_drop": 0
        }

        # --------------------------------------------------------------------
        # Inputs #3 (chunk1 + chunk2): Multi-chunk Non-VLAN IPv4 (100 bytes)
        # --------------------------------------------------------------------
        non_vlan_bytes_3 = bytes.fromhex(
            "112233445566"    # DST MAC
            "aabbccddeeff"    # SRC MAC
            "0800"            # Ethertype = IPv4
            + "22" * 86       # total 14 + 86 = 100 bytes
        )
        chunk1_3 = non_vlan_bytes_3[:64]     # first 64 bytes
        chunk2_3 = non_vlan_bytes_3[64:]     # last 36 bytes

        multi_non_vlan_in_3_chunk1 = {
            "data":              bytes_to_int_le(chunk1_3.ljust(64, b'\x00')),
            "end_of_packet":     False,
            "end_of_packet_len": 0,
        }
        multi_non_vlan_in_3_chunk2 = {
            "data":              bytes_to_int_le(chunk2_3.ljust(64, b'\x00')),
            "end_of_packet":     True,
            "end_of_packet_len": 36,  # final partial chunk
        }
        multi_non_vlan_expected_3 = {
            "dst_mac":   0x112233445566,
            "src_mac":   0xaabbccddeeff,
            "vlan":      0x0,
            "vlan_v":    0x0,
            "ethertype": 0x0800,
            "error_drop": 0
        }

        # --------------------------------------------------------------------
        # Inputs #4 (chunk1 + chunk2): Multi-chunk VLAN IPv6 (100 bytes)
        # --------------------------------------------------------------------
        vlan_bytes_4 = bytes.fromhex(
            "112233445566"  # DST MAC
            "aabbccddeeff"  # SRC MAC
            "8100"          # VLAN Ethertype
            "1122"          # VLAN TCI
            "86dd"          # Next Ethertype = IPv6
            + "33" * 82     # total 18 + 82 = 100 bytes
        )
        chunk1_4 = vlan_bytes_4[:64]
        chunk2_4 = vlan_bytes_4[64:]  # 36 bytes

        multi_vlan_in_4_chunk1 = {
            "data":              bytes_to_int_le(chunk1_4.ljust(64, b'\x00')),
            "end_of_packet":     False,
            "end_of_packet_len": 0,
        }
        multi_vlan_in_4_chunk2 = {
            "data":              bytes_to_int_le(chunk2_4.ljust(64, b'\x00')),
            "end_of_packet":     True,
            "end_of_packet_len": 36,
        }
        multi_vlan_expected_4 = {
            "dst_mac":   0x112233445566,
            "src_mac":   0xaabbccddeeff,
            "vlan":      0x1122,
            "vlan_v":    0x1,
            "ethertype": 0x86dd,
            "error_drop": 0
        }

        # --------------------------------------------------------------------
        # Input #5: Only 12 bytes total => Runt (no full 14 bytes)
        # --------------------------------------------------------------------
        short_bytes_5 = bytes.fromhex(
            "112233445566aabbccddeeff"  # 12 bytes total
        )
        short_in_5 = {
            "data":              bytes_to_int_le(short_bytes_5.ljust(64, b'\x00')),
            "end_of_packet":     True,
            "end_of_packet_len": 12,
        }
        short_expected_5 = {
            "dst_mac":   0x112233445566,
            "src_mac":   0xaabbccddeeff,
            "vlan":      0x0,
            "vlan_v":    0x0,
            "ethertype": 0x0,
            "error_drop": 1
        }

        # --------------------------------------------------------------------
        # Input #6: 16 bytes with 0x8100 => VLAN recognized, but still short
        # --------------------------------------------------------------------
        short_vlan_bytes_6 = bytes.fromhex(
            "112233445566aabbccddeeff81001122"  # 16 bytes
        )
        short_in_6 = {
            "data":              bytes_to_int_le(short_vlan_bytes_6.ljust(64, b'\x00')),
            "end_of_packet":     True,
            "end_of_packet_len": 16,
        }
        short_expected_6 = {
            "dst_mac":   0x112233445566,
            "src_mac":   0xaabbccddeeff,
            "vlan":      0x1122,
            "vlan_v":    0x1,
            "ethertype": 0x0,
            "error_drop": 1
        }

        # ----------------------------------------------------
        # All inputs, in the order we'll feed them
        # ----------------------------------------------------
        self.input_packets = [
            non_vlan_in_1,
            vlan_in_2,
            multi_non_vlan_in_3_chunk1,
            multi_non_vlan_in_3_chunk2,
            multi_vlan_in_4_chunk1,
            multi_vlan_in_4_chunk2,
            short_in_5,
            short_in_6,
        ]

        # ----------------------------------------------------
        # Expected pushes (one per entire packet)
        # ----------------------------------------------------
        self.expected_parsed = [
            non_vlan_expected_1,
            vlan_expected_2,
            multi_non_vlan_expected_3,
            multi_vlan_expected_4,
            short_expected_5,
            short_expected_6,
        ]

        # ----------------------------------------------------
        # Expected step outputs (one per chunk)
        # ----------------------------------------------------
        self.expected_step_outputs = [
            # 1. non_vlan_in_1
            {
                "octets_consumed": 14,
                "extract_range_end": 1,
                "next_proto": EthernetParser.ProtoOut.IPV4,
                "end_of_packet_len": 64,
                "end_of_packet": 1,
                "error_drop": 0,
            },
            # 2. vlan_in_2
            {
                "octets_consumed": 18,
                "extract_range_end": 1,
                "next_proto": EthernetParser.ProtoOut.IPV6,
                "end_of_packet_len": 64,
                "end_of_packet": 1,
                "error_drop": 0,
            },
            # 3. multi_non_vlan_in_3_chunk1
            {
                "octets_consumed": 14,
                "extract_range_end": 1,
                "next_proto": EthernetParser.ProtoOut.IPV4,
                "end_of_packet_len": 0,
                "end_of_packet": 0,
                "error_drop": 0,
            },
            # 4. multi_non_vlan_in_3_chunk2
            {
                "extract_range_end": 0,
                "end_of_packet_len": 36,
                "end_of_packet": 1,
                "error_drop": 0,
            },
            # 5. multi_vlan_in_4_chunk1
            {
                "octets_consumed": 18,
                "extract_range_end": 1,
                "next_proto": EthernetParser.ProtoOut.IPV6,
                "end_of_packet_len": 0,
                "end_of_packet": 0,
                "error_drop": 0,
            },
            # 6. multi_vlan_in_4_chunk2
            {
                "extract_range_end": 0,
                "end_of_packet_len": 36,
                "end_of_packet": 1,
                "error_drop": 0,
            },
            # 7. short_in_5
            {
                "octets_consumed": 14,
                "extract_range_end": 1,
                "next_proto": EthernetParser.ProtoOut.UNKNOWN,
                "end_of_packet_len": 12,
                "end_of_packet": 1,
                "error_drop": 1,
            },
            # 8. short_in_6
            {
                "octets_consumed": 18,
                "extract_range_end": 1,
                "next_proto": EthernetParser.ProtoOut.UNKNOWN,
                "end_of_packet_len": 16,
                "end_of_packet": 1,
                "error_drop": 1,
            },
        ]

    async def din_process(self, sim: TestbenchContext):
        """
        Feed each chunk in self.input_packets to the EthernetParser's 'step' method
        and verify the output against expected values.
        """
        for i, (pkt, expected) in enumerate(zip(self.input_packets, self.expected_step_outputs)):
            while random() >= 0.7:
                await sim.tick()
            out_step = await self.eptc.step_adapter.call(sim, pkt)
            print(
                f"[step] data=0x{pkt['data']:x} eop={pkt['end_of_packet']} "
                f"eop_len={pkt['end_of_packet_len']} => {out_step}"
            )

            # Check fields always present
            assert out_step["data"] == pkt["data"], f"Step {i}: Data mismatch"
            assert out_step["end_of_packet"] == pkt["end_of_packet"], f"Step {i}: End of packet mismatch"
            assert out_step["end_of_packet_len"] == pkt["end_of_packet_len"], f"Step {i}: End of packet len mismatch"
            assert out_step["error_drop"] == expected["error_drop"], f"Step {i}: Error drop mismatch"
            assert out_step["extract_range_end"] == expected["extract_range_end"], f"Step {i}: Extract range end mismatch"

            # Check parsing-specific fields when extract_range_end is 1
            if out_step["extract_range_end"]:
                assert out_step["octets_consumed"] == expected["octets_consumed"], f"Step {i}: Octets consumed mismatch"
                assert out_step["next_proto"] == expected["next_proto"], f"Step {i}: Next proto mismatch"

    async def dout_process(self, sim: TestbenchContext):
        """
        We expect one push from the parser per *complete packet*, 
        including runts (error_drop=1).
        """
        for i, expected in enumerate(self.expected_parsed):
            # Wait for push
            pushed_parsed_layout = await self.eptc.mock_push_parsed.call(sim)
            parsed_fields = pushed_parsed_layout["fields"]
            error_drop    = pushed_parsed_layout["error_drop"]

            print(f"[push_parsed] Received result #{i} => fields={parsed_fields}, error_drop={error_drop}")

            # Check error_drop
            assert error_drop == expected["error_drop"], \
                f"Error drop mismatch: got {error_drop}, expected {expected['error_drop']}"

            # Check fields
            assert parsed_fields["dst_mac"]   == expected["dst_mac"], \
                f"dst_mac mismatch: got {hex(parsed_fields['dst_mac'])}, expected {hex(expected['dst_mac'])}"
            assert parsed_fields["src_mac"]   == expected["src_mac"], \
                f"src_mac mismatch: got {hex(parsed_fields['src_mac'])}, expected {hex(expected['src_mac'])}"
            if parsed_fields["vlan_v"]:
                assert parsed_fields["vlan"]      == expected["vlan"], \
                    f"vlan mismatch: got {hex(parsed_fields['vlan'])}, expected {hex(expected['vlan'])}"
            assert parsed_fields["vlan_v"]    == expected["vlan_v"], \
                f"vlan_v mismatch: got {parsed_fields['vlan_v']}, expected {expected['vlan_v']}"
            assert parsed_fields["ethertype"] == expected["ethertype"], \
                f"ethertype mismatch: got {hex(parsed_fields['ethertype'])}, expected {hex(expected['ethertype'])}"

            print(f" ✓ Parsed result #{i} matches expected.")

    def test_ethernet_parser(self):
        """
        Build the test circuit around the EthernetParser and run the simulation.
        """
        self.eptc = EthernetParserTestCircuit()
        with self.run_simulation(self.eptc) as sim:
            sim.add_testbench(self.din_process)
            sim.add_testbench(self.dout_process)