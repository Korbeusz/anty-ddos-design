# tests/test_mod65521.py
from __future__ import annotations

from random import randint, random, seed

from transactron.testing import TestCaseWithSimulator, SimpleTestCircuit

# DUT -------------------------------------------------------------------
from mur.count.mod65521 import (
    Mod65521,
)  # ← new module path  :contentReference[oaicite:0]{index=0}:contentReference[oaicite:1]{index=1}


class TestMod65521(TestCaseWithSimulator):
    """Randomised functional TB for the new two-stage ``Mod65521`` reducer."""

    # ------------------------------------------------------------------
    #  Stimulus generation
    # ------------------------------------------------------------------
    def setup_method(self):
        seed(42)

        self.sample_count = 10_000
        self.inputs: list[int] = []
        self.expected: list[int] = []

        edge_cases = [
            0x0000_0000_0000_FFFF,
            0xFFFF_FFFF_FFFF_FFFF,
            0x0000_0000_0000_0000,
            0x0000_0000_FFFF_FFFF,
            0x0000_FFFF_FFFF_FFFF,
            0x0123_4567_89AB_CDEF,
        ]
        for x in edge_cases:
            self.inputs.append(x)
            self.expected.append(x % 65_521)

        for _ in range(self.sample_count - len(edge_cases)):
            width = randint(1, 4) * 16  # 16/32/48/64 bits
            mask = (1 << width) - 1
            x = randint(0, mask)
            self.inputs.append(x)
            self.expected.append(x % 65_521)

        self._in_idx = 0  # next operand to feed
        self._out_idx = 0  # next reference result to check

    # ------------------------------------------------------------------
    #  Driver – feeds operands into *input*
    # ------------------------------------------------------------------
    async def _drive_input(self, sim):
        while self._in_idx < len(self.inputs):
            while random() > 0.6:
                await sim.tick()

            word = self.inputs[self._in_idx]
            await self.dut.input.call_try(sim, {"data": word})
            self._in_idx += 1

    # ------------------------------------------------------------------
    #  Checker – polls *result* until each residue becomes valid
    # ------------------------------------------------------------------
    async def _check_result(self, sim):
        while self._out_idx < len(self.expected):
            resp = await self.dut.result.call_try(sim)
            print(f"resp data in hex: {resp['mod']:04X} valid: {resp['valid']}")
            if resp["valid"]:
                got = int(resp["mod"])
                exp = self.expected[self._out_idx]
                assert got == exp, (
                    f"Mismatch at idx {self._out_idx}: "
                    f"got {got:04X}, expected {exp:04X}"
                )
                print(
                    f"calc: {self.inputs[self._out_idx]:016X} "
                    f"-> {got:04X} (expected {exp:04X})"
                )
                self._out_idx += 1

    # ------------------------------------------------------------------
    #  Top-level test (entry-point)
    # ------------------------------------------------------------------
    def test_randomised(self):
        core = Mod65521(input_width=64)
        self.dut = SimpleTestCircuit(core)

        with self.run_simulation(self.dut) as sim:
            sim.add_testbench(self._drive_input)
            sim.add_testbench(self._check_result)
