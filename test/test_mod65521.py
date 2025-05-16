# tests/test_mod65521.py
from __future__ import annotations

from random import randint, random, seed

from transactron.testing import TestCaseWithSimulator, SimpleTestCircuit

# DUT -------------------------------------------------------------------
from mur.count.mod65521 import Mod65521


class TestMod65521(TestCaseWithSimulator):
    """Randomised functional TB for ``Mod65521`` (mod 65 521 reducer)."""

    # ------------------------------------------------------------------
    #  Stimulus generation
    # ------------------------------------------------------------------
    def setup_method(self):
        seed(42)

        self.sample_count = 10_000  # number of test vectors
        self.inputs: list[int] = []  # queued operands
        self.expected: list[int] = []  # reference residues

        # Build a mix of edge-cases + random 1- to 4-limb words
        edge_cases = [
            0x0000_0000_0000_0000,
            0x0000_0000_0000_FFFF,
            0xFFFF_FFFF_FFFF_FFFF,
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

        # Keep indices for driver / checker coroutines
        self._in_idx = 0
        self._out_idx = 0

    # ------------------------------------------------------------------
    #  Driver – feeds operands into *calc*
    # ------------------------------------------------------------------
    async def _drive_calc(self, sim):
        while self._in_idx < len(self.inputs):
            # Sprinkle random idle cycles
            while random() > 0.6:
                await sim.tick()
            x = self.inputs[self._in_idx]
            resp = await self.dut.calc.call_try(sim, {"data": x})
            # Store result for the checker
            assert self.expected[self._in_idx] == resp["mod"]
            self._in_idx += 1

    # ------------------------------------------------------------------
    #  Top-level test (entry-point)
    # ------------------------------------------------------------------
    def test_randomised(self):
        core = Mod65521(input_width=64)
        self.dut = SimpleTestCircuit(core)

        with self.run_simulation(self.dut) as sim:
            sim.add_testbench(self._drive_calc)
