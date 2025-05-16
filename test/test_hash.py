from parameterized import parameterized_class
from random import randint, seed, random

from transactron.testing import TestCaseWithSimulator, SimpleTestCircuit
from mur.count.hash import Hash

MOD65521 = 65_521  # Prime used by the RTL implementation


def ref_hash(x: int, a: int, b: int) -> int:
    """Golden‑model hash: (a · (x mod P) + b) mod P."""
    return (a * x + b) % MOD65521


@parameterized_class(("input_width",), [(32,), (48,), (64,)])
class TestHash(TestCaseWithSimulator):
    input_width: int

    def setup_method(self):
        seed(42)
        self.a = 7
        self.b = 1234
        self.sample_count = 10000
        self.inputs = []
        self.expected = []

        edge_cases = [
            0x0000_0000_0000_FFFF,
            0xFFFF_FFFF_FFFF_FFFF,
            0x0000_0000_0000_0000,
            0x0000_0000_FFFF_FFFF,
            0x0000_FFFF_FFFF_FFFF,
            0x0123_4567_89AB_CDEF,
        ]

        for x in edge_cases:
            masked = x & ((1 << self.input_width) - 1)
            self.inputs.append(masked)
            self.expected.append(ref_hash(masked, self.a, self.b))

        for _ in range(self.sample_count - len(edge_cases)):
            x = randint(0, (1 << self.input_width) - 1)
            self.inputs.append(x)
            self.expected.append(ref_hash(x, self.a, self.b))

        self._in_idx = 0
        self._out_idx = 0

    async def _driver(self, sim):
        print(f"start self.input_width: {self.input_width}")
        while self._in_idx < len(self.inputs):
            word = {"data": self.inputs[self._in_idx]}
            await self.dut.input.call_try(sim, word)
            self._in_idx += 1

    async def _checker(self, sim):
        while self._out_idx < len(self.expected):
            resp = await self.dut.result.call(sim)
            if resp["valid"]:
                # print(f"response data: {resp['hash']}")
                got = int(resp["hash"])
                exp = self.expected[self._out_idx]
                assert (
                    got == exp
                ), f"Mismatch at idx {self._out_idx}: got {got}, expected {exp}"
                self._out_idx += 1

    def test_randomised(self):
        core = Hash(input_width=self.input_width, a=self.a, b=self.b)
        self.dut = SimpleTestCircuit(core)
        with self.run_simulation(self.dut) as sim:
            sim.add_testbench(self._driver)
            sim.add_testbench(self._checker)
