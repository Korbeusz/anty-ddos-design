from mur.params import Params
from mur.extract.aligner import ParserAligner

from transactron.testing import TestCaseWithSimulator, SimpleTestCircuit

from random import randint, random, seed
from collections import deque


class TestAligner(TestCaseWithSimulator):
    def setup_method(self):
        seed(42)

        self.packets = 1000

        self.input = []

        self.params = Params()
        self.octets_in_word = self.params.word_bits // 8

        self.packets = [
            [randint(0x0, 0xFF) for _ in range(randint(1, self.octets_in_word * 3))]
            for _ in range(self.packets)
        ]

        self.inputq = deque()
        self.outputq = deque()

        def data_word_from_index(p: list[int], i: int):
            res = 0
            for si in range(
                i * self.octets_in_word, min(len(p), (i + 1) * self.octets_in_word)
            ):
                res |= p[si] << 8 * (si % self.octets_in_word)
            return res

        def end_of_packet_from_index(p: list[int], i: int):
            eop = len(p) <= (i + 1) * self.octets_in_word
            return (eop, len(p) - i * self.octets_in_word if eop else 0)

        for p in self.packets:
            fully_consumed_words = randint(
                0, max(0, (len(p) // self.octets_in_word) - 1)
            )
            partial_consumed_length_octets = (
                0
                if len(p) < 1
                else randint(
                    0,
                    min(
                        self.octets_in_word // 2,
                        (len(p) - fully_consumed_words * self.octets_in_word) // 2,
                    ),
                )
                * 2
            )
            next_proto = randint(0, 1)
            error = randint(0, 2) == 0

            for i in range(fully_consumed_words):
                self.inputq.append(
                    {
                        "data": data_word_from_index(p, i),
                        "octets_consumed": self.octets_in_word,
                        "end_of_packet": 0,
                        "end_of_packet_len": 0,
                        "extract_range_end": 0,
                        "next_proto": 0,
                        "error_drop": 0,
                    }
                )

            self.inputq.append(
                {
                    "data": data_word_from_index(p, fully_consumed_words),
                    "octets_consumed": partial_consumed_length_octets,
                    "end_of_packet": end_of_packet_from_index(p, fully_consumed_words)[
                        0
                    ],
                    "end_of_packet_len": end_of_packet_from_index(
                        p, fully_consumed_words
                    )[1],
                    "extract_range_end": 1,
                    "next_proto": next_proto,
                    "error_drop": error,
                }
            )

            for i in range(
                fully_consumed_words + 1,
                (len(p) + self.octets_in_word - 1) // self.octets_in_word,
            ):
                self.inputq.append(
                    {
                        "data": data_word_from_index(p, i),
                        "octets_consumed": 0,
                        "end_of_packet": end_of_packet_from_index(p, i)[0],
                        "end_of_packet_len": end_of_packet_from_index(p, i)[1],
                        "extract_range_end": 0,
                        "next_proto": 0,
                        "error_drop": 0,
                    }
                )

            if not error:
                remaining = p[
                    fully_consumed_words * self.octets_in_word
                    + partial_consumed_length_octets :
                ]
                for i in range(
                    (len(remaining) + self.octets_in_word - 1) // self.octets_in_word
                ):
                    self.outputq.append(
                        {
                            "data": data_word_from_index(remaining, i),
                            "end_of_packet": end_of_packet_from_index(remaining, i)[0],
                            "end_of_packet_len": end_of_packet_from_index(remaining, i)[
                                1
                            ],
                        }
                    )
                if not remaining:
                    self.outputq.append(
                        {
                            "data": 0,
                            "end_of_packet": True,
                            "end_of_packet_len": 0,
                        }
                    )

    async def din_process(self, sim):
        while self.inputq:
            while random() >= 0.6:
                await sim.tick()

            print("i", self.inputq[0])
            print(f"IN{self.inputq[0]['data']:x}")
            print(
                f"IF{self.inputq[0]['data']>>(self.inputq[0]['octets_consumed']*8):x}"
            )

            if self.inputq[0]["end_of_packet"]:
                print("===========")

            await self.dut.din.call_try(sim, self.inputq.popleft())

    async def dout_process(self, sim):
        while self.outputq:
            arg = await self.dut.dout.call(sim)
            print("oo", arg)
            print(f"OT{arg['data']:x}")
            assert arg == self.outputq.popleft()

    def test_randomized(self):
        self.dut = SimpleTestCircuit(ParserAligner())
        with self.run_simulation(self.dut) as sim:
            sim.add_testbench(self.din_process)
            sim.add_testbench(self.dout_process)
