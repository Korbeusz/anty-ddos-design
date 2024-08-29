from mur.params import Params
from mur.extract.aligner import ParserAligner

from transactron.testing import TestCaseWithSimulator, SimpleTestCircuit, def_method_mock

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
            [randint(0x0, 0xFF) for _ in range(randint(self.octets_in_word, self.octets_in_word * 3))]
            for _ in range(self.packets)
        ]

        self.inputq = deque()
        self.outputq = deque()

        def data_word_from_index(p: list[int], i: int):
            res = 0
            for si in range(i * self.octets_in_word, min(len(p), (i + 1) * self.octets_in_word)):
                res |= p[si] << 8 * (si % self.octets_in_word)
            return res

        def end_of_packet_from_index(p: list[int], i: int):
            return 0 if len(p) > (i + 1) * self.octets_in_word else len(p) - i * self.octets_in_word

        for p in self.packets:
            fully_consumed_words = randint(0, max(0, (len(p) // self.octets_in_word) - 1))
            partial_consumed_length_qo = (
                0
                if len(p) < 4
                else (randint(4, min(self.octets_in_word, len(p) - fully_consumed_words * self.octets_in_word)) // 4)
            )
            next_proto = randint(0, 1)
            error = randint(0, 1)

            for i in range(fully_consumed_words):
                self.inputq.append(
                    {
                        "data": data_word_from_index(p, i),
                        "quadoctets_consumed": self.octets_in_word // 4,
                        "end_of_packet": 0,
                        "next_proto": 0,
                        "error": 0,
                    }
                )

            self.inputq.append(
                {
                    "data": data_word_from_index(p, fully_consumed_words),
                    "quadoctets_consumed": partial_consumed_length_qo,
                    "end_of_packet": end_of_packet_from_index(p, fully_consumed_words),
                    "next_proto": next_proto,
                    "error": error if end_of_packet_from_index(p, fully_consumed_words) else 0,
                }
            )

            for i in range(fully_consumed_words + 1, (len(p) + self.octets_in_word - 1) // self.octets_in_word):
                self.inputq.append(
                    {
                        "data": data_word_from_index(p, i),
                        "quadoctets_consumed": 0,
                        "end_of_packet": end_of_packet_from_index(p, i),
                        "next_proto": 0,
                        "error": error if end_of_packet_from_index(p, i) else 0,
                    }
                )

            remaining = p[fully_consumed_words * self.octets_in_word + partial_consumed_length_qo * 4 :]
            for i in range((len(remaining) + self.octets_in_word - 1) // self.octets_in_word):
                self.outputq.append(
                    {
                        "data": data_word_from_index(remaining, i),
                        "end_of_packet": end_of_packet_from_index(remaining, i),
                        "next_proto": next_proto,
                        "error": error if end_of_packet_from_index(remaining, i) else 0,
                    }
                )

    @def_method_mock(lambda self: self.dut.din, enable=lambda self: self.inputq and random() < 0.6)
    def din_process(self):
        print("i", self.inputq[0])
        print(f"{self.inputq[0]['data']:x}")
        print(f"{self.inputq[0]['data']>>(self.inputq[0]['quadoctets_consumed']*4*8):x}")
        if self.inputq[0]["end_of_packet"]:
            print("===========")
        return self.inputq.popleft()

    @def_method_mock(lambda self: self.dut.dout)
    def dout_process(self, arg):
        print("oo", arg)
        print(f"{arg['data']:x}")
        assert arg == self.outputq.popleft()

    def active_process(self):
        while self.outputq:
            yield

    def test_randomized(self):
        self.dut = SimpleTestCircuit(ParserAligner())
        with self.run_simulation(self.dut) as sim:
            sim.add_sync_process(self.active_process)
