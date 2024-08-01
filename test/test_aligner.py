from mur.extract.aligner import ParserAligner
from transactron.testing import TestCaseWithSimulator
from random import randint, random, seed
from collections import deque

from transactron.testing.infrastructure import SimpleTestCircuit
from transactron.testing.sugar import def_method_mock


class TestAligner(TestCaseWithSimulator):

    def setup_method(self):
        seed(42)

        self.packets = 1000

        self.input = []

        self.packets = [[randint(0x0, 0xFF) for _ in range(randint(40, 40 * 3))] for _ in range(self.packets)]

        self.inputq = deque()
        self.outputq = deque()

        def data_word_from_index(p: list[int], i: int):
            res = 0
            for si in range(i * 40, min(len(p), (i + 1) * 40)):
                # little/big endian??
                res |= p[si] << 8 * (si % 40)
            return res

        def end_of_packet_from_index(p: list[int], i: int):
            return 0 if len(p) > (i + 1) * 40 else len(p) - i * 40

        for p in self.packets:
            fully_consumed_words = randint(0, (len(p) // 40) - 1)
            partial_consumed_length_qo = randint(4, min(40, len(p) - fully_consumed_words * 40)) // 4
            next_proto = randint(0, 1)

            for i in range(fully_consumed_words):
                self.inputq.append(
                    {
                        "data": data_word_from_index(p, i),
                        "quadoctets_consumed": 40 // 4,
                        "end_of_packet": 0,
                        "next_proto": 0,
                    }
                )

            self.inputq.append(
                {
                    "data": data_word_from_index(p, fully_consumed_words),
                    "quadoctets_consumed": partial_consumed_length_qo,
                    "end_of_packet": end_of_packet_from_index(p, fully_consumed_words),
                    "next_proto": next_proto,
                }
            )

            for i in range(fully_consumed_words + 1, (len(p) + 39) // 40):
                self.inputq.append(
                    {
                        "data": data_word_from_index(p, i),
                        "quadoctets_consumed": 0,
                        "end_of_packet": end_of_packet_from_index(p, i),
                        "next_proto": 0,
                    }
                )

            remaining = p[fully_consumed_words * 40 + partial_consumed_length_qo * 4 :]
            for i in range((len(remaining) + 39) // 40):
                self.outputq.append(
                    {
                        "data": data_word_from_index(remaining, i),
                        "end_of_packet": end_of_packet_from_index(remaining, i),
                        "next_proto": next_proto,
                    }
                )

            print(len(p), fully_consumed_words, partial_consumed_length_qo)

    @def_method_mock(lambda self: self.dut.din, enable=lambda self: self.inputq and random() < 0.6)
    def din_process(self):
        print("i", self.inputq[0])
        return self.inputq.popleft()

    @def_method_mock(lambda self: self.dut.dout)
    def dout_process(self, arg):
        print("oo", arg)
        assert arg == self.outputq.popleft()

    def active_process(self):
        while self.outputq:
            yield

    def test_randomized(self):
        self.dut = SimpleTestCircuit(ParserAligner())
        with self.run_simulation(self.dut) as sim:
            sim.add_sync_process(self.active_process)
