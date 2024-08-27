from amaranth import *


def swap_endianess(m: Module, s: Signal):
    assert s.width % 8 == 0

    r = Signal.like(s)

    for i in range(s.width // 8):
        m.d.comb += r.word_select(i, 8).eq(s.word_select(s.width // 8 - i - 1, 8))

    return r
