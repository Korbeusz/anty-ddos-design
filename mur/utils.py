from amaranth import *
from amaranth_types import ModuleLike


def swap_endianess(m: ModuleLike, s: Value):
    assert s.shape().width % 8 == 0

    r = Signal.like(s)

    for i in range(s.shape().width // 8):
        m.d.comb += r.word_select(i, 8).eq(s.word_select(s.shape().width // 8 - i - 1, 8))

    return r

def select_field_be(m: ModuleLike, target: Signal, source: Signal, offset: Value | int):
    return target.eq(swap_endianess(m, source.bit_select(offset, target.shape().width)))

