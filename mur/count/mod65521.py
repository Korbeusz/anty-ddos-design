from amaranth import *
from transactron import Method, def_method, TModule

__all__ = ["Mod65521"]


class Mod65521(Elaboratable):
    def __init__(self, *, input_width: int = 64) -> None:
        if input_width not in (16, 32, 48, 64):
            raise ValueError("input_width must be 16/32/48/64")
        self.input_width = input_width
        self.calc = Method(i=[("data", input_width)], o=[("mod", 16)])

    def elaborate(self, platform):
        m = TModule()

        @def_method(m, self.calc)
        def _(data):
            limbs = [data.word_select(i, 16) for i in range(self.input_width // 16)]
            acc = Signal(28)
            m.d.comb += acc.eq(0)
            tmp = acc
            for idx, limb in enumerate(reversed(limbs)):
                nxt = Signal(28, name=f"r{idx+1}")
                m.d.comb += nxt.eq(tmp * 15 + limb)
                tmp = nxt
            r_horner = tmp
            folded = Signal(18)
            m.d.comb += folded.eq((r_horner & 0xFFFF) + ((r_horner >> 16) * 15))
            result = Signal(16)
            m.d.comb += result.eq(Mux(folded >= 65_521, folded - 65_521, folded))
            return {"mod": result}

        return m
