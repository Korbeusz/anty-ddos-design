from amaranth import *
from transactron import Method, def_method, TModule
__all__ = ["Mod65521"]


class Mod65521(Elaboratable):
    def __init__(self, *, input_width: int = 64) -> None:
        if input_width not in (32, 48, 64):
            raise ValueError("input_width must be 32/48/64")
        self.input_width = input_width
        self.input = Method(i=[("data", input_width)])
        self.result = Method(o=[("mod", 16), ("valid", 1)])

    def elaborate(self, platform):
        m = TModule()
        limbs = [Signal(16, name=f"limb{i}") for i in range(self.input_width // 16)]
        val = [Signal(1, name=f"val{i}") for i in range(3)]
        nxt = [Signal(28, name=f"nxt{i}") for i in range(4)]
        for i in range(3):
            if i == 0:
                m.d.sync += val[i].eq(0)
            else:
                m.d.sync += val[i].eq(val[i - 1])

        @def_method(m, self.input)
        def _(data):
            for i in range(self.input_width // 16):
                rev = self.input_width // 16 - i - 1
                m.d.sync += limbs[rev].eq(data.word_select(i, 16))
            m.d.sync += val[0].eq(1)

        for idx, limb in enumerate(limbs):
            if idx == 0:
                m.d.comb += nxt[idx].eq(limb)
            elif idx == self.input_width // 16 - 1:
                m.d.sync += nxt[idx].eq((nxt[idx - 1] << 4) - nxt[idx - 1] + limb)
            else:
                m.d.comb += nxt[idx].eq((nxt[idx - 1] << 4) - nxt[idx - 1] + limb)
        folded = Signal(18)
        last_index = self.input_width // 16 - 1
        m.d.comb += folded.eq(
            (nxt[last_index] & 0xFFFF)
            + (((nxt[last_index] >> 16) << 4) - (nxt[last_index] >> 16))
        )

        @def_method(m, self.result)
        def _():
            result = Signal(16)
            m.d.sync += result.eq(Mux(folded >= 65_521, folded - 65_521, folded))
            return {"mod": result, "valid": val[2]}

        return m
