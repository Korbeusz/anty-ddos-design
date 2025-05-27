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
        limbs = [[Signal(16, name=f"limb{i}_{j}") for i in range(self.input_width // 16)] for j in range(self.input_width // 16)]
        val = [Signal(1, name=f"val{i}") for i in range(3 + (self.input_width // 16))]
        nxt = [Signal(28, name=f"nxt{i}") for i in range(4)]
        for i in range(len(val)):
            if i == 0:
                m.d.sync += val[i].eq(0)
            else:
                m.d.sync += val[i].eq(val[i - 1])
        
        for i in range(self.input_width // 16):
            for j in range(self.input_width // 16):
                if i == 0:
                    m.d.sync += limbs[i][j].eq(0)
                else:
                    m.d.sync += limbs[i][j].eq(limbs[i - 1][j])
        @def_method(m, self.input)
        def _(data):
            for i in range(self.input_width // 16):
                rev = self.input_width // 16 - i - 1
                m.d.sync += limbs[0][rev].eq(data.word_select(i, 16))
            m.d.sync += val[0].eq(1)

        for idx in range(self.input_width // 16):
            if idx == 0:
                m.d.sync += nxt[idx].eq(limbs[0][0])
            else:
                m.d.sync += nxt[idx].eq((nxt[idx - 1] << 4) - nxt[idx - 1] + limbs[idx][idx])
        folded = Signal(18)
        last_index = self.input_width // 16 - 1
        m.d.sync += folded.eq(
            (nxt[last_index] & 0xFFFF)
            + (((nxt[last_index] >> 16) << 4) - (nxt[last_index] >> 16))
        )

        @def_method(m, self.result)
        def _():
            result = Signal(16)
            m.d.sync += result.eq(Mux(folded >= 65_521, folded - 65_521, folded))
            return {"mod": result, "valid": val[len(val) - 1]}

        return m
