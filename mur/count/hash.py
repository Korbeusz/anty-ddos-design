from amaranth import *
from transactron import Method, def_method, TModule, Transaction
from mur.count.mod65521 import Mod65521



__all__ = ["Hash"]


class Hash(Elaboratable):
    def __init__(self, *, input_width: int = 64, a: int = 1, b: int = 0) -> None:
        if input_width not in (32, 48, 64):
            raise ValueError("input_width must be 32/48/64")

        self.input_width = input_width
        self._a = Signal(16, init=a)
        self._b = Signal(16, init=b)

        self.input = Method(i=[("data", input_width)])
        self.result = Method(o=[("hash", 16), ("valid", 1)])

    def elaborate(self, platform):
        m = TModule()
        mod_in = Mod65521(input_width=self.input_width)
        mod_out = Mod65521(input_width=32)
        m.submodules += [mod_in, mod_out]

        mul_valid = Signal(init=0)
        mul_result = Signal(32, init=0)

        @def_method(m, self.input)
        def _(data):
            mod_in.input(m, data=data)

        m.d.sync += mul_valid.eq(0)
        with Transaction().body(m):
            mod0_res = mod_in.result(m)
            with m.If(mod0_res["valid"]):
                m.d.sync += [
                    mul_result.eq(self._a * mod0_res["mod"] + self._b),
                    mul_valid.eq(1),
                ]

        with Transaction().body(m, request=mul_valid):
            mod_out.input(m, data=mul_result)

        @def_method(m, self.result)
        def _():
            res = mod_out.result(m)
            return {"hash": res["mod"], "valid": res["valid"]}

        return m
