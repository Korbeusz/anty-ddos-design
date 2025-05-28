from amaranth import *
from amaranth.utils import ceil_log2
from transactron import Method, def_method, TModule

__all__ = ["VolCounter"]


class VolCounter(Elaboratable):
    """
    VolCounter is a simple volume counter that counts the number of samples
    in a sliding window and compares the sum of the samples to a threshold.
    It is used to detect if the traffic volume of samples exceeds a certain threshold
    which could indicate a potential attack or anomaly.

    Attributes
    ----------
        window (int): The size of the sliding window.
        threshold (int): The threshold for the volume counter.
        input_width (int): The width of the input data.

    Methods
    -------
        add_sample(data: int): Add a sample to the volume counter.
        result(): Get the result of the volume counter.
    """

    def __init__(
        self,
        *,
        window: int,
        threshold: int,
        input_width: int = 16,
    ) -> None:
        if window < 1:
            raise ValueError("window must be ≥ 1")
        if input_width < 1:
            raise ValueError("input_width must be ≥ 1")

        self.window = window
        self.threshold = threshold
        self.input_width = input_width

        worst_case_bits = input_width + ceil_log2(window)
        self.sum_width = worst_case_bits

        self.add_sample = Method(i=[("data", input_width)])
        self.result = Method(o=[("mode", 1)])

    def elaborate(self, platform):
        m = TModule()

        counter = Signal(range(self.window))
        acc = Signal(self.sum_width)

        with m.If(counter == self.window - 1):
            m.d.sync += counter.eq(0)
            m.d.sync += acc.eq(0)
        with m.Else():
            m.d.sync += counter.eq(counter + 1)

        @def_method(m, self.add_sample)
        def _add_sample(data):
            with m.If(~(counter == self.window - 1)):
                m.d.sync += acc.eq(acc + data)
            with m.Else():
                m.d.sync += acc.eq(data)

        mode = Signal(1)
        mode_set_ready = Signal()
        m.d.sync += mode_set_ready.eq((counter + 1) == (self.window - 1))

        @def_method(m, self.result, ready=mode_set_ready)
        def _result():
            m.d.comb += mode.eq(Mux(acc > self.threshold, 1, 0))
            return {"mode": mode}

        return m
