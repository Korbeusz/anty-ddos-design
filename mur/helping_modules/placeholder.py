from amaranth import *
from synth_examples.genverilog import gen_verilog
from transactron.core import TModule
from amaranth.lib.wiring import Component, In, Out


class PlaceholderModule(Component):
    """
    Parameterised clone of the original Verilog placeholder_module.
    ▸ DATA_WIDTH is normally 520 bits:
        [519]     = SOP
        [518]     = EOP
        [517:512] = EMPTY[5:0]
        [511:0]   = DATA  (incremented by 1 on write)
    """

    # Define the component signature

    def __init__(self):
        super().__init__(
            {
                "clk": In(1),
                "rst_n": In(1),
                "in_data": In(520),
                "in_valid": In(1),
                "in_empty": In(1),
                "rd_en_fifo": Out(1),
                "out_data": Out(520),
                "wr_en_fifo": Out(1),
                "out_full": In(1),
            }
        )

    def elaborate(self, platform):
        m = TModule()

        # Handy aliases for the sub-fields we need
        sop = self.in_data[519]  # bit 519
        eop = self.in_data[518]  # bit 518
        empty_in = self.in_data[512:518]  # bits 512-517
        dat_in = self.in_data[0:512]  # bits 0-511

        # Incremented data field (wraps at 512 bits, matching the Verilog)
        dat_inc = Signal(512)
        m.d.comb += dat_inc.eq(dat_in + 1)

        # Default every cycle
        m.d.sync += [self.rd_en_fifo.eq(0), self.wr_en_fifo.eq(0)]

        # Write path: valid word → bump DATA by 1 and push to FIFO-2
        with m.If(self.in_valid & ~self.out_full):
            m.d.sync += [
                self.out_data.eq(Cat(dat_inc, empty_in, eop, sop)),
                self.wr_en_fifo.eq(1),
            ]
        # Read path: request another word when pipeline is clear
        with m.Elif(~self.in_valid & ~self.in_empty & ~self.out_full):
            m.d.sync += self.rd_en_fifo.eq(1)

        return m


# Optional helper to emit Verilog for quick sanity-checks
if __name__ == "__main__":
    gen_verilog(PlaceholderModule(), "placeholder.v")
