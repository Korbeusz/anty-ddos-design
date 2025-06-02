from amaranth import Cat, Mux, Signal
from amaranth.lib.wiring import Component, In, Out
from transactron.core import TModule, Transaction


from mur.final_build.ParserCMSVol import ParserCMSVol
from mur.params import Params
from mur.utils import swap_endianess
from synth_examples.genverilog import gen_verilog

CYCLE_TIME = 0.000000001


class ParserCMSVolModule(Component):
    """Wrapper around :class:`ParserCMSVol` with a 520‑bit FIFO interface.

    Incoming words use the big‑endian queue format from ``alt_e100s20.v``.
    Internally, :class:`ParserCMSVol` expects little‑endian data, so this
    module swaps byte order on both input and output.

    The ports mirror those of :class:`PlaceholderModule` so the generated
    Verilog can drop into the same spot in ``alt_e100s20.v`` between the RX
    and TX async FIFOs.
    """

    def __init__(self):
        super().__init__(
            {
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

        m.submodules.core = core = ParserCMSVol(
            depth=4,
            width=2**14,
            counter_width=32,
            window=int(1 / CYCLE_TIME),
            volume_threshold=100_000,
            cms_fifo_depth=16,
        )
        word_bits = Params().word_bits  # 512

        get_read = Signal(init=1)
        # ------------------------------------------------------------------
        #  Input path: convert 520-bit FIFO word to ParserCMSVol layout
        # ------------------------------------------------------------------
        eop = self.in_data[518]
        empty = self.in_data[512:518]
        payload_be = self.in_data[0:512]
        payload_le = swap_endianess(m, payload_be)

        eop_len = Signal(range(0, (word_bits // 8) + 1))
        m.d.comb += eop_len.eq(Mux(eop, (word_bits // 8) - empty, 0))

        # Default handshake outputs
        m.d.sync += [self.wr_en_fifo.eq(0)]
        m.d.comb += self.rd_en_fifo.eq(get_read)
        with m.If(~self.in_empty & core.din.ready):
            m.d.sync += get_read.eq(1)
        with m.Else():
            m.d.sync += get_read.eq(0)
        with Transaction().body(m, request=self.in_valid):
            core.din(
                m,
                {
                    "data": payload_le,
                    "end_of_packet": eop,
                    "end_of_packet_len": eop_len,
                },
            )

        # ------------------------------------------------------------------
        #  Output path: convert ParserCMSVol word back to 520-bit format
        # ------------------------------------------------------------------
        in_packet = Signal(init=0)

        with Transaction().body(m, request=~self.out_full):
            word = core.dout(m)
            empty_out = word["end_of_packet"].as_unsigned() * (
                (word_bits // 8) - word["end_of_packet_len"]
            )
            data_be = swap_endianess(m, word["data"])
            sop_out = ~in_packet
            m.d.sync += [
                self.out_data.eq(
                    Cat(
                        data_be,
                        empty_out[:6],
                        word["end_of_packet"],
                        sop_out,
                    )
                ),
                self.wr_en_fifo.eq(1),
                in_packet.eq(~word["end_of_packet"]),
            ]

        return m


if __name__ == "__main__":
    gen_verilog(ParserCMSVolModule(), "parsercmsvol_module.v")
