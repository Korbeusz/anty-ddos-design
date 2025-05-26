from amaranth import *
from transactron.core import TModule
from transactron.lib.fifo import BasicFifo
from transactron import Method

from mur.extract.interfaces import ProtoParserLayouts

__all__ = ["Passthrough"]


class Passthrough(Elaboratable):
    """Minimal module passing input words to output without modification."""

    def __init__(self, depth: int = 4) -> None:
        layout = ProtoParserLayouts().parser_in_layout
        self._fifo = BasicFifo(layout, depth)
        self.din = self._fifo.write
        self.dout = self._fifo.read

    def elaborate(self, platform):
        m = TModule()
        m.submodules.fifo = self._fifo
        return m