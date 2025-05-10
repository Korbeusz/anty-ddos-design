from __future__ import annotations

"""cms_vol_controller.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Top‑level supervision module that combines a **RollingCountMinSketch** (RCMS)
with a **VolCounter** to build a self‑contained, rolling traffic statistics
engine.

* Three ingress **BasicFifo** queues accept 32‑bit/32‑bit/16‑bit words that
  arrive asynchronously from the outer world (e.g. packet parser).
* Every cycle a transaction pops one element from each FIFO:
    * The two 32‑bit words are concatenated (**Cat**) into a single 64‑bit
      item that feeds the RCMS (*insert* or *query*, depending on the current
      *mode*).  The LS‑word comes first – ``Cat(low, high)`` – to follow the
      usual little‑endian layout adopted in *mur*.
    * The 16‑bit word is forwarded to the VolCounter (*add_sample*).
* Once per *window* the VolCounter raises a *result*; a dedicated transaction
  reads it, switches the RCMS between **UPDATE** / **QUERY** mode and rotates
  its triple‑buffered roles (*change_roles*).
* Whenever the RCMS produces a *valid* **query_resp**, the 32‑bit estimate is
  pushed into an egress FIFO that can be drained by external logic at leisure.

The design relies purely on **Transactron** hand‑shake semantics, i.e. all
transactions stall automatically until every invoked Method is *ready*.
"""

from amaranth import *
from transactron import *
from transactron.core import Transaction
from transactron.lib.fifo import BasicFifo

from mur.count.RollingCountMinSketch import RollingCountMinSketch
from mur.count.VolCounter import VolCounter

__all__ = ["CMSVolController"]


class CMSVolController(Elaboratable):
    """Combine **RollingCountMinSketch** & **VolCounter** with FIFO front‑/back‑ends."""

    # ---------------------------------------------------------------------
    #  Constructor
    # ---------------------------------------------------------------------
    def __init__(
        self,
        *,
        # RCMS parameters --------------------------------------------------
        depth: int = 4,
        width: int = 32,
        counter_width: int = 32,
        hash_params: list[tuple[int, int]] | None = None,
        # VolCounter -------------------------------------------------------
        window: int = 1024,
        threshold: int = 10_000,
        # FIFO depths ------------------------------------------------------
        fifo_depth: int = 16,
    ) -> None:

        # ── Ingress FIFOs (WRITE exposed) ---------------------------------
        lay32 = [("data", 32)]
        lay16 = [("data", 16)]

        self._fifo_a = BasicFifo(lay32, fifo_depth)
        self._fifo_b = BasicFifo(lay32, fifo_depth)
        self._fifo_s = BasicFifo(lay16, fifo_depth)

        # Public *write* handles so outer modules can inject data
        self.push_a = self._fifo_a.write   # 32‑bit word, low
        self.push_b = self._fifo_b.write   # 32‑bit word, high
        self.push_s = self._fifo_s.write   # 16‑bit volume sample

        # ── Egress FIFO for RCMS query results -----------------------------
        out_lay = [("data", counter_width)]
        self._fifo_out = BasicFifo(out_lay, fifo_depth)
        self.pop_count = self._fifo_out.read   # public *read* for estimates

        # ── Sub‑modules ----------------------------------------------------
        self.rcms = RollingCountMinSketch(
            depth            = depth,
            width            = width,
            counter_width    = counter_width,
            input_data_width = 64,              # Cat(32,32)
            hash_params      = hash_params,
        )
        self.vcnt = VolCounter(
            window       = window,
            threshold    = threshold,
            input_width  = 16,
        )

    # ---------------------------------------------------------------------
    #  Elaborate
    # ---------------------------------------------------------------------
    def elaborate(self, platform):
        m = TModule()

        # Register every sub‑block so the simulator/net‑list sees them
        m.submodules += [
            self._fifo_a, self._fifo_b, self._fifo_s, self._fifo_out,
            self.rcms, self.vcnt,
        ]

        # ------------------------------------------------------------
        # 1. Data path — pop A/B/S; insert OR query CMS; update VC
        # ------------------------------------------------------------
        with Transaction().body(m):
            a = self._fifo_a.read(m)            # low  word
            b = self._fifo_b.read(m)            # high word
            s = self._fifo_s.read(m)            # volume sample

            self.rcms.input(m, data=Cat(a["data"], b["data"]))
            self.vcnt.add_sample(m, data=s["data"])

        # ------------------------------------------------------------
        # 2. Once per *window* — pull VC result → switch RCMS roles/mode
        # ------------------------------------------------------------
        with Transaction().body(m):
            res = self.vcnt.result(m)           # ready only each *window*
            self.rcms.set_mode(m, mode=res["mode"])
            with m.If(res["mode"] == 0):
                self.rcms.change_roles(m)

        # ------------------------------------------------------------
        # 3. RCMS query responses → outbound FIFO (gated by *valid*)
        # ------------------------------------------------------------
        with Transaction().body(m):
            q = self.rcms.output(m)
            with m.If(q["valid"]):
                self._fifo_out.write(m, {"data": q["count"]})

        return m
