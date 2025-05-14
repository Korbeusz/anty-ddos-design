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
from transactron.core import *
from transactron.lib.fifo import BasicFifo
from transactron.lib.simultaneous import condition
from mur.count.RollingCountMinSketch import RollingCountMinSketch
from mur.count.VolCounter import VolCounter
from transactron.lib import logging
log = logging.HardwareLogger("test.cmsvolcontroller")
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
        discard_threshold: int = 0,
        # VolCounter -------------------------------------------------------
        window: int = 1024,
        volume_threshold: int = 10_000,
        # FIFO depths ------------------------------------------------------
        fifo_depth: int = 16,
    ) -> None:

        self.discover_threshold = discard_threshold
        # ── Ingress FIFOs (WRITE exposed) ---------------------------------
        lay32 = [("data", 32)]
        lay16 = [("data", 16)]

        self._fifo_sip = BasicFifo(lay32, fifo_depth)
        self._fifo_dip = BasicFifo(lay32, fifo_depth)
        self._fifo_dport = BasicFifo(lay16, fifo_depth)
        self._fifo_len = BasicFifo(lay16, fifo_depth)
        self._fifo_out = BasicFifo(lay32, fifo_depth)
        self.out = self._fifo_out.read
        # Public *write* handles so outer modules can inject data
        self.push_a = self._fifo_sip.write   # 32‑bit word, low
        self.push_b = self._fifo_dip.write   # 32‑bit word, high
        self.push_c = self._fifo_dport.write  # 16‑bit word, low
        self.push_s = self._fifo_len.write    # 16‑bit word, high

        self._insert_requested = Signal(32)
        self._query_requested = Signal(32)
        self._insert_received = Signal(32)
        self._query_received = Signal(32)

        # ── Sub‑modules ----------------------------------------------------
        self.rcms_sipdip = RollingCountMinSketch(
            depth            = depth,
            width            = width,
            counter_width    = counter_width,
            input_data_width = 32+32,              # Cat(32,32)
            hash_params      = hash_params,
        )
        self.rcms_dportdip = RollingCountMinSketch(
            depth            = depth,
            width            = width,
            counter_width    = counter_width,
            input_data_width = 16+32,              
            hash_params      = hash_params,
        )
        self.rcms_siplen = RollingCountMinSketch(
            depth            = depth,
            width            = width,
            counter_width    = counter_width,
            input_data_width = 32+16,              # Cat(32,16)
            hash_params      = hash_params,
        )
        self.vcnt = VolCounter(
            window       = window,
            threshold    = volume_threshold,
            input_width  = 16,
        )

    # ---------------------------------------------------------------------
    #  Elaborate
    # ---------------------------------------------------------------------
    def elaborate(self, platform):
        m = TModule()

        # Register every sub‑block so the simulator/net‑list sees them
        m.submodules += [
            self._fifo_sip,self._fifo_dip,self._fifo_dport,self._fifo_len,self._fifo_out,
            self.vcnt, self.rcms_sipdip, self.rcms_dportdip, self.rcms_siplen,
        ]

        # ------------------------------------------------------------
        # 1. Data path — pop A/B/S; insert OR query CMS; update VC
        # ------------------------------------------------------------
        self._current_mode = Signal(1)
        with Transaction().body(m):
            sip = self._fifo_sip.read(m)
            dip = self._fifo_dip.read(m)
            dport = self._fifo_dport.read(m)
            s = self._fifo_len.read(m)

            self._current_mode = self.rcms_sipdip.input(m, data=Cat(sip["data"], dip["data"]))["mode"]
            self.rcms_dportdip.input(m, data=Cat(dport["data"], dip["data"]))
            self.rcms_siplen.input(m, data=Cat(sip["data"], s["data"]))
            with m.If(self._current_mode == 0):
                m.d.sync += self._insert_requested.eq(self._insert_requested + 1)
            with m.Else():
                m.d.sync += self._query_requested.eq(self._query_requested + 1)
            self.vcnt.add_sample(m, data=s["data"])
            #log a, b, s values
            log.debug(m, True, "Input happens current_mode {:d} _insert_requested {:d}", self._current_mode, self._insert_requested)

        # ------------------------------------------------------------
        # 2. Once per *window* — pull VC result → switch RCMS roles/mode
        # ------------------------------------------------------------
        with Transaction().body(m):
            res = self.vcnt.result(m)           # ready only each *window*
            self.rcms_sipdip.set_mode(m, mode=res["mode"])
            self.rcms_dportdip.set_mode(m, mode=res["mode"])
            self.rcms_siplen.set_mode(m, mode=res["mode"])
            with m.If(res["mode"] == 0):
                self.rcms_sipdip.change_roles(m)
                self.rcms_dportdip.change_roles(m)
                self.rcms_siplen.change_roles(m)
            log.debug(m, True, "RCMS mode {:d} → {:d}", self._current_mode, res["mode"])
            

        # ------------------------------------------------------------
        # 3. RCMS query responses → outbound FIFO (gated by *valid*)
        # ------------------------------------------------------------
        self._inserts_difference = Signal(32)
        m.d.comb += self._inserts_difference.eq(self._insert_requested - self._insert_received)
        self._all_query_received = Signal(1)
        m.d.comb += self._all_query_received.eq(self._query_requested == self._query_received)
        self._query_decision = Signal(32)
        self._out = Signal(32)
        self._out_valid = Signal(1)
        m.d.sync += self._out_valid.eq(0)
        with Transaction().body(m):
            q1 = self.rcms_sipdip.output(m)
            q2 = self.rcms_dportdip.output(m)
            q3 = self.rcms_siplen.output(m)
            log.debug(m, True, " _inserts_difference {:d}, _all_query_received {:d}", self._inserts_difference, self._all_query_received)
            log.debug(m, True, "cms_sum:{:d}+{:d}+{:d}", q1["count"], q2["count"], q3["count"])
            with m.If(self._all_query_received & self._inserts_difference):
                m.d.sync += self._out.eq(self._inserts_difference)
                m.d.sync += self._insert_received.eq(self._insert_requested)
                m.d.sync += self._out_valid.eq(1)
            with m.If(~self._all_query_received & q1["valid"]):
                m.d.sync += self._out_valid.eq(1)
                m.d.sync += self._query_received.eq(self._query_received + 1)
                m.d.sync += self._out.eq(Mux(q1["count"] + q2["count"] + q3["count"] > self.discover_threshold,1,0))
        with Transaction().body(m,request=self._out_valid):    
            self._fifo_out.write(m, {"data": self._out})
            
            

        return m
