from typing import Protocol
from amaranth import *
from amaranth.lib.wiring import Signature, In, Out
from amaranth_types import AbstractInterface, AbstractSignature


class IntelAvalonTxSignature(Signature):
    # https://www.intel.com/content/www/us/en/docs/programmable/683100/21-1-19-2-0/tx-mac-interface-to-user-logic.html
    def __init__(self):
        super().__init__(
            {
                "clk_txmac": In(1),
                "l8_tx_data": Out(512),
                "l8_tx_empty": Out(6),
                "l8_tx_startofpacket": Out(1),
                "l8_tx_endofpacket": Out(1),
                "l8_tx_ready": In(1),
                "l8_tx_error": Out(1),
                "l8_txstatus_valid": In(1),
                "l8_txstatus_data": In(40),
                "l8_txstatus_error": In(7),
            }
        )


class IntelAvalonRxInterface(AbstractInterface[AbstractSignature], Protocol):
    clk_txmac: Signal
    l8_tx_data: Signal
    l8_tx_empty: Signal
    l8_tx_startofpacket: Signal
    l8_tx_endofpacket: Signal
    l8_tx_ready: Signal
    l8_tx_error: Signal
    l8_txstatus_valid: Signal
    l8_txstatus_data: Signal
    l8_txstatus_error: Signal


class IntelAvalonRxSignature(Signature):
    # https://www.intel.com/content/www/us/en/docs/programmable/683100/21-1-19-2-0/rx-mac-interface-to-user-logic.html
    def __init__(self):
        super().__init__(
            {
                "clk_rxmac": In(1),
                "l8_rx_data": In(512),
                "l8_rx_empty": In(6),
                "l8_rx_startofpacket": In(1),
                "l8_rx_endofpacket": In(1),
                "l8_rx_error": In(6),
                "l8_rxstatus_valid": In(1),
                "l8_rxstatus_data": In(40),
            }
        )


class IntelAvalonTxInterface(AbstractInterface[AbstractSignature], Protocol):
    clk_rxmac: Signal
    l8_rx_data: Signal
    l8_rx_empty: Signal
    l8_rx_startofpacket: Signal
    l8_rx_endofpacket: Signal
    l8_rx_error: Signal
    l8_rxstatus_valid: Signal
    l8_rxstatus_data: Signal
