from amaranth.lib.wiring import Signature, In, Out

class IntelIPTxSignature(Signature):
    W = 5

    # https://www.intel.com/content/www/us/en/docs/programmable/683114/14-1/40-100gbe-ip-core-tx-data-bus-without.html
    # using custom streaming interface to optimize data width to process (5 instead of 8)
    def __init__(self):
        super().__init__(
            {
                "din": Out(self.W * 64),
                "din_start": Out(self.W),
                "din_end_pos": Out(self.W * 8),
                "din_ack": In(1),
                "clk_txmac": Out(1),
            }
        )


class IntelIPRxSignature(Signature):
    W = 5
    # https://www.intel.com/content/www/us/en/docs/programmable/683114/14-1/40-100gbe-ip-core-rx-data-bus-without.html 
    def __init__(self):
        super().__init__(
            {
                "dout_d": In(self.W * 64),
                "dout_c": In(self.W * 8),
                "dout_first_data": In(self.W),
                "dout_last_data": In(self.W * 8),
                "dout_runt_last_data": In(self.W),
                "dout_payload": In(self.W),
                "dout_fcs_error": In(1),
                "dout_fcs_valid": In(1),
                "dout_dst_addr_match": In(self.W),
                "dout_valid": In(1),
                "lanes_deskewed": In(1),
                "clk_rxmac": Out(1),
            }
        )

