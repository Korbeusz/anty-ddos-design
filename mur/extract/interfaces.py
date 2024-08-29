from mur.params import Params
from transactron.utils.transactron_helpers import make_layout


class ProtoParserLayouts:
    def __init__(self):
        self.data_aligned = ("data", Params().word_bits)
        """
        Data packet aligned to the start of field. Field is completely filled, unless end of packet is indicated.
        This is a maximum amout of data transmitted at 100Gbps link. It also equals maximum header frame size (IPv6).
        """

        self.end_of_packet = ("end_of_packet", range((Params().word_bits // 8) + 1))
        """
        Non-zero if there was an end of the packet at octet of signal value.
        """

        self.next_protocol = ("next_proto", Params().next_proto_bits)

        self.error = ("error", 1)

        self.parser_in_layout = self.align_out_layout = make_layout(
            self.data_aligned,
            self.end_of_packet,
            self.next_protocol,
            self.error,
        )

        self.quadoctets_consumed = ("quadoctets_consumed", range((Params().word_bits // (8 * 4)) + 1))
        """ how many 4's of octets were parsed. Every header is aligned to 4's of octets (32B) """

        self.parser_out_layout = make_layout(
            self.data_aligned,
            self.quadoctets_consumed,
            self.next_protocol,
            self.end_of_packet,
            self.error,
        )

        self.tx_layout = make_layout(self.data_aligned, self.end_of_packet)
