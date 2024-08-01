from transactron.utils.transactron_helpers import make_layout


class ProtoParserLayouts:
    def __init__(self):
        self.data_aligned = ("data", 40 * 8)
        """
        Data packet aligned to the start of field. Field is completely filled, unless end of packet is indicated.
        This is a maximum amout of data transmitted at 100Gbps link. It also equals maximum header frame size (IPv6).
        """

        self.end_of_packet = ("end_of_packet", 6)  # transactron helpers ceil of 40 log2
        """
        Non-zero if there was an end of the packet at octet of signal value.
        """

        self.next_protocol = ("next_proto", 2)

        self.parser_in_layout = self.align_out_layout = make_layout(
            self.data_aligned, self.end_of_packet, self.next_protocol
        )

        self.quadoctets_consumed = ("quadoctets_consumed", 4)
        """ how many 4's of octets were parsed. Every header is aligned to 4's of octets (32B) """

        self.parser_out_layout = make_layout(
            self.data_aligned,
            self.quadoctets_consumed,
            self.next_protocol,
            self.end_of_packet,
        )
