from mur.params import Params
from transactron.utils.transactron_helpers import make_layout, extend_layout


class ProtoParserLayouts:
    def __init__(self):
        self.data_aligned = ("data", Params().word_bits)
        """
        Data packet aligned to the start of field. Field is completely filled, unless end of packet is indicated.
        (NOTE: Current width of 512 exceeds transmision speed and current maximum parsed header size (IPv6+TCP).
        IPs in other FPGAs provide custom 40*8*8 bus, header assumption still holds). Little-endian
        """

        self.end_of_packet = ("end_of_packet", 1)
        """
        Indicates last word of data for packet. (Packet may be empty).
        """

        self.end_of_packet_len = ("end_of_packet_len", range((Params().word_bits // 8) + 1))
        """
        Number of data octets is end_of_frame packet.
        May be 0 for no data. Ignored when end_of_packet not set
        """

        self.parser_in_layout = make_layout(
            self.data_aligned,
            self.end_of_packet,
            self.end_of_packet_len,
        )

        self.next_protocol = ("next_proto", Params().next_proto_bits)
        """
        Internal representation of next protocol parser to forward packet. Sampled at `extract_range_end`. 
        Value of 0 is reserved to unknown protocol. It should represent enum located at `<parser_class>.ProtoOut`.
        """

        self.align_out_layout = extend_layout(self.parser_in_layout, self.next_protocol)

        self.data_out = ("data", Params().word_bits)
        """
        Data output from parser. Prefix of it may be consumed by parser. See `parsing_ended`
        """

        self.extract_range_end = ("extract_range_end", 1)
        """ 
        Flag indicating that parser reached end of data of interest and all next words until the end of the packet should be forwarded.
        This means that parser is not allowed to consume any more data to end_of_packet and `quadoctets_consumed` is ignored, because
        it is redundant. Some of parser outputs are sampled at this flag. Must be held for only for one cycle.
        """

        self.quadoctets_consumed = ("quadoctets_consumed", range((Params().word_bits // (8 * 4)) + 1))
        """ How many 4's of octets were parsed and consumed. Every header is aligned to 4's of octets (32B) """

        self.error_drop = ("error_drop", 1)
        """
        Indicates fatal error when parsing, that should cause packet to be dropped. `qo_consumed` is ignored. 
        Errors are sampled only at `extract_range_end`. Normal output should be continued until `end_of_packet`, but will be ignored.
        """

        # NOTE: There is currently no need for it, but there are possibly two other non-fatal error classes
        # One that causes `qo_consumed` to be invalid, and parsing shouldn't be forwarded to next parser, and other that parsing may continue, but
        # data from this parses may be incorrect. Introduce if there is need for it.
        # Both may be singalled via result flow and first one report error_drop to stop parsing

        self.parser_out_layout = self.align_in_layout = make_layout(
            self.data_out,
            self.quadoctets_consumed,
            self.extract_range_end,
            self.next_protocol,
            self.end_of_packet,
            self.end_of_packet_len,
            self.error_drop,
        )

        self.tx_layout = make_layout(self.data_aligned, self.end_of_packet)
