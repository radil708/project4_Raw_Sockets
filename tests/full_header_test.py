import unittest
from headers_r import ip_header_r,tcp_header_r,packet_parser_r

class FullHeaderTest(unittest.TestCase):

    @classmethod
    def setUp(self) -> None:
        ip_header  = b'\x45\x00\x00\x28'  # Version, IHL, Type of Service | Total Length
        ip_header += b'\xab\xcd\x00\x00'  # Identification | Flags, Fragment Offset
        ip_header += b'\x40\x06\xa6\xec'  # TTL, Protocol | Header Checksum
        ip_header += b'\x0a\x0a\x0a\x02'  # Source Address
        ip_header += b'\x0a\x0a\x0a\x01'  # Destination Address

        tcp_header  = b'\x30\x39\x00\x50' # Source Port | Destination Port
        tcp_header += b'\x00\x00\x00\x00' # Sequence Number
        tcp_header += b'\x00\x00\x00\x00' # Acknowledgement Number
        tcp_header += b'\x50\x02\x71\x10' # Data Offset, Reserved, Flags | Window Size
        tcp_header += b'\xe6\x32\x00\x00' # Checksum | Urgent Pointer

        packet = ip_header + tcp_header

        self.fullpacket = packet
        self.parser = packet_parser.packet_parser()

    def test_ip_read(self):
        test_ip_header = self.fullpacket[:20]
        parsed_packet_info = self.parser.parse_ip_packet(test_ip_header)

        self.assertEqual(4, parsed_packet_info['version'])
        self.assertEqual(5, parsed_packet_info['ihl'])
        self.assertEqual(0, parsed_packet_info['service_type'])
        self.assertEqual(40, parsed_packet_info['total_len'])
        self.assertEqual(43981, parsed_packet_info['packet_id'])
        self.assertEqual(0, parsed_packet_info['service_type'])
        self.assertEqual(0, parsed_packet_info['fragmentation_flag'])
        self.assertEqual(0, parsed_packet_info['location_flag'])
        self.assertEqual(0, parsed_packet_info['frag_offset'])
        self.assertEqual(64, parsed_packet_info['time_to_live'])
        self.assertEqual(6, parsed_packet_info['protocol'])
        self.assertEqual("10.10.10.2", parsed_packet_info['ip_src'])
        self.assertEqual("10.10.10.1", parsed_packet_info['ip_dest'])

    # testing ip header packet generation
    def test_match_ip_gen(self):
        test_ip_header = self.fullpacket[:20]
        parsed_packet_info = self.parser.parse_ip_packet(test_ip_header)

        new_ip_header_obj = ip_header.ip_header(ip_source_in=parsed_packet_info['ip_src'],
                                                ip_dest_in=parsed_packet_info['ip_dest'],
                                                packet_id_in=parsed_packet_info['packet_id'],
                                                frag_flag_input=parsed_packet_info['fragmentation_flag'],
                                                location_flag=parsed_packet_info['location_flag'],
                                                offset_in=parsed_packet_info['frag_offset'],
                                                ttl=parsed_packet_info['time_to_live'])
        ip_header_bytes = new_ip_header_obj.generate_ip_packet()
        self.assertEqual(test_ip_header, ip_header_bytes)

    def test_tcp_read(self):
        test_tcp_header = self.fullpacket[20:]
        parsed_tcp_info = self.parser.parse_tcp_packet(test_tcp_header)

        self.assertEqual(12345, parsed_tcp_info['port_src'])
        self.assertEqual(80, parsed_tcp_info['port_dest'])
        self.assertEqual(0, parsed_tcp_info['seq_num'])
        self.assertEqual(0, parsed_tcp_info['ack_num'])
        self.assertEqual(5, parsed_tcp_info['data_offset'])
        self.assertEqual(0, parsed_tcp_info['reserved_bits'])

        self.assertEqual(0, parsed_tcp_info['ns_flag'])
        self.assertEqual(0, parsed_tcp_info['cwr_flag'])
        self.assertEqual(0, parsed_tcp_info['ece_flag'])
        self.assertEqual(0, parsed_tcp_info['urg_flag'])
        self.assertEqual(0, parsed_tcp_info['ack_flag'])
        self.assertEqual(0, parsed_tcp_info['psh_flag'])
        self.assertEqual(0, parsed_tcp_info['rst_flag'])
        self.assertEqual(1, parsed_tcp_info['syn_flag'])
        self.assertEqual(0, parsed_tcp_info['fin_flag'])

        self.assertEqual(28944, parsed_tcp_info['window_size'])
        self.assertEqual(58930, parsed_tcp_info['checksum'])
        self.assertEqual(0, parsed_tcp_info['urg_ptr'])

    # example of generating tcp packet
    def test_matching_tcp_gen(self):
        test_ip_header = self.fullpacket[:20]
        parsed_ip_info = self.parser.parse_ip_packet(test_ip_header)

        #Constants for pseudo header
        PROTOCOL = 6 # can grab from ip or set constant
        SRC_IP = parsed_ip_info['ip_src']
        DEST_IP = parsed_ip_info['ip_dest']
        TCP_LEN = 20



        test_tcp_header = self.fullpacket[20:]
        parsed_tcp_info = self.parser.parse_tcp_packet(test_tcp_header)

        tcp_obj = tcp_header.tcp_header(src_port_in=parsed_tcp_info['port_src'],
                                        dest_port_in=parsed_tcp_info['port_dest'],
                                        seq_num=parsed_tcp_info['seq_num'],
                                        ack_num=parsed_tcp_info['ack_num'],
                                        data_offset_in=parsed_tcp_info['data_offset'],
                                        ack_flag=parsed_tcp_info['ack_flag'],
                                        sync_flag=parsed_tcp_info['syn_flag'],
                                        window_size_in=parsed_tcp_info['window_size'],
                                        urg_ptr=parsed_tcp_info['urg_ptr'],
                                        read_checksum=parsed_tcp_info['checksum'])

        tcp_obj.set_pseudo_header(iph_protocol=PROTOCOL,
                                  iph_src_ip_addr=SRC_IP,
                                  iph_dest_ip=DEST_IP,
                                  tcp_len=TCP_LEN)
        tcp_obj.calc_checksum()
        tcp_byte_generated = tcp_obj.generate_tcp_packet()

        self.assertEqual(test_tcp_header,tcp_byte_generated)

        # testing verification of checksum
        self.assertEqual(parsed_tcp_info['checksum'], tcp_obj.get_calculated_checksum())

if __name__ == '__main__':
    unittest.main(verbosity=3)