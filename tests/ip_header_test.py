import struct
import logging

from headers_r import ip_header
from headers_r import packet_parser
import unittest

class TestIPHeader(unittest.TestCase):
    @classmethod
    def setUp(self) -> None:
        self.ip_header = ip_header.ip_header(ip_source_in="10.10.10.2",
                                             ip_dest_in="10.10.10.1",packet_id_in=43981,
                                             frag_flag_input=0,location_flag=0,offset_in=0,ttl=64)
        self.packet_parser = packet_parser.packet_parser()


    def test_checksum(self):
        calc_checksum = self.ip_header.checksum_actual
        self.assertEqual(16, calc_checksum.bit_length())
        self.assertEqual(42732, calc_checksum)
        self.assertEqual('0xa6ec',hex(calc_checksum))

    def test_vis_helper(self):
        self.assertEqual("\\x45\\x00",self.ip_header.display_helper(1))

    def test_generate_ip_packet(self):
        test_ip_header_bytes = b'\x45\x00\x00\x28'  # Version, IHL, Type of Service | Total Length
        test_ip_header_bytes += b'\xab\xcd\x00\x00'  # Identification | Flags, Fragment Offset
        test_ip_header_bytes += b'\x40\x06\xa6\xec'  # TTL, Protocol | Header Checksum
        test_ip_header_bytes += b'\x0a\x0a\x0a\x02'  # Source Address
        test_ip_header_bytes += b'\x0a\x0a\x0a\x01'  # Destination Address
        self.assertEqual(test_ip_header_bytes, self.ip_header.generate_ip_packet())

    def test_parser_1(self):
        ip_ex1 = ip_header.ip_header(ip_source_in="10.10.10.2",
                                     ip_dest_in="10.10.10.1",
                                     packet_id_in=43981,frag_flag_input=0,location_flag=0,offset_in=0,ttl=64)
        gen_packet = ip_ex1.generate_ip_packet()
        read_values = self.packet_parser.parse_ip_packet(gen_packet)
        self.assertEqual(4, read_values['version'])
        self.assertEqual(5, read_values['ihl'])
        self.assertEqual(0, read_values['service_type'])
        self.assertEqual(40, read_values['total_len'])
        self.assertEqual(43981, read_values['packet_id'])
        self.assertEqual(0, read_values['service_type'])
        self.assertEqual(0, read_values['fragmentation_flag'])
        self.assertEqual(0, read_values['location_flag'])
        self.assertEqual(0, read_values['frag_offset'])
        self.assertEqual(64, read_values['time_to_live'])
        self.assertEqual(6, read_values['protocol'])
        self.assertEqual("10.10.10.2", read_values['ip_src'])
        self.assertEqual("10.10.10.1", read_values['ip_dest'])

    def test_ip_parser_2(self):
        ip_ex2 = ip_header.ip_header(ip_source_in="198.120.10.2", ihl_in=6,
                                     ip_dest_in="10.142.5.1",
                                     packet_id_in=13, frag_flag_input=1, location_flag=1, offset_in=52, ttl=32)
        gen_packet_2 = ip_ex2.generate_ip_packet()
        read_values = self.packet_parser.parse_ip_packet(gen_packet_2)
        self.assertEqual(6,read_values['ihl'])
        self.assertEqual("198.120.10.2",read_values['ip_src'])
        self.assertEqual("10.142.5.1",read_values['ip_dest'])
        self.assertEqual(13,read_values['packet_id'])
        self.assertEqual(1,read_values['fragmentation_flag'])
        self.assertEqual(1, read_values['location_flag'])
        self.assertEqual(52, read_values['frag_offset'])
        self.assertEqual(32, read_values['time_to_live'])



if __name__ == '__main__':
    unittest.main(verbosity=3)