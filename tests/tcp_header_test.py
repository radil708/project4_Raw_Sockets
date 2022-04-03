from headers_r.packet_parser_r import packet_parser
from headers_r.tcp_header_r import tcp_header
import unittest

class TestTCPHeader(unittest.TestCase):
    @classmethod
    def setUp(self):
        tcp_header = b'\x30\x39\x00\x50'  # Source Port | Destination Port
        tcp_header += b'\x00\x00\x00\x00'  # Sequence Number
        tcp_header += b'\x00\x00\x00\x00'  # Acknowledgement Number
        tcp_header += b'\x50\x02\x71\x10'  # Data Offset, Reserved, Flags | Window Size
        tcp_header += b'\xe6\x32\x00\x00'  # Checksum | Urgent Pointer

        self.raw_tcp_header = tcp_header
        self.parser = packet_parser()

    def test_tcp_reader(self):
        dict_read_values = self.parser.parse_tcp_packet(self.raw_tcp_header)
        self.assertEqual(12345, dict_read_values['port_src'])
        self.assertEqual(80, dict_read_values['port_dest'] )
        self.assertEqual(0, dict_read_values['seq_num'])
        self.assertEqual(0, dict_read_values['ack_num'] )
        self.assertEqual(5, dict_read_values['data_offset'])
        self.assertEqual(0,dict_read_values['reserved_bits'] )

        self.assertEqual(0,dict_read_values['ns_flag'] )
        self.assertEqual(0, dict_read_values['cwr_flag'])
        self.assertEqual(0,dict_read_values['ece_flag'])
        self.assertEqual(0,dict_read_values['urg_flag'] )
        self.assertEqual(0,dict_read_values['ack_flag'])
        self.assertEqual(0,dict_read_values['psh_flag'] )
        self.assertEqual(0, dict_read_values['rst_flag'])
        self.assertEqual(1,dict_read_values['syn_flag'])
        self.assertEqual(0,dict_read_values['fin_flag'] )

        self.assertEqual(28944,dict_read_values['window_size'])
        self.assertEqual(58930,dict_read_values['checksum'])
        self.assertEqual(0,dict_read_values['urg_ptr'])

    # how to generate TCP Header
    def text_tcp_gen(self):
        IPH = 6
        IP_SRC = "10.10.10.2"
        IP_DEST = "10.10.10.1"

        my_tcp = tcp_header(src_port_in=2712,dest_port_in=85,seq_num=156,
                            ack_num=23,data_offset_in=7,
                            ack_flag=1,sync_flag=1,window_size_in=2300,urg_ptr=42,
                            ece_flag=1,rst_flag=1,fin_flag=1)
        my_tcp.set_pseudo_header(IPH,IP_SRC,IP_DEST,22)
        my_tcp.calc_checksum()

        bytes_tcp = my_tcp.generate_tcp_packet()

        dict_read_values = self.parser.parse_tcp_packet(bytes_tcp)

        self.assertEqual(2712, dict_read_values['port_src'])
        self.assertEqual(85, dict_read_values['port_dest'])
        self.assertEqual(156, dict_read_values['seq_num'])
        self.assertEqual(23, dict_read_values['ack_num'])
        self.assertEqual(7, dict_read_values['data_offset'])
        self.assertEqual(0, dict_read_values['reserved_bits'])

        self.assertEqual(0, dict_read_values['ns_flag'])
        self.assertEqual(0, dict_read_values['cwr_flag'])
        self.assertEqual(1, dict_read_values['ece_flag'])
        self.assertEqual(0, dict_read_values['urg_flag'])
        self.assertEqual(1, dict_read_values['ack_flag'])
        self.assertEqual(0, dict_read_values['psh_flag'])
        self.assertEqual(1, dict_read_values['rst_flag'])
        self.assertEqual(1, dict_read_values['syn_flag'])
        self.assertEqual(1, dict_read_values['fin_flag'])

        self.assertEqual(2300, dict_read_values['window_size'])
        self.assertEqual(42, dict_read_values['urg_ptr'])




if __name__ == '__main__':
    unittest.main(verbosity=3)
