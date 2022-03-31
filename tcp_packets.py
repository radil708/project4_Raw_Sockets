"""
offset, reserved, tcp_flags, window
checksum, urgent_ptr
tcp_options
payload
"""
import struct

class tcp_packet:
    def __init__(self, source_ip, source_port, dest_ip, dest_port) -> None:
        self.source_ip = source_ip
        self.source_port = source_port
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        
        self.packet_length = 0
        self.syn = 0
        self.ack = 0
        self.seq_num = 0
        self.checksum = 0

    def set_headers(self):
        # seq_num, ack_num, offset, 
        # offset, reserved, tcp_flags, window
        # checksum, urgent_ptr
        pass

    def set_flags(self):
        # syn, fin, rst, psh, ack, urg
        pass
    
    def set_seq_num(self, curr_seq_num):
        self.seq_num = curr_seq_num

    def set_ack_num(self, curr_ack_num):
        self.ack_num = curr_ack_num

    def checksum(self):
        # header + tcp_header + data
        pass

