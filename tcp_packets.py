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

        #TCP Headers
        self.seq_num = 0
        self.ack_seq = 0
        self.doff = 5
        self.fin = 0
        self.syn = 1
        self.rst = 0
        self.psh = 0
        self.ack = 0
        self.urg = 0
        self.window = 16384 # TEXTBOOK VALUE - TA
        self.check = 0 # filled by pseudo header
        self.urg_ptr = 0

    def tcp_checksum(self):
        pass
    
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

    def pack_packet(self):
        struct.pack(self.source_port, self.dest_port, self.seq_num, self.ack_num)