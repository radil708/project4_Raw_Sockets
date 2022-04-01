"""
offset, reserved, tcp_flags, window
checksum, urgent_ptr
tcp_options
payload
"""
from random import randint
import struct
import socket

# tcp header
class tcp_header:
    def __init__(self, source_ip, source_port, dest_ip, dest_port) -> None:
        self.source_ip = source_ip
        self.tcp_source_port = source_port
        self.dest_ip = dest_ip
        self.tcp_dest_port = dest_port

        #TCP Headers
        self.tcp_seq = randint(0, 5840)
        self.tcp_ack_seq = 0
        self.tcp_doff = 5
        
        #tcp flags
        self.tcp_fin = 0
        self.tcp_syn = 1
        self.tcp_rst = 0
        self.tcp_psh = 0
        self.tcp_ack = 0
        self.tcp_urg = 0
        self.tcp_window = socket.htons(5840)	#maximum allowed window size

        self.tcp_check = 0
        self.tcp_urg_ptr = 0

        self.tcp_offset_res = (self.tcp_doff << 4) + 0
        self.tcp_flags = self.tcp_fin + (self.tcp_syn << 1) + (self.tcp_rst << 2) + \
            (self.tcp_psh <<3) + (self.tcp_ack << 4) + (self.tcp_urg << 5)

        self._tcp_header = self.assemble_tcp_header()
        self.pseudoheader = self.get_pseudoheader()
        self.tcp_check = self.tcp_checksum(self.pseudoheader)
        print("checksum", self.tcp_check)

        # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
        self.final_tcp_header = self.assemble_tcp_header()
    
    def assemble_tcp_header(self):
        # the ! in the pack format string means network order
        return struct.pack('!HHLLBBHHH', self.tcp_source_port, self.tcp_dest_port, self.tcp_seq, self.tcp_ack_seq, \
            self.tcp_offset_res, self.tcp_flags, self.tcp_window, self.tcp_check, self.tcp_urg_ptr)

    def tcp_checksum(self, msg):
        # checksum functions needed for calculation checksum
        csum = 0
        print('msg to calc csum', msg)
        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            #w = ord(msg[i]) + (ord(msg[i + 1]) << 8)
            print('curr_msg', msg[i])
            w = msg[i]
            if i + 1 < len(msg):
                w+= msg[i+1] << 8
            csum = csum + w
        
        csum = (csum >> 16) + (csum & 0xffff)
        csum += (csum >> 16)
        
        #complement and mask to 4 byte short
        csum = ~csum & 0xffff
        
        return csum

    def get_pseudoheader(self):
        user_data = ''

        # pseudo header fields
        source_address = socket.inet_aton(self.source_ip)
        dest_address = socket.inet_aton(self.dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(self._tcp_header) + len(user_data)

        psh = struct.pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
        psh = psh + self._tcp_header + struct.pack(user_data)

        return psh

    def set_syn(self, curr_syn):
        self.tcp_syn = curr_syn

    def set_ack(self, curr_ack):
        self.tcp_ack = curr_ack

    def set_seq_num(self, curr_seq_num):
        self.tcp_seq = curr_seq_num

    def set_ack_num(self, curr_ack_num):
        self.tcp_ack_seq = curr_ack_num

class ip_header:
    def __init__(self, source_ip, dest_ip) -> None:
        self.source_ip = source_ip
        self.dest_ip = dest_ip

        # ip header fields
        self.ip_ihl = 5
        self.ip_ver = 4
        self.ip_tos = 0
        self.ip_tot_len = 0	# kernel will fill the correct total length
        self.ip_id = 54321	#Id of this packet
        self.ip_frag_off = 0
        self.ip_ttl = 255
        self.ip_proto = socket.IPPROTO_TCP
        self.ip_check = 0	# kernel will fill the correct checksum
        self.ip_saddr = socket.inet_aton(self.source_ip)	#Spoof the source ip address if you want to
        self.ip_daddr = socket.inet_aton(self.dest_ip)

        #self.ip_ihl_ver = (version << 4) + self.ihl
        self.ip_ihl_ver = (self.ip_ver << 4) + self.ip_ihl       
    
    def assemble_ip_header(self):
        # the ! in the pack format string means network order

        return struct.pack('!BBHHHBBH4s4s', self.ip_ihl_ver, self.ip_tos, self.ip_tot_len, self.ip_id, self.ip_frag_off, \
            self.ip_ttl, self.ip_proto, self.ip_check, self.ip_saddr, self.ip_daddr)