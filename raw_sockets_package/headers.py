"""
offset, reserved, tcp_flags, window
checksum, urgent_ptr
tcp_options
payload
"""
from project_constants import *
from random import randint
import struct
import socket

# tcp header
class tcp_header_1:
    def __init__(self, source_ip, source_port, dest_ip, dest_port, curr_syn_flag, curr_ack_flag, ack_num, seq_num) -> None:
        self.source_ip = source_ip
        self.tcp_source_port = source_port
        self.dest_ip = dest_ip
        self.tcp_dest_port = dest_port

        #TCP Headers
        self.tcp_seq = seq_num
        self.tcp_ack_seq = ack_num
        self.tcp_doff = 5
        
        #tcp flags
        self.tcp_fin = 0
        self.tcp_syn = curr_syn_flag
        self.tcp_rst = 0
        self.tcp_psh = 0
        self.tcp_ack = curr_ack_flag
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
            #print('curr_msg', msg[i])
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

        psh = struct.pack(PSH_HEADER_FORMAT, source_address, dest_address, placeholder, protocol, tcp_length)
        psh = psh + self._tcp_header + struct.pack(user_data)

        return psh

class ip_header_1:
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

        return struct.pack(IP_HEADER_FORMAT, self.ip_ihl_ver, self.ip_tos, self.ip_tot_len, self.ip_id, self.ip_frag_off, \
            self.ip_ttl, self.ip_proto, self.ip_check, self.ip_saddr, self.ip_daddr)

class header_parser:
    def __init__(self, source_ip, source_port, dest_ip, dest_port, total_header_received, data_received):
        #self.ip_header = self.ip_unpack(data_received[:20])
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.source_port = source_port
        self.dest_port = dest_port
        self.ip_header = struct.unpack(IP_HEADER_FORMAT, total_header_received[:20])
        self.tcp_header = struct.unpack(TCP_HEADER_FORMAT, total_header_received[20:40])
        self.data = data_received

        self.data_length = self.get_data_length()

        print('\n\n\nip', self.ip_header, 'raw', total_header_received[:20])
        print('tcp', self.tcp_header, 'raw', total_header_received[20:40])
        #print('data received', self.data)
        print('data length', self.data_length)
        print('str version', self.get_data_str())

        self.tcp_hdr_dict = self.parse_tcp_header()
        self.ip_hdr_dict = self.parse_ip_header()

        print('ip hdr dict', self.ip_hdr_dict)
        print('tcp hdr dict', self.tcp_hdr_dict)

    def get_data_str(self):
        if self.data_length == 0:
            print('data is 0 length', len(self.data))
            return " "
        format = str(self.data_length) + 's'
        return struct.unpack(format, self.data) 

    def get_data_length(self):
        length = self.ip_header[1] - 40
        if length < 0: return 0
        return length

    def parse_ip_header(self):
        ip_hdr_dict = {}
 
        ip_hdr_dict['version'] = self.ip_header[0]
        ip_hdr_dict['ihl'] = ip_hdr_dict['version'] - (4 << 4)
        #ip_hdr_dict['service_type'] = read_service_int
        ip_hdr_dict['total_len'] = self.ip_header[1]
        ip_hdr_dict['packet_id'] = self.ip_header[2]
        ip_hdr_dict['flags'] = self.ip_header[3]
        #ip_hdr_dict['fragmentation_flag'] = self.ip_header[0]
        #ip_hdr_dict['location_flag'] = self.ip_header[0]
        ip_hdr_dict['frag_offset'] = self.ip_header[4]
        ip_hdr_dict['time_to_live'] = self.ip_header[5]
        ip_hdr_dict['protocol'] = self.ip_header[6]
        #get_check = self.ip_header[7]
        #check = self.tcp_checksum(self.ip_header)
        #print('get check', get_check, 'actual', check)
        ip_hdr_dict['checksum'] = self.ip_header[7]
        ip_hdr_dict['ip_src'] = socket.inet_ntoa(self.ip_header[8])
        ip_hdr_dict['ip_dest'] = socket.inet_ntoa(self.ip_header[9])
        return ip_hdr_dict

    def parse_tcp_header(self):
        dict_read_values = {}
        dict_read_values['port_src'] = self.tcp_header[0]
        dict_read_values['port_dest'] = self.tcp_header[1]
        dict_read_values['seq_num'] = self.tcp_header[2]
        dict_read_values['ack_num'] = self.tcp_header[3]
        dict_read_values['data_offset'] = self.tcp_header[4]
        dict_read_values['reserved_bits'] = dict_read_values['data_offset'] >> 4

        """dict_read_values['ns_flag'] = dict_read_flags['ns']
        dict_read_values['cwr_flag'] = dict_read_flags['cwr']
        dict_read_values['ece_flag'] = dict_read_flags['ece']
        dict_read_values['urg_flag'] = dict_read_flags['urg']
        dict_read_values['ack_flag'] = dict_read_flags['ack']
        dict_read_values['psh_flag'] = dict_read_flags['psh']
        dict_read_values['rst_flag'] = dict_read_flags['rst']
        dict_read_values['syn_flag'] = dict_read_flags['syn']
        dict_read_values['fin_flag'] = dict_read_flags['fin']"""

        dict_read_values['window_size'] = self.tcp_header[6]
        #dict_read_values['checksum'] = self.get_pseudoheader_csum()
        dict_read_values['urg_ptr'] = self.tcp_header[7]

        return dict_read_values
    
    def get_pseudoheader_csum(self):
        # pseudo header fields
        source_address = socket.inet_aton(self.source_ip)
        dest_address = socket.inet_aton(self.dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP

        tcp_length = len(self.data)

        psh = struct.pack(PSH_HEADER_FORMAT, source_address, dest_address, placeholder, protocol, tcp_length)
        psh = psh + self.data
        return self.tcp_checksum(psh)

    def tcp_checksum(self, msg):

        # checksum functions needed for calculation checksum
        csum = 0
        print('msg to calc csum', msg)
        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            #w = ord(msg[i]) + (ord(msg[i + 1]) << 8)
            #print('curr_msg', msg[i])
            w = msg[i]
            if i + 1 < len(msg):
                w+= msg[i+1] << 8
            csum = csum + w
        
        csum = (csum >> 16) + (csum & 0xffff)
        csum += (csum >> 16)
        
        #complement and mask to 4 byte short
        csum = ~csum & 0xffff
        
        return csum
   


