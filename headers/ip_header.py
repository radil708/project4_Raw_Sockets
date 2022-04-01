'''
version = 4 bits
ihl = 4 bits
type of service = 4 bits
total_len; ;em = 16 bits
id = 16 bits
flags = 3 bits
offset= 13 bits
ttl = 8 bits
prto = 8 bits
checksum = 16 bits
'''
import socket
import struct
MAX_4_BIT_INT = 15
MAX_8_BIT_INT = 255
MAX_13_BIT_INT = 8191
MAX_16_BIT_INT = 65535

def convert_int_to_16bitint(val_in):
    if val_in <= 4:
        return (0 << )

def convert_int_to_16_bit(val_in):
    if val_in > MAX_16_BIT_INT:
        raise ValueError(f"Cannot convert any values over {MAX_16_BIT_INT} to 16 bit representation")

def convert_int_to8_bit(val_in):
    if val_in > 255:
        raise ValueError()
    else:
        return format(val_in,'08b')







class ip_header():
    def __init__(self, version_in=4, ihl_in=5,
                 service_type_in=0,total_len_in=40,
                 id_in,frag_flag_in,location_flag,offset_in,ttl):
        self.version = version_in
        self.ihl = ihl_in
        self.service_type = service_type_in
        # length of ip header is always 160 bits or 20 bytes (5 segments each 32 bits)
        self.total_len = total_len_in
        self.id = id_in
        #reserve flag always = 0
        self.rsv_flag = 0
        # frag flag 0: pacjet is allowed to be fragmented
        #frag flag 1: packet not allowed to be fragmented
        self.frag_flag = frag_flag_in


        #locatio flag 0: packet is the last fragment in a series or not frag
        #location flag 1: flag is not the last fragment in the series
        self.location_flag = location_flag

        self.frag_offset = offset_in

        self.time_to_live = ttl
        self.protocol = socket.IPPROTO_TCP
        self.checksum = 0

        if total_len_in > MAX_16_BIT_INT:
            raise ValueError(f"total_len cannot exceed {MAX_16_BIT_INT}")
        elif total_len_in < 0:
            raise ValueError(f"total_len cannot be smaller than 0")

        #check for errors
        if self.frag_offset > MAX_13_BIT_INT:
            raise ValueError("frag offset in ip header cannot exceed 8191 (max value for 13 bits)")
        elif self.frag_offset < 0:
            raise ValueError("frag offset in ip header cannot be smaller than 0")

        if self.time_to_live > MAX_8_BIT_INT:
            raise ValueError(f'Service type in ip header cannot exceed {MAX_8_BIT_INT}(max value for 8 bits)')
        elif self.service_type < 0:
            raise ValueError("service type in ip header cannot be lower than 0")

        if self.time_to_live > MAX_8_BIT_INT:
            raise ValueError(f"time to live in ip header cannot exceed {MAX_8_BIT_INT} (max value for 8 bit) ")
        elif self.time_to_live < 0:
            raise ValueError("time to live in ip header cannot be lower than 0")

    def create_ip_packet_bytes(self):

        #IP header len = ipv4geafer +

        # why? byte = 8 bits, # ints are converted to most efficient bit rep ie. 4 bits, 8 bits etc
            #depending on int value. 4 as binary in python is 4 bits
        # packing usually requires a byte/ 8 bits at minimum
        # we cannot directly create a 8 bit/1 byte value number representing two 4 bit ints
        # always be a byte. So to represent two numbers in 1 byte we need
        # to bitshift and add
        # 4 as a byte is 0000 0100, we bit shift left 4 spaces to get 0100 0000
        # 5 in bits is 0000 0101
        # so 0100 0000 + 0000 0101 = 0100 0101 -> now this is '4' and '5' as byte
        version_ihl_bytes_out = ((self.version << 4) + self.ihl_in) # 8 bits
        seg_1 = (version_ihl_bytes_out << 8) + self.service_type
        seg_1 = (seg_1 << 16) + self.total_len




        # fill up the 3 bits as a 4 bit value
        full_flags = (self.rsv_flag) + (self.frag_flag << 2) + (self.location_flag << 1)\
        #convert to a 3 bit value
        full_flags = (full_flags >> 1)
        # 8 bytes
        flag_offset_bytes_out = (full_flags << 13) + self.frag_offset # 16 bits

        seg_2 = (self.id << 32) + flag_offset_bytes_out









class tcp_header():
    def __init__(self,src_prt_in,dest_port_in,seq_num_in,ack_num_in,offset_in, ):
