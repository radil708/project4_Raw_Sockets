import socket
from struct import pack,unpack
from bit_vis_helper import all_escapes

all_escapes

MAX_4_BIT_INT = 15
MAX_8_BIT_INT = 255
MAX_13_BIT_INT = 8191
MAX_16_BIT_INT = 65535

def binary_addition_checksum(x : int, y : int,
                             bit_length : int = 16, dif_bit_lengths : bool = False,
                             overflow : bool = False, ) -> int:

    if dif_bit_lengths == True:
        x = format(x,'0b')
        y = format(y,'0b')
    else:
        bit_limit = '0' + str(bit_length) + 'b'
        x = format(x, bit_limit)
        y = format(y, bit_limit)

    result = ""
    carry_val = 0

    rev_x, rev_y = x[::-1], y[::-1]


    for i in range(max(len(rev_x),len(rev_y))):
        if i < len(rev_x):
            ord_val_x = ord(rev_x[i]) - ord("0")
        else:
            ord_val_x = 0
        if  i < len(rev_y):
            ord_val_y = ord(rev_y[i]) - ord("0")
        else:
            ord_val_y = 0

        total_ord_val = ord_val_x + ord_val_y + carry_val
        char_val = str(total_ord_val % 2)
        result = char_val + result
        carry_val = total_ord_val // 2

    if overflow == True:
        result = "1" + result

    int_result = int(result,2)

    return int_result

class ip_header:
    def __init__(self, ip_source_in : str, ip_dest_in : str, packet_id_in=0, 
                frag_flag_input=0, location_flag=0, offset_in=0, ttl=225, version_in=4, ihl_in=5,
                 service_type_in=0, total_len_in=20, read_checksum_in = 0):

        self.ip_source = ip_source_in
        self.ip_dest = ip_dest_in

        # ALL VALUES AFTER STRING PASSED IN ARE INTS

        # A 4-bit field that identifies the IP version being used. The current version is 4
        self.version = version_in

        # A 4-bit field containing the length of the IP header in 32-bit increments
        # min size is 20 bytes (5 * 8 bits)
        # max size is 24 bytes (6 * 8 bits)
        # ihl value can only be 5 or 6
        self.ihl = ihl_in

        if (self.ihl != 5 and self.ihl != 6):
            raise ValueError("ERROR: ip header length (ihl) must be 5 or 6\n"
                             "FAILED TO CONSTRUCT IP HEADER\nEXITING PROGRAM")

        #8-bit field uses 3 bits for IP Precedence, 4 bits for service with the last bit not being used.
        # The 4-bit service field, although defined, has never been used.
        # bits change how packet is treated
        self.service_type = service_type_in

        if self.service_type > MAX_8_BIT_INT:
            raise ValueError(f'Service type in ip header cannot exceed {MAX_8_BIT_INT}(max value for 8 bits)')
        elif self.service_type < 0:
            raise ValueError("service type in ip header cannot be lower than 0")

        #16 bit field indicates entire size of IP Packet (header and data) in bytes
        # min value total_len = 20 (if no data present)
        # max value total+len = 65,535 (largest 16 bit value that can be represented)
        self.total_len = total_len_in

        if (self.total_len < 20 or self.total_len > MAX_16_BIT_INT):
            raise ValueError("ERROR: ip header total length cannot be less than 20 or greater than 65535\n"
                             "FAILED TO CONSTRUCT IP HEADER\nEXITING PROGRAM ")


        # If the IP packet is fragmented then each fragmented packet will use
        # the same 16 bit identification number to identify to which IP packet they belong to.
        self.packet_id = packet_id_in


        #reserve flag always = 0
        self.rsv_flag = 0

        if self.rsv_flag != 0:
            raise ValueError("ERROR: ip header reserve flag must be 0\n"
                             "FAILED TO CONSTRUCT IP HEADER\nEXITING PROGRAM")

        #frag flag 0: packet is allowed to be fragmented
        #frag flag 1: packet not allowed to be fragmented
        self.frag_flag = frag_flag_input

        if (self.frag_flag != 0 and self.frag_flag != 1):
            raise ValueError("ERROR fragmentation flag must be 0 or 1\n"
                             "FAILED TO CONSTRUCT IP HEADER\nEXITING PROGRAM")


        #location flag 0: packet is the last fragment in a series or not frag
        #location flag 1: flag is not the last fragment in the series
        self.location_flag = location_flag

        if (self.location_flag != 0 and self.location_flag != 1):
            raise ValueError("ERROR fragmentation flag must be 0 or 1\n"
                             "FAILED TO CONSTRUCT IP HEADER\nEXITING PROGRAM")

        # this 13 bit field specifies the position of the fragment
        # in the original fragmented IP packet.
        self.frag_offset = offset_in

        if (self.frag_offset > MAX_13_BIT_INT):
            raise ValueError(f"ERROR: Fragmentation offset greater than 13 bit limit "
                             f"(i.e. > {MAX_13_BIT_INT}\nFAILED TO CONSTRUCT IP HEADER\nEXITING PROGRAM")

        #Everytime an IP packet passes through a router,
        # the time to live field is decremented by 1.
        # Once it hits 0 the router will drop the packet and
        # sends an ICMP time exceeded message to the sender.
        # The time to live field has 8 bits and is used to prevent packets from looping around forever
        # (if you have a routing loop).
        self.time_to_live = ttl

        if self.time_to_live > MAX_8_BIT_INT:
            raise ValueError(f"time to live in ip header cannot exceed {MAX_8_BIT_INT} (max value for 8 bit) ")
        elif self.time_to_live < 0:
            raise ValueError("time to live in ip header cannot be lower than 0")

        #this 8 bit field tells us which protocol is enapsulated in the IP packet,
        # for example TCP has value 6 and UDP has value 17.
        # since tcp we will keep constant
        self.protocol = socket.IPPROTO_TCP

        # if receiving a packet and parsing, must modify.
        # also must modifiy right before sending
        self.pseudo_checksum = 0

        # here is checksum from a read packet, 0 if generating a new packet
        self.read_checksum = read_checksum_in

        self.set_16_bit_dict()

        # calculates checksum here
        self.checksum_actual = self.calc_checksum()
        self.dict_16_bits[6] = pack('!H', self.checksum_actual)

    def reset_pseudo_checksum(self):
        self.pseudo_checksum = 0

    def set_checksum_actual(self, checksum_in : int):
        self.checksum_actual = checksum_in
        self.dict_16_bits[6] = pack('!H', self.checksum_actual)


    def set_16_bit_dict(self):
        self.dict_16_bits = {}

        version_ihl_bits = (self.version << 4) + self.ihl # only 8 bits here
        mask = 2 ** 16 - 1
        version_ihl_service_bits = (version_ihl_bits << 8) & mask

        self.dict_16_bits[1] = pack('!H',version_ihl_service_bits)

        #================================================================

        #TODO TOTAL len current has default, change
        self.dict_16_bits[2] = pack('!H',self.total_len)

        #=================================================================

        self.dict_16_bits[3] = pack('!H', self.packet_id)

        #================================================================

        full_flags = (self.rsv_flag << 2) + (self.frag_flag << 1) + self.location_flag
        flag_frag_bits = (full_flags << 13) + self.frag_offset

        self.dict_16_bits[4] = pack('!H',flag_frag_bits)

        #===================================================================

        ttl_proto_bits = (self.time_to_live << 8) + self.protocol
        self.dict_16_bits[5] = pack('!H',ttl_proto_bits)

        #====================================================================
        #TODO need to fix this checksum - FIXED? now auto calculates checksum
        self.dict_16_bits[6] = pack('!H', self.pseudo_checksum)

        #====================================================================
        src_32_bits = pack('!4s',socket.inet_aton(self.ip_source))
        src_unpacked_32_bits_split_two_16 = unpack('!HH',src_32_bits)
        src_16_bit_p1 = src_unpacked_32_bits_split_two_16[0]
        src_16_bit_p2 = src_unpacked_32_bits_split_two_16[1]

        self.dict_16_bits[7] = pack('!H',src_16_bit_p1)
        self.dict_16_bits[8] = pack('!H',src_16_bit_p2)

        #=====================================================================

        dest_32_bits = pack('!4s', socket.inet_aton(self.ip_dest))
        dest_unpacked_32_bits_split_two_16 = unpack('!HH',dest_32_bits)
        dest_16_bit_p1 = dest_unpacked_32_bits_split_two_16[0]
        dest_16_bit_p2 = dest_unpacked_32_bits_split_two_16[1]

        self.dict_16_bits[9] = pack('!H',dest_16_bit_p1)
        self.dict_16_bits[10] = pack('!H',dest_16_bit_p2)

    def calc_checksum(self) -> int:
        starter = 0

        for i in range(1,11):
            temp = unpack('!H', self.dict_16_bits[i])
            current = binary_addition_checksum(temp[0],starter)
            starter = current

        mask = 2 ** 16 - 1
        checksum = current & mask
        checksum += 0x0001
        checksum = 0xffff - checksum
        return checksum

    def display_helper(self,int):
        return (self.dict_16_bits[int]).decode('all-escapes')

    def generate_ip_packet(self):
        ret = self.dict_16_bits[1]

        for i in range(2,11):
            ret += self.dict_16_bits[i]

        return ret




