from struct import pack,unpack, calcsize
from headers_r import ip_header_r

def split_16_bits_into_two_8_bits(byte_in : bytes):
    return unpack('!BB',byte_in)

#TODO this would be an int so keep in mind
def split_8bit_int_into_two_4_bits_int(val_in : int):
    bin_string = bin(val_in)[2:]

    if len(bin_string) < 8:
        bin_string = ("0" * (8-len(bin_string))) + bin_string

    first_4_bit_int = int(bin_string[:4],2)
    second_4_bit_int = int(bin_string[4:],2)

    return first_4_bit_int,second_4_bit_int

def split_frag_flag_int(val_in : int):
    new_value = val_in
    if val_in.bit_length() < 16:
        new_value = (1<<16) + val_in

    bin_string = bin(new_value)[2:]


    flags_string = bin_string[1:4]
    frag_offset_string = bin_string[4:]

    fragmentation_flag = int(flags_string[1])
    location_flag = int(flags_string[2])
    frag_offset_int = int(frag_offset_string,2)

    return fragmentation_flag, location_flag,frag_offset_int

def split_32_bit_int_into_4_8_bits_ints(val_in : int):
    bin_string = bin(val_in)[2:]

    if len(bin_string) < 32:
        bin_string = ("0" * (32-len(bin_string))) + bin_string

    first_8_bit_int = int(bin_string[:8], 2)
    second_8_bit_int = int(bin_string[8:16], 2)
    third_8_bit_int = int(bin_string[16:24],2)
    fourth_8_bit_int = int(bin_string[24:],2)

    return first_8_bit_int,second_8_bit_int,third_8_bit_int,fourth_8_bit_int

def tcp_split_16_bit_int_for_data_offset_flags(val_in : int):
    bin_string = (bin(val_in)[2:])

    if len(bin_string) < 16:
        bin_string = ("0" * (16 - len(bin_string))) + bin_string

    data_offset_str = bin_string[:4]
    reserve_bits_str = bin_string[4:7]

    flag_key_list = ['ns','cwr','ece','urg','ack','psh','rst','syn','fin']

    dict_flags = {}
    for i in range(len(flag_key_list)):
        dict_flags[flag_key_list[i]] = bin_string[i + 7]

    # convert string values to int

    data_offset_int = int(data_offset_str,2)
    reserve_bits_int = int(reserve_bits_str,2)

    for key,val in dict_flags.items():
        temp_val = int(dict_flags[key])
        dict_flags[key] = temp_val

    return data_offset_int, reserve_bits_int, dict_flags





class packet_parser:
    def __init__(self, source_ip, source_port, dest_ip, dest_port, header_rcvd, data_rcvd) -> None:
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.source_port = source_port
        self.dest_port = dest_port

        self.ip_hdr_dict = self.parse_ip_packet(header_rcvd[:20])
        self.tcp_hdr_dict = self.parse_tcp_packet(header_rcvd[20:40])
        
        #self.data = self.parse_data(data_rcvd)
        print('ip hdr dict', self.ip_hdr_dict)
        print('tcp hdr dict', self.tcp_hdr_dict)
        print('raw data', data_rcvd)


    def parse_ip_packet(self,ip_packet : bytes):
        # grabs first 16 bit seg
        bytes_version_ihl_service = ip_packet[:2]
        int_version_ihl_service = split_16_bits_into_two_8_bits(bytes_version_ihl_service) # tuple of 2 8 bit segments
        read_version_int, read_ihl_int = split_8bit_int_into_two_4_bits_int(int_version_ihl_service[0]) # tuple of 2 4 bit segments as ints
        read_service_int = int_version_ihl_service[1]

        #grabs second 16 bit seg
        bytes_total_length = ip_packet[2:4]
        read_total_len_int = (unpack('!H',bytes_total_length))[0]

        #grabs 3rd 16 bit seg
        bytes_id = ip_packet[4:6]
        read_id_int = (unpack('!H',bytes_id))[0]

        #grabs 4th 16 bit seg
        bytes_flags_and_frag_offset = ip_packet[6:8]
        int_flags_and_frag_offset = (unpack('!H',bytes_flags_and_frag_offset))[0]
        read_frag_flag, read_location_flag, read_frag_offset = split_frag_flag_int(int_flags_and_frag_offset)

        #grab 5th 16 bit seg
        bytes_ttl_protocol_16 = ip_packet[8:10]
        read_time_to_live_int, read_protocol_int = split_16_bits_into_two_8_bits(bytes_ttl_protocol_16)

        #grab 6th 16 bit seg
        bytes_checksum = ip_packet[10:12]
        read_checksum_int = unpack('!H',bytes_checksum)[0]

        #grab 32 bit seg of source ip
        bytes_ip_src = ip_packet[12:16]
        ip_source_32_bit_int = unpack('!L',bytes_ip_src)[0]
        s1,s2,s3,s4 = split_32_bit_int_into_4_8_bits_ints(ip_source_32_bit_int)

        read_ip_src_str = str(s1) + "." + str(s2) + "." + str(s3) + "." + str(s4)
        print('\n\nsrc ip got', read_ip_src_str, 'actual', self.dest_ip)

        if not self.verify_source_ip(read_ip_src_str):
            print('not verified')
        else:
            print('verified')


        #grab 32 bit seg of dest ip
        bytes_ip_dest = ip_packet[16:20]
        ip_dest_32_bit_int = unpack('!L', bytes_ip_dest)[0]
        d1,d2,d3,d4 = split_32_bit_int_into_4_8_bits_ints(ip_dest_32_bit_int)

        read_ip_dest_str = str(d1) + "." + str(d2) + "." + str(d3) + "." + str(d4)
        print('dest ip got', read_ip_dest_str, 'actual', self.source_ip)

        if not self.verify_dest_ip(read_ip_dest_str):
            print('not verified')
        else:
            print('verified')
        dict_info = {}

        dict_info['version'] = read_version_int
        dict_info['ihl'] = read_ihl_int
        dict_info['service_type'] = read_service_int
        dict_info['total_len'] = read_total_len_int
        dict_info['packet_id'] = read_id_int
        dict_info['fragmentation_flag'] = read_frag_flag
        dict_info['location_flag'] = read_location_flag
        dict_info['frag_offset'] = read_frag_offset
        dict_info['time_to_live'] = read_time_to_live_int
        dict_info['protocol'] = read_protocol_int
        dict_info['checksum'] = read_checksum_int
        dict_info['ip_src'] = read_ip_src_str
        dict_info['ip_dest'] = read_ip_dest_str

        return dict_info
    
    def verify_source_ip(self, src_ip_rcvd):
        return src_ip_rcvd == self.dest_ip

    def verify_dest_ip(self, dst_ip_rcvd):
        return dst_ip_rcvd == self.source_ip

    def get_total_len(self):
        return 

    def parse_ip_packet_and_gen(self, ip_packet : bytes):
        read_values = self.parse_ip_packet(ip_packet)

        generated_ip_packet = ip_header_r.ip_header(ip_source_in=read_values['ip_src'],
                                        ip_dest_in=read_values['ip_dest'],
                                        packet_id_in=read_values['packet_id'],
                                        frag_flag_input=read_values['fragmentation_flag'],
                                        location_flag=read_values['location_flag'],
                                        offset_in=read_values['frag_offset'],
                                        ttl=read_values['time_to_live'],version_in=read_values['version'],
                                        ihl_in=read_values['ihl'],service_type_in=read_values['service_type'],
                                        total_len_in=read_values['total_len'],read_checksum_in=read_values['checksum'])
        return generated_ip_packet

    def parse_tcp_packet(self, ip_packet: bytes):
        # get first 16 bits (src port)
        bytes_src_port = ip_packet[:2]
        read_src_port = (unpack('!H', bytes_src_port))[0]

        #===============================================
        # get second 16 bits 9dest port
        bytes_dest_port = ip_packet[2:4]
        read_dest_port = (unpack('!H', bytes_dest_port))[0]

        #==============================================
        #get the third seg (one 32 bit seq number)
        bytes_seq_num = ip_packet[4:8]
        read_seq_num = (unpack('!L',bytes_seq_num))[0]

        #=============================================
        bytes_ack_num = ip_packet[8:12]
        read_ack_num = (unpack('!L', bytes_ack_num))[0]

        #=============================================
        # here gets a bit tricky
        # get a 16 bit seg rep offset and flags
        bytes_do_flags = ip_packet[12:14]
        int_16bit_do_flags = (unpack('!H',bytes_do_flags))[0]

        read_data_offset, read_rsv_flags, dict_read_flags = \
            tcp_split_16_bit_int_for_data_offset_flags(int_16bit_do_flags)

        #=================================================
        bytes_window_size = ip_packet[14:16]
        read_window_size = (unpack('!H', bytes_window_size))[0]

        #================================================
        bytes_checksum = ip_packet[16:18]
        read_checksum = (unpack('!H', bytes_checksum))[0]

        #================================================
        bytes_urg_ptr = ip_packet[18:20]
        read_urg_ptr = (unpack('!H', bytes_urg_ptr))[0]

        dict_read_values = {}

        dict_read_values['port_src'] = read_src_port
        dict_read_values['port_dest'] = read_dest_port
        dict_read_values['seq_num'] = read_seq_num
        dict_read_values['ack_num'] = read_ack_num
        dict_read_values['data_offset'] = read_data_offset
        dict_read_values['reserved_bits'] = read_rsv_flags

        dict_read_values['ns_flag'] = dict_read_flags['ns']
        dict_read_values['cwr_flag'] = dict_read_flags['cwr']
        dict_read_values['ece_flag'] = dict_read_flags['ece']
        dict_read_values['urg_flag'] = dict_read_flags['urg']
        dict_read_values['ack_flag'] = dict_read_flags['ack']
        dict_read_values['psh_flag'] = dict_read_flags['psh']
        dict_read_values['rst_flag'] = dict_read_flags['rst']
        dict_read_values['syn_flag'] = dict_read_flags['syn']
        dict_read_values['fin_flag'] = dict_read_flags['fin']

        dict_read_values['window_size'] = read_window_size
        dict_read_values['checksum'] = read_checksum
        dict_read_values['urg_ptr'] = read_urg_ptr

        return dict_read_values
    
    def parse_data(self, data):
        len_expected = self.ip_hdr_dict['total_len'] - 40
        if len_expected == 0: return ' '
        format = '!' + str(len_expected) + 's'
        data = pack(format, data)
        print('data size', calcsize(data), 'len exp', len_expected)
        return unpack(format, data)




















