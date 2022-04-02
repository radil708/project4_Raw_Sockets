from struct import pack, bunpack
from headers import ip_header

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



class packet_parser():

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


        #grab 32 bit seg of dest ip
        bytes_ip_dest = ip_packet[16:20]
        ip_dest_32_bit_int = unpack('!L', bytes_ip_dest)[0]
        d1,d2,d3,d4 = split_32_bit_int_into_4_8_bits_ints(ip_dest_32_bit_int)

        read_ip_dest_str = str(d1) + "." + str(d2) + "." + str(d3) + "." + str(d4)

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

    def parse_ip_packet_and_gen(self, ip_packet : bytes):
        read_values = self.parse_ip_packet(ip_packet)

        generated_ip_packet = ip_header(ip_source_in=read_values['ip_src'],
                                        ip_dest_in=read_values['ip_dest'],
                                        packet_id_in=read_values['packet_id'],
                                        frag_flag_input=read_values['fragmentation_flag'],
                                        location_flag=read_values['location_flag'],
                                        offset_in=read_values['frag_offset'],
                                        ttl=read_values['time_to_live'],version_in=read_values['version'],
                                        ihl_in=read_values['ihl'],service_type_in=read_values['service_type'],
                                        total_len_in=read_values['total_len'],read_checksum_in=read_values['checksum'])
        return generated_ip_packet


















