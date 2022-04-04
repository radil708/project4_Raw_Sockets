import xml.dom
from struct import pack,unpack
from headers_r.ip_header_r import MAX_4_BIT_INT,MAX_8_BIT_INT,MAX_16_BIT_INT,MAX_13_BIT_INT, binary_addition_checksum
import socket

MAX_32_BIT_INT = 4294967295

ERROR_STR_APPEND = "FAILED TO CONSTRUCT TCP HEADER\nEXITING PROGRAM"

def is_valid_control_flag_val(ctrl_flg_val):
    if (ctrl_flg_val != 0 and ctrl_flg_val != 1):
        return False
    else:
        return True

def get_val_data_offset_reserve(val_in_do : int, val_reserve_bits : int = 0):
    if val_in_do.bit_length() < 6:
        new = (val_in_do << (6 - val_in_do.bit_length()))


    return new

class tcp_header:
    def __init__(self, src_port_in: int, dest_port_in: int, seq_num: int, ack_num: int, 
                 ack_flag: int, sync_flag: int, data_offset_in: int = 0, window_size_in: int = 65535, urg_ptr: int = 0,
                 read_checksum: int = 0, ns_flag: int = 0, cwr_flag: int = 0 ,
                 ece_flag: int = 0,urge_flag: int = 0, psh_flag: int = 0,
                 rst_flag: int = 0, fin_flag: int = 0, tcp_data = ''):

        self.calc_checksum_flag = False
        self.tcp_data = tcp_data

        #set up values for pseudo header
        self.protocol = None
        self.ip_src = None
        self.ip_dest = None
        self.tcp_len = None



        if src_port_in > MAX_16_BIT_INT:
            raise ValueError(f'ERROR: src_port cannot be greater than f{MAX_16_BIT_INT}\n' + ERROR_STR_APPEND)

        #The sending device’s port.
        self.port_src = src_port_in


        if dest_port_in > MAX_16_BIT_INT:
            raise ValueError(f'ERROR: dest_port cannot be greater than f{MAX_16_BIT_INT}\n' + ERROR_STR_APPEND )

        #The receiving device’s port.
        self.port_dest = dest_port_in

        if seq_num > MAX_32_BIT_INT:
            raise ValueError(f'ERROR: seq num cannot be greater than f{MAX_32_BIT_INT}\n' + ERROR_STR_APPEND)

        # A device initiating a TCP connection must choose a random initial sequence number,
        # which is then incremented according to the number of transmitted bytes.
        self.num_seq = seq_num

        if ack_num > MAX_32_BIT_INT:
            raise ValueError(f'ERROR: ack num cannot be greater than {MAX_32_BIT_INT}\n' + ERROR_STR_APPEND)

        #The receiving device maintains an acknowledgment number starting with zero.
        # It increments this number according to the number of bytes received.
        self.num_ack = ack_num

        if data_offset_in > MAX_4_BIT_INT:
            raise ValueError(f'ERROR: data offset cannot be greater than f{MAX_4_BIT_INT}\n' + ERROR_STR_APPEND)

        self.data_offset = data_offset_in

        # reserved 3 bits
        self.rsv_3_bits = 0

        # 9 control bits/flags

        #experimental flag, leave alone
        self.ns_flag = ns_flag

        if not is_valid_control_flag_val(ns_flag):
            raise ValueError('ns flag is not valid\n' + ERROR_STR_APPEND)

        # set when the sending node receives a TCP segment that has the ECE bit turned on.
        # It is used to indicate to a peer that the congestion window was reduced to
        # facilitate recovery of an intermediate device
        # leave alone for now?
        self.cwr_flag = cwr_flag

        if not is_valid_control_flag_val(cwr_flag):
            raise ValueError('cwr flag is not valid\n' + ERROR_STR_APPEND)

        #TCP supports ECN using two flags in the TCP header.
        # The first, ECN-Echo (ECE) is used to echo back the congestion indication
        # (i.e., signal the sender to reduce the transmission rate).
        # The second, Congestion Window Reduced (CWR), to acknowledge
        # that the congestion-indication echoing was received.
        #leave alone for now
        self.ece_flag = ece_flag

        if not is_valid_control_flag_val(ece_flag):
            raise ValueError('ece flag is not valid\n' + ERROR_STR_APPEND)

        #When this bit is set, the data should be treated as priority over other data.
        # leave at 0 for now?
        self.urg_flag = urge_flag

        if not is_valid_control_flag_val(urge_flag):
            raise ValueError('urge flag is not valid\n' + ERROR_STR_APPEND)

        self.ack_flag = ack_flag

        if not is_valid_control_flag_val(ack_flag):
            raise ValueError('ack flag is not valid\n' + ERROR_STR_APPEND)

        #this is the push function. This tells an application that
        # the data should be transmitted immediately and
        # that we don’t want to wait to fill the entire TCP segment.
        # leaveat 0 for now?
        self.psh_flag = psh_flag

        if not is_valid_control_flag_val(psh_flag):
            raise ValueError('psh flag is not valid\n' + ERROR_STR_APPEND)

        #this resets the connection, when you receive this you have to
        # terminate the connection right away.
        # This is only used when there are unrecoverable errors and it’s not a
        # normal way to finish the TCP connection.
        #leave at 0 for now
        self.rst_flag = rst_flag

        if not is_valid_control_flag_val(rst_flag):
            raise ValueError('rst flag is not valid\n' + ERROR_STR_APPEND)

        #we use this for the initial three way handshake
        # and it’s used to set the initial sequence number.
        self.syn_flag = sync_flag

        if not is_valid_control_flag_val(sync_flag):
            raise ValueError('sync flag is not valid\n' + ERROR_STR_APPEND)

        #this bit is used to end the TCP connection. TCP is full duplex so
        # both parties will have to use the FIN bit to end the connection.
        # This is the normal method how we end a connection.
        self.fin_flag = fin_flag

        if not is_valid_control_flag_val(fin_flag):
            raise ValueError('fin flag is not valid\n' + ERROR_STR_APPEND)

        if window_size_in > MAX_16_BIT_INT:
            raise ValueError(f"window size cannot be greater than {MAX_16_BIT_INT}\n" + ERROR_STR_APPEND)

        self.window_size = window_size_in

        if urg_ptr > MAX_16_BIT_INT:
            raise ValueError(f"urgent pointer cannot be greater than {MAX_16_BIT_INT}\n" + ERROR_STR_APPEND)

        self.urg_ptr = urg_ptr

        self.read_checksum = read_checksum

        self.pseudo_checksum = 0

        self.checksum_actual = None

        self.set_16_bit_seg()




    # need to call after creating a tcp header obj
    # pass in values from ip_header object
    def set_pseudo_header(self, iph_protocol : int, iph_src_ip_addr : str, iph_dest_ip : str):
        self.protocol = iph_protocol
        self.ip_src = iph_src_ip_addr
        self.ip_dest = iph_dest_ip

        header_temp = self.dict_16_bits[1]

        for i in range(2, 11):
            header_temp += self.dict_16_bits[i]

        if type(self.tcp_data) == bytes:
            self.tcp_len = len(header_temp) + len(self.tcp_data)
            print(self.tcp_len)
        elif type(self.tcp_data) == str:
            self.tcp_len = len(header_temp) + len(self.tcp_data.encode('utf-8'))
        self.tcp_len = 40
        '''
        header_temp = self.dict_16_bits[1]

        for i in range(2,11):
            header_temp += self.dict_16_bits[i]

        tcp_data_len = len(self.tcp_data)

        # Padding zero
        if (tcp_data_len % 2 == 1):
            self.tcp_data += '0'
            tcp_data_len += 1

        self.tcp_len = len(header_temp) + tcp_data_len
        '''

        self.psuedo_header_dict = {}

        self.psuedo_header_dict[1] = pack('!H',self.protocol)

        #===============================================
        #split up 32 bit ip src address into two 16 bit segs
        src_32_bits = pack('!4s', socket.inet_aton(self.ip_src))
        src_unpacked_32_bits_split_two_16 = unpack('!HH', src_32_bits)
        src_16_bit_p1 = src_unpacked_32_bits_split_two_16[0]
        src_16_bit_p2 = src_unpacked_32_bits_split_two_16[1]

        self.psuedo_header_dict[2] = pack('!H',src_16_bit_p1)
        self.psuedo_header_dict[3] = pack('!H', src_16_bit_p2)

        #===============================================
        #split up 32 bit dest address into two 16 bit segs
        dest_32_bits = pack('!4s', socket.inet_aton(self.ip_dest))
        dest_unpacked_32_bits_split_two_16 = unpack('!HH', dest_32_bits)
        dest_16_bit_p1 = dest_unpacked_32_bits_split_two_16[0]
        dest_16_bit_p2 = dest_unpacked_32_bits_split_two_16[1]

        self.psuedo_header_dict[4] = pack('!H',dest_16_bit_p1)
        self.psuedo_header_dict[5] = pack('!H',dest_16_bit_p2)

        #=================================================

        self.psuedo_header_dict[6] = pack('!H',self.tcp_len)



    def set_16_bit_seg(self):

        self.dict_16_bits = {}

        # first 16 bit seg (src port)
        bytes_src_port = pack('!H',self.port_src)
        self.dict_16_bits[1] = bytes_src_port
        #==================================================

        #second 16 bit seg (dest port)
        bytes_dest_port = pack('!H', self.port_dest)

        self.dict_16_bits[2] = bytes_dest_port
        #==========================================

        #generate first 32 bits
        seq_num_32_bits = pack('!L', self.num_seq)

        seq_num_split_into_2_16_bit_ints = unpack('!HH', seq_num_32_bits)

        #seq_num_split_into_2_16_bit_ints = unpack('!HH', seq_num_32_bits)
        seq_num_16_p1 = seq_num_split_into_2_16_bit_ints[0]
        seq_num_16_p2 = seq_num_split_into_2_16_bit_ints[1]

        #save in 16 bit increments for checksum
        # third and fourth 16 bit seg (seq number)
        self.dict_16_bits[3] = pack('!H',seq_num_16_p1)
        self.dict_16_bits[4] = pack('!H',seq_num_16_p2)

        #=======================================================

        ack_num_32_bits = pack('!L', self.num_ack)
        ack_num_split_into_2_16_bit_ints = unpack('!HH',ack_num_32_bits)
        ack_num_16_p1 = ack_num_split_into_2_16_bit_ints[0]
        ack_num_16_p2 = ack_num_split_into_2_16_bit_ints[1]

        # save in 16 bit increments for checksum
        # fifth and sixth 16 bit seg (ack number)
        self.dict_16_bits[5] = pack('!H',ack_num_16_p1)
        self.dict_16_bits[6] = pack('!H',ack_num_16_p2)

        #===========================================================

        data_offset_reserve = get_val_data_offset_reserve(self.data_offset, self.rsv_3_bits)

        lst_flags = [self.ns_flag, self.cwr_flag,
                     self.ece_flag,self.urg_flag,self.ack_flag,
                     self.psh_flag, self.rst_flag, self.syn_flag,self.fin_flag]

        for i in range(len(lst_flags)):
            data_offset_reserve = (data_offset_reserve << 1) + lst_flags[i]

        # sevent 16 bit seg (data offset + reserve bits + flags
        self.dict_16_bits[7] = pack('!H',data_offset_reserve)

        #==============================================================

        #eigth 16 bit seg (window size)
        self.dict_16_bits[8] = pack('!H',self.window_size)
        #================================================================

        #9th seg ment pseudo checksum = 0 needed to calculate checksum
        self.dict_16_bits[9] = pack('!H',self.pseudo_checksum)

        #==============================================================

        self.dict_16_bits[10] = pack('!H', self.urg_ptr)


    #also sets self.checksum_actual attr and corrects dict bits
    def calc_checksum(self):

        lst_16_bit_segs = []

        if (self.protocol == None):
            raise ValueError('ERROR: Must call tcp_header.set_pseudoheader method before calculating checksum\n'
                             'EXITING PROGRAM')

        if (self.calc_checksum_flag == True):
            raise RuntimeError("ERROR: checksum cannot be calculated more than once\n"
                               "please CALL get_calculated_checksum method to get checksum value instead\n"
                               "EXITING PROGRAM")

        for i in range(1,7):
            lst_16_bit_segs.append(self.psuedo_header_dict[i])

        for j in range(1,11):
            lst_16_bit_segs.append(self.dict_16_bits[j])

        x = lst_16_bit_segs[0]
        for j in range(1,len(lst_16_bit_segs)):
            x += lst_16_bit_segs[j]

        starter = 0

        for i in range(len(lst_16_bit_segs)):
            temp = unpack('!H', lst_16_bit_segs[i])
            current = binary_addition_checksum(temp[0], starter)
            starter = current

        mask = 2 ** 16 - 1
        checksum = current & mask
        checksum = checksum + 0x0001
        checksum = 0xffff - checksum

        self.calc_checksum_flag = True

        self.checksum_actual = checksum

        self.dict_16_bits[9] = pack('!H',self.checksum_actual)

        return self.checksum_actual

    def get_calculated_checksum(self):
        if (self.protocol == None):
            raise ValueError('ERROR: Must call tcp_header.set_pseudoheader method before calling get_calculated_checksum\n'
                             'EXITING PROGRAM')
        if (self.calc_checksum_flag == False):
            raise RuntimeError('Please call calc_checksum method before calling get_calculated_checksum\n'
                               'EXITING PROGRAM')
        return self.checksum_actual

    def generate_tcp_packet(self):
        if (self.calc_checksum_flag == False):
            raise RuntimeError('ERROR: Please call calc_checksum method before generating tcp')

        bytes_out = self.dict_16_bits[1]

        for i in range(2,11):
            bytes_out += self.dict_16_bits[i]

        if type(self.tcp_data) == bytes:
            return bytes_out + self.tcp_data
        elif type(self.tcp_data) == str:
            return bytes_out + self.tcp_data.encode('utf-8')









