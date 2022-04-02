from struct import pack,unpack
from headers.ip_header import MAX_4_BIT_INT,MAX_8_BIT_INT,MAX_16_BIT_INT,MAX_13_BIT_INT
import socket

MAX_32_BIT_INT = 2147483647

ERROR_STR_APPEND = "FAILED TO CONSTRUCT TCP HEADER\nEXITING PROGRAM"

def is_valid_control_flag_val(ctrl_flg_val):
    if (ctrl_flg_val != 0 and ctrl_flg_val != 1):
        return False
    else:
        return True

class tcp_header():
    def __init__(self,src_port_in : int, dest_port_in : int,seq_num : int, ack_num : int, data_offset_in : int,
                 ack_flag,sync_flag, window_size_in,urg_ptr, read_checksum=0, ns_flag=0,cwr_flag=0,ece_flag=0,urge_flag=0,psh_flag=0,rst_flag=0,fin_flag=0):

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
            raise ValueError(f'ERROR: ack num cannot be greater than f{MAX_32_BIT_INT}\n' + ERROR_STR_APPEND)

        #The receiving device maintains an acknowledgment number starting with zero.
        # It increments this number according to the number of bytes received.
        self.num_ack = ack_num

        if data_offset_in > MAX_4_BIT_INT:
            raise ValueError(f'ERROR: data offset cannot be greater than f{MAX_4_BIT_INT}\n' + ERROR_STR_APPEND)

        self.data_offset = data_offset_in

        # reserved bits
        self.rsv_flag = 0

        # 9 control bits/flags

        #experimental flag, leave alone
        self.ns_flag = ns_flag

        if not is_valid_control_flag_val(ns_flag):
            raise ValueError('ns flag is not valid\n' + ERROR_STR_APPEND)

        #TCP supports ECN using two flags in the TCP header.
        # The first, ECN-Echo (ECE) is used to echo back the congestion indication
        # (i.e., signal the sender to reduce the transmission rate).
        # The second, Congestion Window Reduced (CWR), to acknowledge
        # that the congestion-indication echoing was received.
        #leave alone for now
        self.ece_flag = ece_flag

        if not is_valid_control_flag_val(ece_flag):
            raise ValueError('ece flag is not valid\n' + ERROR_STR_APPEND)

        # set when the sending node receives a TCP segment that has the ECE bit turned on.
        # It is used to indicate to a peer that the congestion window was reduced to
        # facilitate recovery of an intermediate device
        # leave alone for now?
        self.cwr_flag = cwr_flag

        if not is_valid_control_flag_val(cwr_flag):
            raise ValueError('cwr flag is not valid\n' + ERROR_STR_APPEND)

        #When this bit is set, the data should be treated as priority over other data.
        # leave at 0 for now?
        self.urg_flag = urge_flag

        if not is_valid_control_flag_val(urge_flag):
            raise ValueError('urge flag is not valid\n' + ERROR_STR_APPEND)

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

        self.checksum = 0

        if urg_ptr > MAX_16_BIT_INT:
            raise ValueError(f"urgent pointer cannot be greater than {MAX_16_BIT_INT}\n" + ERROR_STR_APPEND)


    def set_pseudo_header(self,protocol : int, src_ip : str, dest_ip : str, tcp_len : int):
        self.protocol = protocol
        self.ip_src = src_ip
        self.ip_dest = dest_ip
        self.tcp_len = tcp_len


    def generate_tcp_packet(self):

        dict_16_bits = {}

        # first 16 bit seg
        bytes_src_port = pack('!H',self.port_src)
        dict_16_bits[1] = bytes_src_port
        #==================================================

        #second 16 bit seg
        bytes_dest_port = pack('!H', self.port_dest)
        dict_16_bits[2] = bytes_dest_port
        #==========================================

        #generate first 32 bits
        seq_num_32_bits = pack('L', self.num_seq)
        seq_num_split_into_2_16_bit_ints = unpack('!HH', seq_num_32_bits)
        seq_num_16_p1 = seq_num_split_into_2_16_bit_ints[0]
        seq_num_16_p2 = seq_num_split_into_2_16_bit_ints[1]

        #save in 16 bit increments for checksum
        # third and fourth 16 bit seg
        dict_16_bits[3] = seq_num_16_p1
        dict_16_bits[4] = seq_num_16_p2

        #=======================================================

        ack_num_32_bits = pack('L', self.num_ack)
        ack_num_split_into_2_16_bit_ints = unpack('!HH',ack_num_32_bits)
        ack_num_16_p1 = ack_num_split_into_2_16_bit_ints[0]
        ack_num_16_p2 = ack_num_split_into_2_16_bit_ints[1]

        # save in 16 bit increments for checksum
        # fifth and sixth 16 bit seg
        dict_16_bits[5] = ack_num_16_p1
        dict_16_bits[6] = ack_num_16_p1

        #===========================================================






