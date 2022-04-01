import socket as S
from socket import AF_INET, SOCK_RAW, IPPROTO_RAW
from project_constants import DOUBLE_LINE_DIVIDER
from tcp_packets import tcp_header, ip_header
import struct
import time
import random

class raw_socket():

    def __init__(self, host_name, dest_port, source_ip, source_port, display=False):
        # try/except block for each socket creation
        self.socket_sender = S.socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
        self.socket_rcvr = S.socket(S.AF_INET, S.SOCK_RAW, S.IPPROTO_TCP)
        
        self.host_name = host_name
        self.source_ip = source_ip
        self.dest_ip = S.gethostbyname(host_name)

        self.source_port = source_port
        self.dest_port = dest_port

        self.curr_seq_num = 0
        self.curr_ack_num = 0

        self.connect_sender_socket(display)
        self.threeway_handshake()

    def connect_sender_socket(self, display=False):
        try:
            self.socket_sender.connect((self.dest_ip, self.dest_port))
        except:
            if display == True:
                print("ERROR: Socket Sender failed to connect:\n"
                      f"HOST: {self.host_name}\nHOST IP: {self.dest_ip}\nPORT: {self.dest_port}\n" +
                      "EXITING PROGRAM")
            self.close_connection()
            exit(1)

        if display == True:
            print(f"Raw TCP Sender Socket Successfully Connected to:"
                  f"\nHOST: {self.host_name}\nHOST IP: {self.dest_ip}\nPORT: {self.dest_port}\n"+
                  DOUBLE_LINE_DIVIDER)

    def get_basic_tcp_hdr(self):
        return tcp_header(self.source_ip, self.source_port, self.dest_ip, self.dest_port)

    def get_basic_ip_hdr(self):
        return ip_header(self.source_ip, self.source_port, self.dest_ip, self.dest_port)
    
    def create_packet_to_send(self, data, syn_val, seq_num, ack_val, ack_num):
        ip_hdr = self.get_basic_ip_hdr().assemble_ip_header()
        
        tcp_hdr = self.get_basic_tcp_hdr()
        tcp_hdr.set_syn(syn_val)
        tcp_hdr.set_ack(ack_val)
        tcp_hdr.set_seq_num(seq_num)
        tcp_hdr.set_ack_num(ack_num)

        ftcp_hdr = tcp_hdr.assemble_tcp_header()

        return ip_hdr + ftcp_hdr + data
    
    def send_packet(self, data):
        packet = self.create_packet_to_send(data)

        # increase count to send more packets
        #count = 3
        
        #for i in range(count):
        print('sending packet...')
        # Send the packet finally - the port specified has no effect
        # put this in a loop if you want to flood the target 
        self.socket_sender.sendto(packet, (self.dest_ip, 0))	
        print('send')
        time.sleep(1)
            
        #print('all packets sent')

    def receive_packet(self):
        info_recvd = self.socket_rcvr.recvfrom(65565)
        
        print("got from dest", info_recvd)
        packet = info_recvd[0]
        src_address = info_recvd[1]
        
        header = struct.unpack('!BBHHHBBH4s4s', packet[:20])

        if (header[6] == 6):
            protocol = "TCP"
        elif (header[6] == 17):
            protocol = "UDP"

        print("Protocol: ", protocol)
        print("Address: ", src_address)
        print("Header: ", header)
        return header

    def parse_header_received(self, header):
        if (header[6] == 6):
            protocol = "TCP"
        elif (header[6] == 17):
            protocol = "UDP"
        
        seq_num, ack_num = 0,0
        # get the seq_num
        # get the ack_num
        return seq_num, ack_num

    def threeway_handshake(self):
        # set syn flag = 1 for initiating host
        initial_seq_num = random.randint(0, 50505)
        initial_packet = self.create_packet_to_send(data="", syn_val=1, seq_num=initial_seq_num, ack_val=0, ack_num=0)
        self.send_packet(initial_packet)

        # receive packet 
        header_received = self.receive_packet()
        seq_num_rcvd, ack_num = self.parse_header_received(header_received)

        if ack_num == initial_seq_num + 1:
            print('initial handshake received')

        # send with seq_num=initial_seq_num+1, ack = 1, and ack_num = seq_num_rcvd + 1
        third_packet = self.create_packet_to_send(data="", syn_val=1, seq_num=initial_seq_num+1, ack_val=1, ack_num=seq_num_rcvd+1)
        self.send_packet(third_packet)

    def close_connection(self,display=False):
        self.socket_sender.close()
        self.socket_rcvr.close()

        if display == True:
            print("socket connection closed")
