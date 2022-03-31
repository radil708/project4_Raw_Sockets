import socket as S
from socket import AF_INET, SOCK_RAW, IPPROTO_RAW
from project_constants import DOUBLE_LINE_DIVIDER
from tcp_packets import tcp_packet
import struct

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


    def set_socket_values(self,src_ip_in, dest_ip_in):
        self.source_ip = src_ip_in
        self.dest_ip = dest_ip_in

    def close_connection(self,display=False):
        self.socket_sender.close()
        self.socket_rcvr.close()

        if display == True:
            print("socket connection closed")

    def create_packet_to_send(self):
        #initialize packet
        pass
    
    def send_packet(self, tcp_packet):
        pass
    
    def receive_packet(self):
        pass

    def threeway_handshake(self):
        # set syn flag = 1 for initiating host
        
        # packet 1 from hostA -> hostB is empty with syn = 1
        packet1 = tcp_packet(self.source_ip, self.source_port, self.dest_ip, self.dest_port)
        packet1.syn = 1
        self.curr_seq_num = self.curr_seq_num + 1
        packet1.set_seq_numg(self.curr_seq_num)

        # packet 2 from hostB -> hostA
        packet2 = tcp_packet(self.source_ip, self.source_port, self.dest_ip, self.dest_port)
        packet2.syn = 1
        packet2.ack = 1
        self.curr_ack_num = self.curr_seq_num + 1
        packet2.set_ack_num(self.ack_num)

        # packet 3 from hostA -> hostB
        packet3 = tcp_packet(self.source_ip, self.source_port, self.dest_ip, self.dest_port)
        packet3.set_ack_num(s)