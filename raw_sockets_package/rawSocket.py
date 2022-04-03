import socket as S
from socket import AF_INET, SOCK_RAW, IPPROTO_RAW
from wsgiref import headers
from project_constants import *
from headers_r import tcp_header_r, ip_header_r, packet_parser_r
from raw_sockets_package.headers import *
import struct
import time
import random

class raw_socket:

    def __init__(self, host_name, dest_port, source_ip, source_port, display=False):
        # try/except block for each socket creation
        self.socket_sender = S.socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
        self.socket_rcvr = S.socket(S.AF_INET, S.SOCK_RAW, S.IPPROTO_TCP)
        
        self.host_name = host_name
        self.source_ip = source_ip
        self.dest_ip = S.gethostbyname(host_name)

        print('source ip:', source_ip, 'source_port', source_port)

        self.source_port = source_port
        self.dest_port = dest_port
        self.initial_seq_num = random.randint(0, 50505) # this is random seq

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

    def get_basic_tcp_hdr(self, data_len, seq_num, ack_num, syn_flag, ack_flag):
        tcp_hdr = tcp_header_r.tcp_header(self.source_port, self.dest_port, seq_num=seq_num, ack_num=ack_num, ack_flag=ack_flag, sync_flag=syn_flag)
        psh = tcp_hdr.set_pseudo_header(S.IPPROTO_TCP, self.source_ip, self.dest_ip, 20+data_len)
        check = tcp_hdr.calc_checksum()

        return tcp_hdr.generate_tcp_packet()

    def get_basic_ip_hdr(self):
        ip_hdr = ip_header_r.ip_header(self.source_ip, self.dest_ip)
        return ip_hdr.generate_ip_packet()
    
    def create_packet_to_send(self, data, seq_num, ack_num, syn_flag, ack_flag):
        data = struct.pack(data)
        data_len = len(data)
        print('data length in bytes', data_len, data)

        #FROM headers_r directory:
        ip_hdr_bytes = self.get_basic_ip_hdr()
        tcp_hdr_bytes = self.get_basic_tcp_hdr(data_len, seq_num, ack_num, syn_flag, ack_flag)
        
        #FROM headers.py:
        #ip_hdr_bytes = ip_header_1(self.source_ip, self.dest_ip).assemble_ip_header()
        #tcp_hdr_bytes = tcp_header_1(self.source_ip, self.source_port, self.dest_ip, self.dest_port, syn_flag, ack_flag, ack_num, seq_num).assemble_tcp_header()
        
        return ip_hdr_bytes + tcp_hdr_bytes + data
    
    def send_packet(self, packet):
        print('sending packet...')
        self.socket_sender.sendto(packet, (self.dest_ip, self.dest_port))	
        print('send')
            
    def receive_packet(self):
        self.socket_rcvr.settimeout(60)
        info_recvd = self.socket_rcvr.recv(65535)
        
        print("got from dest total len", len(info_recvd))

        header = info_recvd[:40]
        data = info_recvd[40:]
        
        #RAW BYTES RECEIVED IN PACKET
        #print('ip got', header[:20])
        #print('tcp got', header[20:40])
        #print('data got', data[40:])
        return header, data

    def threeway_handshake(self):
        # set syn flag = 1 for initiating host
        #RAmzi current seq number and current flag numb

        initial_packet = self.create_packet_to_send(data="", seq_num=self.initial_seq_num, ack_num=0, syn_flag=1, ack_flag=0)
        self.send_packet(initial_packet)
        
        # receive 5 packets until we get what we want
        x = 0
        while x < 5:
            # receive packet 
            header_received, data_received = self.receive_packet()
            #FROM headers_r dir
            #parser = packet_parser.packet_parser(self.source_ip, self.source_port, self.dest_ip, self.dest_port, header_received, data_received)
            #ip_rcvd_dict = parser.parse_ip_packet(header_received[:20])
            #tcp_rcvd_dict = parser.parse_tcp_packet(header_received[20:40])
            
            #FROM headers.py
            parser = header_parser(self.source_ip, self.source_port, self.dest_ip, self.dest_port, header_received, data_received)
            
            #print('ip headers from rcvd packet', parser.ip_hdr_dict)
            if parser.ip_hdr_dict['protocol'] != 6: continue

            #print('tcp headers from rcvd packet', parser.tcp_hdr_dict)
            ack_num_rcvd = parser.tcp_hdr_dict['ack_num']
            seq_num_rcvd = parser.tcp_hdr_dict['seq_num']
            
            #print('data from rcvd packet', parser.data)
            print('initial seq sent', self.initial_seq_num, 'ack rcvd', ack_num_rcvd, 'seq rcvd', seq_num_rcvd)
            
            if ack_num_rcvd == self.initial_seq_num + 1:
                print('initial handshake received')
                break

            #if parser.tcp_hdr_dict['port_dest'] != self.source_port: continue

            x+=1

        # send with seq_num=initial_seq_num+1, ack = 1, and ack_num = seq_num_rcvd + 1
        third_packet = self.create_packet_to_send(data="", seq_num=self.initial_seq_num, ack_num=seq_num_rcvd+1, syn_flag=1, ack_flag=1)
        self.send_packet(third_packet)

    def close_connection(self,display=False):
        self.socket_sender.close()
        self.socket_rcvr.close()

        if display == True:
            print("socket connection closed")
