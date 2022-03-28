import socket as S
from socket import AF_INET, SOCK_RAW, IPPROTO_RAW

class raw_socket():

    def __init__(self,host_in,port_in):
        self.socket_sender = S.socket(AF_INET, SOCK_RAW, IPPROTO_RAW)

        try:
            self.socket.connect(host_in,port_in)
        except:
            print("ERROR: sender socket could not connect to host or port")
            exit(1)

        try:
            self.socket_rcvr = S.socket(S.AF_INET, S.SOCK_RAW, S.IPPROTO_TCP)
        except:
            print("ERROR: receiver socket could not be created")

        self.source_ip = None
        self.dest_ip = None
        self.port = port_in

    def set_socket_values(self,src_ip_in, dest_ip_in):
        self.source_ip = src_ip_in
        self.dest_ip = dest_ip_in


