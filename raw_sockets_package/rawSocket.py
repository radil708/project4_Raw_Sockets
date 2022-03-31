import socket as S
from socket import AF_INET, SOCK_RAW, IPPROTO_RAW
from project_constants import DOUBLE_LINE_DIVIDER

class raw_socket():

    def __init__(self):

        self.socket_sender = S.socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
        self.socket_rcvr = S.socket(S.AF_INET, S.SOCK_RAW, S.IPPROTO_TCP)

        self.source_ip = None
        self.dest_ip = None
        self.port = None

    def set_sender_socket(self,host_name, port_in,display=False):
        host_in = S.gethostbyname(host_name)
        self.dest_ip = host_in
        self.port = port_in

        try:
            self.socket_sender.connect((host_in, port_in))
        except:
            if display == True:
                print("ERROR: Socket Sender failed to connect:\n"
                      f"HOST: {host_name}\nHOST IP: {host_in}\nPORT: {port_in}\n" +
                      "EXITING PROGRAM")
            self.close_connection()
            exit(1)

        if display == True:
            print(f"Raw TCP Sender Socket Successfully Connected to:"
                  f"\nHOST: {host_name}\nHOST IP: {host_in}\nPORT: {port_in}\n"+
                  DOUBLE_LINE_DIVIDER)


    def set_socket_values(self,src_ip_in, dest_ip_in):
        self.source_ip = src_ip_in
        self.dest_ip = dest_ip_in

    def close_connection(self,display=False):
        self.socket_sender.close()
        self.socket_rcvr.close()

        if display == True:
            print("socket connection closed")


