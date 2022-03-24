import os
from project_constants import *
from raw_sockets_package.rawSocket import raw_socket
import socket as s

from project4_helper_functions import *
from os import system

def main():
    option = 1
    
    source_ip = None
    if option == 0:
        drop_tcp_rst_cmd = "iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP"
        os.system(drop_tcp_rst_cmd)
        source_ip = fetch_address_data_linux()

    else:
        source_ip = fetch_address_data_windows(False)

    dest_ip = s.gethostbyname(TEST_HOST)

    my_socket = raw_socket(dest_ip,TCP_PORT)


main()