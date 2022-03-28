#!/usr/bin/env python3
import os
from random import randint
import sys
from project_constants import *
from raw_sockets_package.rawSocket import raw_socket
import socket as s
from project4_helper_functions import *
from os import system

def main():
    all_args = sys.argv[1:]

    if len(all_args) < 1:
        raise ValueError("Missing Arg, 1: linux, 0: windows")

    try:
        value_in = int(all_args[0])
    except ValueError:
        print("Argument must be an int; 0 or 1")

    if value_in != 0 and value_in != 1:
        raise ValueError("Arg can only be 1 (linux) or 0 (windows)")

    source_ip = None

    if value_in == 0:
        drop_tcp_rst_cmd = "iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP"
        os.system(drop_tcp_rst_cmd)
        source_ip = fetch_address_data_linux()

    else:
        source_ip = fetch_address_data_windows(False)

    dest_ip = s.gethostbyname(TEST_HOST)
    r = randint(1001, 65535)
    my_socket = raw_socket(dest_ip,TEST_HOST_2)


main()