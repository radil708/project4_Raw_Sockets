import subprocess
import re

def fetch_address_data_windows(use_default_gateway_ip : bool = True):
    # start a process and set command to ipconfig
    cmd_line_process = subprocess.Popen(['ipconfig'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # send the command and get output
    cmd_line_output_bytes, cmd_err_bytes = cmd_line_process.communicate()

    output_str = cmd_line_output_bytes.decode()

    output_list = output_str.split("\r\n\r\n")

    data_addr_all = []

    for each in output_list:
        if "IPv4" in each:
            data_addr_all.append(each)
        else:
            continue

    data_addr_all_new = []

    if data_addr_all == []:
        raise RuntimeError("Could not find IPv4 Address")

    dot_pattern = re.compile(r"\. ")
    space_pattern = re.compile(r"\s")

    for i in range(len(data_addr_all)):
        temp = re.sub(r"\r\n", '_SPLIT_DELIMETER',data_addr_all[i])
        temp_1 = re.sub(dot_pattern,"",temp)
        temp_2 = re.sub(space_pattern, "", temp_1)
        temp_3 = temp_2.split("_SPLIT_DELIMETER")
        data_addr_all_new.append(temp_3)

    #TODO delete
    #print(data_addr_all_new[0])
    #print(data_addr_all_new[1])

    parse_output = ""

    found_flag = False

    if use_default_gateway_ip == False:
        for each in data_addr_all_new:
            temp_dict = {}
            for each_addr in each:
                temp = each_addr.split(":")
                temp_dict[temp[0]] = temp[1]
            if temp_dict["DefaultGateway"] == "":
                parse_output = temp_dict["IPv4Address"]
                found_flag = True
                break
            if found_flag == True:
                break
            else:
                continue
    else:
        for each in data_addr_all_new:
            temp_dict = {}
            for each_addr in each:
                temp = each_addr.split(":")
                temp_dict[temp[0]] = temp[1]
            if temp_dict["DefaultGateway"] != "":
                parse_output = temp_dict["IPv4Address"]
                found_flag = True
                break
            if found_flag == True:
                break
            else:
                continue

    return parse_output

def fetch_address_data_linux():
    # start a process and set command to ipconfig
    cmd_line_process = subprocess.Popen(['ifconfig'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # send the command and get output
    cmd_line_output_bytes, cmd_err_bytes = cmd_line_process.communicate()

    cmd_line_output_str = cmd_line_output_bytes.decode()
    info_list = (cmd_line_output_str.split("\n"))[1].split(" ")
    return info_list[1]

def create_tcp_header(source_port_in, dest_port_in, seq_num,
                      ack_num,header_len, window_size, flags, checksum,urg_ptr,checksum,options,data ):
    pass

def create_ip_header(version,h_len,s_type,total_len,id,flags,
                     f_offset,time_to_live,prot,h_checksum,source_ip,dest_ip,option_padding)


