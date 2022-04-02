import struct
import socket
def add_binary_nums(x, y):
    x = format(x,'0b')
    y = format(y,'0b')
    max_len = max(len(x), len(y))

    x = x.zfill(max_len)
    y = y.zfill(max_len)

    # initialize the result
    result = ''

    # initialize the carry
    carry = 0

    # Traverse the string
    for i in range(max_len - 1, -1, -1):
        r = carry
        r += 1 if x[i] == '1' else 0
        r += 1 if y[i] == '1' else 0
        result = ('1' if r % 2 == 1 else '0') + result
        carry = 0 if r < 2 else 1  # Compute the carry.

    if carry != 0: result = '1' + result

    return result.zfill(max_len)

def main():
    v = 4
    ihl = 5

    # make 8 bits fo v and ihl
    v_ihl = (4 << 4) + 5

    service = 0
    total_len = 40
    mask = 2 ** 16 - 1

    v_ihl_serv = (v_ihl << 8) & mask

    lst_packed = []
    A = struct.pack('!H',v_ihl_serv)
    lst_packed.append(A)

    #==============================

    B = struct.pack('!H',total_len)
    lst_packed.append(B)

    #==============================

    id = 43981
    C = struct.pack('!H',id)
    lst_packed.append(C)
    #=========================

    full_flags = 0 + (0 << 2) + (0 << 1) \
        # convert to a 3 bit value
    full_flags = (full_flags >> 1)
    flag_frag = (full_flags << 13) + 0

    D = struct.pack('!H', flag_frag)
    lst_packed.append(D)

    #==============================
    ttl_p = (64 << 8) + 6
    E = struct.pack('!H', ttl_p)
    lst_packed.append(E)
    #=============================
    F = struct.pack('!H',0)
    lst_packed.append(F)
    #=============================
    ip_src = "10.10.10.2"
    temp_pack = struct.pack('!4s', socket.inet_aton(ip_src))
    unpacked_temp = struct.unpack('!HH',temp_pack)
    G = struct.pack('!H',unpacked_temp[0])
    H = struct.pack('!H', unpacked_temp[1])
    lst_packed.append(G)
    lst_packed.append(H)
    #==============================
    ip_dest = "10.10.10.1"
    temp_pack_d = struct.pack('!4s', socket.inet_aton(ip_dest))
    unpacked_temp_d = struct.unpack('!HH', temp_pack_d)
    I = struct.pack('!H', unpacked_temp_d[0])
    J = struct.pack('!H', unpacked_temp_d[1])
    lst_packed.append(I)
    lst_packed.append(J)
    #==================================
    for each in lst_packed:
        print(each.decode('all-escapes'))

    print("===============================")

    for each in lst_packed:
        starter = 0
        t = struct.unpack('!H',each)
        print(t[0])

    print("================")

    starter = 0
    for each in lst_packed:
        t = struct.unpack('!H',each)
        sol = add_binary_nums(t[0],starter)
        back_to_int = int(sol,2)
        starter=back_to_int


    print(sol,back_to_int)
    print(back_to_int & mask)
    close = back_to_int & mask
    close += 0x0001
    print(0xffff - close)
    #first = add_binary_nums(17664,60)
    #first_as_int = int(first,2)
    #print(int(first,2))
    #print(struct.pack('!H',first_as_int).decode('all-escapes'))

    test = add_binary_nums(17664,0)
    print(int(test,2))




main()