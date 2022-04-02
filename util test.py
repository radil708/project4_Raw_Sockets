import socket
import struct
import binascii
import all_escapes
import ipaddress

def split_16bit_to_28bit(val_int):
    c = (val_int >> 8) & 0xff
    f = val_int & 0xff
    return c,f


def checksum(msg):
    sum = 0

    #Taking 2 characters at a time in a loop
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        sum += w

    sum = (sum>>16) + (sum & 0xffff);
    sum += (sum >> 16);

    #Complement and mask to 4 byte short
    sum = ~sum & 0xffff
    return sum

def pack_ip(ip):
    num_list = map(int, ip.split('.'))
    return repr(bytearray(num_list))

src_ip = pack_ip('127.0.0.255')
print(repr(src_ip))


def add_binary_nums(x, y):
    x = format(x,'016b')
    y = format(y,'016b')
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

'''
def convert_int_to_bits(val_in : int, len_bytes : int, unsigned : bool = True):
    # TODO DELETE 1 byte = 8 bits
    if len_bytes == 2:
        if unsigned == True:
            bytes_out = struct.pack('B',val_in)
        else:
            bytes_out = struct.pack('H',val_in)
    elif len_bytes == 4:
        if unsigned == True:
            bytes_out = struct.pack('>L', val_in)
        else:
            bytes_out = struct.pack('l', val_in)
    elif len_bytes == 8:
        if unsigned == True:
            bytes_out = struct.pack('>Q', val_in)
        else:
            bytes_out = struct.pack('q', val_in)
    elif len_bytes == 16:
        #TODO check if padding should go before or after, current pads before/prepends
        if unsigned == True:
            bytes_out = struct.pack('>8xQ', val_in)
        else:
            bytes_out = struct.pack('8xq',val_in)
    else:
        raise ValueError('ERROR: Invalid Params; Valid Params Listed Below\nlen_bytes must be 2,4,8, or 16\n'
                         'val_in cannot be larger than 2^63')

    return bytes_out

'''



def main():
    '''
    x = convert_int_to_bytes(4,16)
    print(x)
    print(len(x))
    print(type(x))
    print(struct.unpack('QQ',x))

    my_hexdata = "1a"

    scale = 16  ## equals to hexadecimal

    num_of_bits = 8

    z = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

    print(z)


    a = (4 << 4) + 5

    print(c)
    print(struct.unpack('B',c))

    print(a, type(a),struct.pack('B',a))

    bytes_out = struct.pack('B',4)
    print(bytes_out)


    a = bin(4)
    b = bin(5)
    print(a,b)
    c = ("0x%x" % int('01000101',2))
    d = int(c,16)
    e = hex(d)
    print(hex(d))
    print(type(e))
    print(e.encode('ascii'))
    print('\\x45'.encode('utf-8'))

    v = 4 << 4 | 4
    print(v)
    z = struct.pack('!B',v)
    print(struct.unpack('B',z))

    fmt_string = "!BBHHHBBHLL"

    version_ihl = (4 << 4) + 5
    tos = 0
    total_length = 100
    identification = 42
    flags = 0
    ttl = 32
    protocol = 6
    checksum = 0xabcd
    s_addr = 0x0a0b0c0d
    d_addr = 0x01010101

    ip_header = struct.pack(fmt_string,
                            version_ihl,
                            tos,
                            total_length,
                            identification,
                            flags,
                            ttl,
                            protocol,
                            checksum,
                            s_addr,
                            d_addr)

    print(ip_header)
    print(binascii.hexlify(ip_header).decode())
    '''




    z = 4 << 4
    q = 5 << 4
    print("here")
    print(z,q)

    print(bin(4),bin(5))

    print(bytes.fromhex("000102030405060708090A0B0C0D0E0F"))
    print(bytes.fromhex("45000028"))

    fmt_string = "!BBHHHBBHLL"

    version_ihl = (4 << 4) + 5
    tos = 0
    total_length = 100
    identification = 42
    flags = 0
    ttl = 32
    protocol = 6
    checksum = 0xabcd
    s_addr = 0x0a0b0c0d
    d_addr = 0x01010101

    ip_header = struct.pack(fmt_string,
                            version_ihl,
                            tos,
                            total_length,
                            identification,
                            flags,
                            ttl,
                            protocol,
                            checksum,
                            s_addr,
                            d_addr)

    a = (0 << 5)
    b = (1 << 4)
    c = (1 << 3)
    d = 0
    e = a + b + c + d
    print(a,b,c,d, a + b + c + d)
    full_flags = 0 + (1 << 2) + (1 << 1)
    full_flags = (full_flags >> 1)
    print(bin(full_flags))
    print(bin(4095))
    print(struct.pack('!B',full_flags))
    print(bin((full_flags << 13) + (8 >> 12)))
    print((8 >> 12).bit_length())
    print(bin(4))

    version_ihl_bytes_out = ((4 << 4) + 5)  # 8 bits
    seg_1 = (version_ihl_bytes_out << 8) + 0 # 16 BITS
    seg_1_m = (seg_1 << 16) + 40
    q = split_16bit_to_28bit(seg_1)
    print(q[0],q[1])
    print(bin(q[0]),bin(q[1]))
    print(len(bin(q[0])), len(bin(q[1])))
    print(0x0028)
    print("yo")
    print((0<<12).bit_length())
    a = format(40,'08b')
    print(int(a,2))
    print(type(format(40,'08b')))
    print(format(40,'08b'))

    #to send 16 bit size or 2 bytes use h

    print(struct.pack('!L',seg_1_m))
    #print(bin(version_ihl))
    #print(ip_header)










def main_2():
    version_ihl_bytes_out = ((4 << 4) + 5)  # 8 bits
    print(struct.pack('!b',version_ihl_bytes_out))
    print(bin(version_ihl_bytes_out << 8))
    seg_1 = (version_ihl_bytes_out << 7) + 40
    print(bin(seg_1))

    # fill up the 3 bits as a 4 bit value
    full_flags = 0 + (0<< 2) + (0 << 1) \
        # convert to a 3 bit value
    full_flags = (full_flags >> 1)
    # 8 bytes
    flag_offset_bytes_out = int(format(((full_flags << 13) + 0),'016b'))  # 16 bits

    print("what",0x28)
    first_16 = seg_1
    print("first", bin(first_16))
    second_16 = 40
    print("second", bin(40))
    third_16 = 43981
    print("yo",bin(third_16))
    fourth_16 = flag_offset_bytes_out
    fifth_16 = (40 << 4) + 6
    print(bin(fifth_16))
    print("fifth", bin(fifth_16))
    print(bin(first_16) + bin(second_16))
    #fifth_16 = (40 << ) + 6
    a = struct.pack('!HHHHH', first_16, second_16, third_16, fourth_16, fifth_16)
    print(a)
    print(0x28)
    #print(ord(checksum))
    #print(struct.pack('!H',checksum))

    #seg_2 = (0 << 32) + flag_offset_bytes_out
    print(0x45)

def main_3():
    v= 4
    ihl = 5

    # make 8 bits fo v and ihl
    v_ihl = (4 << 4) + 5

    service = 0
    total_len = 40
    # correct
    a = struct.pack('!BBH',v_ihl,service,total_len)

    print(a)
    print(a.decode('all-escapes'))

    #======================================
    id = 43981
    # fill up the 3 bits as a 4 bit value
    full_flags = 0 + (0 << 2) + (0 << 1) \
        # convert to a 3 bit value
    full_flags = (full_flags >> 1)
    flag_frag = (full_flags << 13) + 0

    b = struct.pack('!HH',id,flag_frag)

    print(b.decode('all-escapes'))

    #===================================
    ttl = 40
    protocol = 6
    #print(bin(64))
    #get bitlength and shift until total is 16
    #print(a.bit_length())
    #print(7 + 9)
    #print(bin((64 << 9)))
    ttl_p = (64 << 8) + 6
    print(bin(ttl_p))
    print(42732,bin(42732))
    c = struct.pack('!HH',ttl_p,42732)
    print(c.decode('all-escapes'))

    temp_header = struct.pack('!HH',ttl_p,0)
    print(temp_header.decode('all-escapes'))

    d = struct.unpack('!H', b'\xa6\xec')
    print(bin(d[0]))
    print(d[0])

    #=========================
    ip_src = "10.10.10.2"
    ip_dest = "10.10.10.1"
    #print(socket.inet_aton(ip_src).decode())

    e = struct.pack('!4s',socket.inet_aton(ip_src))
    f = struct.pack('!4s',socket.inet_aton(ip_dest))
    print(e.decode('all-escapes'))
    print(f.decode('all-escapes'))

    lst = []
    print(a,b)
    unpacked_a = struct.unpack('!HH',a)
    lst.append(unpacked_a[0])
    lst.append(unpacked_a[1])
    unpacked_b = struct.unpack('!HH',b)
    lst.append(unpacked_b[0])
    lst.append(unpacked_b[1])
    c_unpacked = struct.unpack('!HH', temp_header)
    lst.append(c_unpacked[0])
    lst.append(c_unpacked[1])

    src_unpacked = struct.unpack('!HH',e)
    dest_unpacked = struct.unpack('!HH',f )
    lst.append(src_unpacked[0])
    lst.append(src_unpacked[1])

    lst.append(dest_unpacked[0])
    lst.append(dest_unpacked[1])

    new = add_binary_nums(lst[0],lst[1])

    for i in range(2,len(lst)):
        new = int(new,2)
        new = add_binary_nums(new,lst[i])

    new = int(new,2)
    print("checksum",new)


    print(unpacked_a)
    print(add_binary_nums(unpacked_a[0],unpacked_a[1]))




main_3()




