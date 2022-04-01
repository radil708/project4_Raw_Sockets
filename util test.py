import struct
import binascii

def split_16bit_to_28bit(val_int):
    c = (val_int >> 8) & 0xff
    f = val_int & 0xff
    return c,f




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
    print(bin(version_ihl_bytes_out << 8))
    seg_1 = (version_ihl_bytes_out << 8) + 0

    # fill up the 3 bits as a 4 bit value
    full_flags = 0 + (0<< 2) + (0 << 1) \
        # convert to a 3 bit value
    full_flags = (full_flags >> 1)
    # 8 bytes
    flag_offset_bytes_out = int(format(((full_flags << 13) + 0),'016b'))  # 16 bits

    first_16 = seg_1
    print("first", bin(first_16))
    second_16 = 40
    print("second", bin(40))
    third_16 = 43981
    print("yo",bin(third_16))
    fourth_16 = flag_offset_bytes_out
    fifth_16 = (40 << 4) + 6
    print("fifth", bin(fifth_16))
    print(bin(first_16) + bin(second_16))
    #fifth_16 = (40 << ) + 6
    checksum = int(first_16) + int(second_16) + int(third_16) + int(fourth_16) + int(fifth_16)
    print(bin(checksum))
    print(struct.pack('!H',checksum))
    print("\xa6ec")

    #seg_2 = (0 << 32) + flag_offset_bytes_out

main_2()

