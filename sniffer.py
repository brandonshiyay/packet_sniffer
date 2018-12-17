import socket
import struct
import uuid


s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
mac_addr = hex(uuid.getnode())[2:]
print(mac_addr)


def map_ipv4(addr):
    return '.'.join(map(str, addr))


def ipv6_addr(addr):
    v6addr = list()
    for i in range(1, int(len(addr)/4)+1):
        v6addr.append(addr[(4*i-4):(4*i)])
    return ':'.join(v6addr)
while True:
    r_data, addr = s.recvfrom(65535)
    dest, src, prototype = struct.unpack('! 6s 6s H', r_data[:14])
    data = r_data[14:]
    hex_dest = dest.hex()
    hex_src = src.hex()
    print('dest: {}, src: {}, proto: {}\n'.format(hex_dest, hex_src, prototype))
    # print(data)
    # print(data)
    if prototype == 2048:
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version & 15) * 4
        tos = data[1]
        ttl, protocol, src_addr, dest_addr = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        ipv4_data = data[header_length:]
        print('\tversion header length:{}'.format(version_header_length))
        print('\tIP Version:{}'.format(version))
        print('\tprotocol: {}\n\t{} ----> {}'.format(protocol, map_ipv4(src_addr), map_ipv4(dest_addr)))
        if protocol == 6:
            print('\tType: TCP')
            src_port, dest_port, seq_num, ack_num = struct.unpack('! H H L L', ipv4_data[:12])
            print('\tSrc port:{}\n\tDest port:{}\n\tSeq number:{}\n\tAck number:{}'.format(src_port,dest_port, seq_num, ack_num))
        elif protocol == 17:
            print('\tType: UDP')
    if prototype == 2054:
        '''
        ARP packets
        Operation: 1 for request, 2 for reply.
        '''
        hardware_type, protocol_type, hardware_address_length, protocol_address_length, operation = struct.unpack('! H H B B H', data[:8])
        SHA, SIA, THA = struct.unpack('! 6s 4s 6s', data[8:24])
        TIPA = struct.unpack('! 4s', data[24:28])
        print('\tARP packet')
        print('\tHardware Type:{}\n\tProtocol Type:{}'.format(hardware_type, protocol_type))
        print('\tHAL:{}\n\tPAL:{}'.format(hardware_address_length, protocol_address_length))
        print('\tSHA:{}\n\tSIA:{}\n\tTHA:{}'.format(SHA.hex(), map_ipv4(SIA), THA.hex()))
        print('\tTarget IP Address:{}'.format(map_ipv4(TIPA[0])))
        if operation == 1:
            print('\tOperation: Requesting')
        elif operation == 2:
            print('\tOperation: Replying')
    if prototype == 34525:
        '''
        IPv6 packets
        '''
        payload_length, next_header, hop_limit = struct.unpack('! H B B', data[4:8])
        ipv6_src, ipv6_dest = struct.unpack('! 16s 16s', data[8:40])
        ipv6_src = ipv6_addr(ipv6_src.hex())
        ipv6_dest = ipv6_addr(ipv6_dest.hex())
        header_data = data[0]
        v6_version = header_data >> 4
        traffic_class = data[1] >> 4
        flow_label = data[2] >> 4
        print('\tIPv6 packet')
        print('\tversion:{}'.format(v6_version))
        print('\tpayload length:{}\n\tnext header:{}\n\thop limit:{}'.format(payload_length, next_header, hop_limit))
        print('\tsrc :{}\n\tdest:{}'.format(ipv6_src, ipv6_dest))
    print('\n')
