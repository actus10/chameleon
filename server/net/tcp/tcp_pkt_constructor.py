# -*- coding: utf-8 -*-
# Copyright 2017, A10 Networks
# Author: Mike Thompson: @mike @t @a10@networks!com


import socket
from struct import *


# checksum functions needed for calculation checksum

def checksum(msg):
    s = 0
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        try:
            w = ord(msg[i]) + (ord(msg[i + 1]) << 8)
        except:
            w = ord(msg[i])

        s = s + w

    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)

    # complement and mask to 4 byte short
    s = ~s & 0xffff

    return s


class tcp_packet():
    def __init__(self, tcp_seq, tcp_ack_seq, tcp_sport, tcp_dport, src_addr, dst_addr, userdata):
        # tcp header fields
        self.user_data = userdata
        self.tcp_source = tcp_sport  # source port
        self.tcp_dest = tcp_dport  # destination port
        self.tcp_seq = tcp_seq
        self.tcp_ack_seq = tcp_ack_seq
        self.tcp_doff = 5  # 4 bit field, size of tcp header, 5 * 4 = 20 bytes
        # tcp flags
        self.tcp_fin = 0
        self.tcp_syn = 0
        self.tcp_rst = 0
        self.tcp_psh = 0
        self.tcp_ack = 0
        self.tcp_urg = 0
        self.tcp_window = socket.htons(65534)  # maximum allowed window size
        self.tcp_check = 0
        self.tcp_urg_ptr = 0
        # create a raw socket
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except socket.error, msg:
            print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            sys.exit()

        self.s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # now start constructing the packet
        self.packet = '';

        self.source_ip = src_addr
        self.dest_ip = dst_addr  # or socket.gethostbyname('www.google.com')

        # ip header fields
        self.ip_ihl = 5
        self.ip_ver = 4
        # Set tos bit to map to IPtables match class to permit resets.
        self.ip_tos = 160
        self.ip_tot_len = 0  # kernel will fill the correct total length
        self.ip_id = 0  # Id of this packet
        self.ip_frag_off = 0
        self.ip_ttl = 128  # choice([255, 128, 64])
        self.ip_proto = socket.IPPROTO_TCP
        self.ip_check = 0  # kernel will fill the correct checksum
        self.ip_saddr = socket.inet_aton(self.source_ip)  # Spoof the source ip address if you want to
        self.ip_daddr = socket.inet_aton(self.dest_ip)

        self.ip_ihl_ver = (self.ip_ver << 4) + self.ip_ihl


        # tcp header fields

    def pack(self):
        """Need to add TCP Options RFC 1392 and other cools stuff like SACK and stuff.
        However, time is never on my side. Maybe a community project...
        This all needs to be ported to C once the DPDK Driver is completed.
        """

        self.ip_header = pack('!BBHHHBBH4s4s', self.ip_ihl_ver, self.ip_tos, self.ip_tot_len, self.ip_id,
                              self.ip_frag_off,
                              self.ip_ttl, self.ip_proto, self.ip_check, self.ip_saddr, self.ip_daddr)

        self.tcp_offset_res = (self.tcp_doff << 4) + 0

        self.tcp_flags = self.tcp_fin + (self.tcp_syn << 1) \
                         + (self.tcp_rst << 2) + (self.tcp_psh << 3) + (self.tcp_ack << 4) + (self.tcp_urg << 5)
        # print (self.tcp_source, self.tcp_dest, self.tcp_seq, self.tcp_ack_seq,
        #        self.tcp_offset_res, self.tcp_flags, self.tcp_window, self.tcp_check, self.tcp_urg_ptr)
        # the ! in the pack format string means network order
        self.tcp_header = pack('!HHLLBBHHH', self.tcp_source, self.tcp_dest, self.tcp_seq, self.tcp_ack_seq, \
                               self.tcp_offset_res, self.tcp_flags, self.tcp_window, self.tcp_check, self.tcp_urg_ptr)

        # self.user_data = ''

        # pseudo header fields
        self.source_address = socket.inet_aton(self.source_ip)
        self.dest_address = socket.inet_aton(self.dest_ip)
        self.placeholder = 0
        self.protocol = socket.IPPROTO_TCP
        self.tcp_length = len(self.tcp_header) + len(self.user_data)

        self.psh = pack('!4s4sBBH', self.source_address, self.dest_address,
                        self.placeholder, self.protocol, self.tcp_length)

        self.psh = self.psh + self.tcp_header + str(self.user_data)

        self.tcp_check = checksum(self.psh)

        self.tcp_header = pack('!HHLLBBH',
                               self.tcp_source, self.tcp_dest, self.tcp_seq, self.tcp_ack_seq, self.tcp_offset_res, \
                               self.tcp_flags, self.tcp_window) + pack('H', self.tcp_check) + pack('!H',
                                                                                                   self.tcp_urg_ptr)


        self.packet = self.ip_header + self.tcp_header + self.user_data


    def sendto(self):
        self.s.sendto(self.packet, (self.dest_ip, 0))



if __name__ == "__main__":
    x = tcp_packet()
