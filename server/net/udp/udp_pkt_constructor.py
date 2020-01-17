# -*- coding: utf-8 -*-
# Copyright 2017, A10 Networks
# Author: Mike Thompson: @mike @t @a10@networks!com

import socket
from struct import *


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


class udp_packet(object):
    def __init__(self, sport, dport, src, dst, data=''):
        self.dest_ip = dst
        self.source_ip = src

        # udp header
        self.sport = sport
        self.dport = dport
        self.data = data
        self.sum = 255
        self.length = len(self.data)

        self.packet = '';

        # ip header fields
        self.ip_ihl = 5
        self.ip_ver = 4
        self.ip_tos = 0
        self.ip_tot_len = 0  # kernel will fill the correct total length
        self.ip_id = 0  # Id of this packet
        self.ip_frag_off = 0
        self.ip_ttl = 255
        self.ip_proto = socket.IPPROTO_UDP
        self.ip_check = 0  # kernel will fill the correct checksum
        self.ip_saddr = socket.inet_aton(self.source_ip)  # Spoof the source ip address if you want to
        self.ip_daddr = socket.inet_aton(self.dest_ip)

    def send(self):
        self.ip_ihl_ver = (self.ip_ver << 4) + self.ip_ihl

        self.ip_header = pack('!BBHHHBBH4s4s', self.ip_ihl_ver, self.ip_tos, self.ip_tot_len, self.ip_id,
                              self.ip_frag_off,
                              self.ip_ttl, self.ip_proto, self.ip_check, self.ip_saddr, self.ip_daddr)

        self.udp_header = pack('!4H', self.sport, self.dport, 8 + len(self.data), self.sum)
        psh = self.ip_header + self.udp_header + self.data
        self.udp_check = checksum(psh)
        self.udp_header = pack('!4H', self.sport, self.dport, 8 + len(self.data),
                               self.udp_check)

        packet = self.ip_header + self.udp_header + self.data
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except socket.error, msg:
            print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            sys.exit()
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.sendto(packet, (self.dest_ip, 0))


if __name__ == "__main__":
    payload = ('M-SEARCH * HTTP/1.1\r\n' +
               'ST: TESTESTEST\r\n' +
               'MX: 3\r\n' +
               'MAN: "ssdp:discover"\r\n' +
               'HOST: 239.255.255.250:1900\r\n\r\n')

    x = udp_packet(65000, 1900, '172.31.7.136', '34.213.101.215', payload)
    x.send()
