# -*- coding: utf-8 -*-
# Copyright 2017, A10 Networks
# Author: Mike Thompson: @mike @t @a10@networks!com


import os
import socket
import struct

import dpkt


class bpf_socket(object):
    """
    The whole point of this class is to utilize SO_ATTACH_FILTER to spread the load accross CPU's.
    Since this a RAW socket for now until DPDK driver can be be created performance will not be the best.
    However, you can modify the cserver.py and pass a normal socket is required.
    NetFilterQueues were tested but the performance was much worst... The socket performance issues will be addressed in
    future releases.
    """
    def __init__(self, cpu_count, if_n):
        self.cpu_count = cpu_count
        self.cpu_bpf_filters = []
        self.if_n = if_n
        self.create()

    def create(self):
        """
        Really need to look at the logic here. Optimization can occur here. Just to many other things to finish up.
        """
        MAX_PORT = 65534
        range_step = (MAX_PORT / self.cpu_count)
        range_list = []
        cpu_port_list = []
        if self.cpu_count == 1:
            range_list = [0, 65534]
        elif self.cpu_count == 2:
            range_list = [0, 32767, 65534]
        else:
            for i in range(0, MAX_PORT, range_step):
                range_list.append(i)
        if range_list[len(range_list) - 1] != 65534:
            range_list[(len(range_list) - 1)] = 65534
        last = 0
        for i in range_list:
            if i == 0:
                pass
            elif last == 0:
                cpu_port_list.append((last, i))
            elif i == last:
                cpu_port_list.append((last + 1, 65534))
            else:
                cpu_port_list.append((last + 1, i))
            last = i

        for i in cpu_port_list:
            out = os.popen(
                "tcpdump -i" + str(self.if_n) + " -ddd -s 1500 tcp src portrange " + str(i[0]) + "-" + str(i[1]))
            self.cpu_bpf_filters.append([out])


    def get_socket(self, cpu_n):
        SO_ATTACH_FILTER = 26
        filter = self.cpu_bpf_filters[cpu_n][0].readlines()
        bpf = ""
        nb = int(filter[0])
        for l in filter[1:]:
            bpf += struct.pack("HBBI", *map(long, l.split()))
        bpfh = struct.pack("HL", nb, id(bpf) + 36) #Need to adjust for different architectures. x86_64 support only
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(dpkt.ethernet.ETH_TYPE_IP))
        sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, bpfh)
        return sock


if __name__ == "__main__":
    x = bpf_socket(2, 'ens3')
    print type(x.get_socket(0))
