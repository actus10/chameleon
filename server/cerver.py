# -*- coding: utf-8 -*-
# Copyright 2017, A10 Networks
# Author: Mike Thompson: @mike @t @a10@networks!com
"""
This is the primary entry point for chameleon. There are many optimizations that need to occur. However, optimization
is only needed once we get all of the other needs taken care of.
"""

import config
import dpkt
import fcntl
import multiprocessing
import netaddr
import socket
import struct
import traceback

from bpf_socket import bpf_socket
from multiprocessing import Queue
from net.tcp.TCPServer import TCPServer
from utilities import  banner
from utilities import logos

import time

# Count the CPU's for obvious reasons.
_CPU_COUNT_ = multiprocessing.cpu_count()

#TODO: Needs to be moved into a utility file.
def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', 'eth0'[:15])
        )[20:24])
    except:
        try:
            return socket.inet_ntoa(fcntl.ioctl(
                s.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack('256s', 'ens3'[:15])
            )[20:24])
        except:
            pass

#TODO: Needs to be moved into a utility file.
def add_colons_to_mac(self, mac_addr):
    """This function accepts a 12 hex digit string and converts it to a colon
       separated string.
    """
    s = list()
    for i in range(12 / 2):  # mac_addr should always be 12 chars, we work in groups of 2 chars
        s.append(mac_addr[i * 2:i * 2 + 2])
    r = ":".join(s)
    return r
#TODO: Needs to be moved into a utility file.
def inet_to_str(inet):
    """Convert inet object to a string
        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)
#TODO: Needs to be moved into a utility file.
def check_ip_block(l, ip):
    for i in l:
        for j in ip:
            try:
                if '/' in i:
                    if j in netaddr.IPNetwork(i):
                        return True
                elif isinstance(i, str):
                    if j == netaddr.IPAddress(i):
                        return True
            except:
                traceback.print_exc()
#TODO: Needs to be moved into a utility file.
def check_ip_proto(proto):
    #Make sure the ip proto is permitted.
    for i in config.ip_proto_permit:
        if i == proto:
            return False
    return True
#TODO: Needs to be moved into a utility file.
def check_port(l, port):
    for i in l:
        for j in port:
            if isinstance(i, int):
                if j == i:
                    return True
            if isinstance(i, list):
                if j in i:
                    return True
    return False


class Dispatcher(multiprocessing.Process):
    """
    For each Processor there will be a Dispatcher. Each Dispatcher picks up the raw_socket events and then performs a
    hash to ensure that the flow get to the correct CPU.
    """
    def __init__(self, qlist, sock):
        multiprocessing.Process.__init__(self)
        self.q_list = qlist
        self.sock = sock

    def run(self):
        while True:
            try:
                #If we receive and error then just move on. Ya... Crummy unhandled except... I'm ok with this for today.
                frame = self.sock.recv(1500)
            except:
                continue
            #If we do get a event but the frame object is null then again... Move on...
            if frame is None:
                continue
            else:
                eth = dpkt.ethernet.Ethernet(frame)    #Unpacking the ethernet frame
                if not isinstance(eth.data, dpkt.ip.IP): # Lets check to see if there is IP data in the frame
                    pass
                else:
                    ip = eth.data
                    if ip.p == 6: #If ip protocol matches TCP
                        tcp = ip.data #Data is unpacked as part of the DPKT modules
                        # this is for a single interface mode
                        if config.multi_nic is False and tcp.dport == 22 or tcp.sport == 22:
                            pass
                        else:
                            #Hash is simple. Not Optimal but that is ok right now.
                            MOD = (netaddr.IPAddress(inet_to_str(eth.data.src)).value +
                                   eth.data.data.dport + eth.data.data.sport) % (_CPU_COUNT_)
                            q = self.q_list[MOD]
                            q.put(ip)

def main():
    """
    we are only going to have one worker dispatching the frames to the application layer. Raw sockets does not give
    lower level functionality to split file resources per thread. We do not want to start the dispatcher until
    the other threads are started. We will have 1 UDP server which will green thread from the maindispatcher loop
    and the rest will be TCP...
    dispatcher = Dispatcher(q_list)
    """
    print logos.image1
    time.sleep(2)
    print banner.banner
    time.sleep(2)
    print logos.image2
    time.sleep(2)
    try:
        bpf_s = bpf_socket(_CPU_COUNT_, config.if_n)

        jobs = []
        q_list = []

        # Create the Queues for each machine thread.
        for cpu in range(0, _CPU_COUNT_):
            q_list.append(Queue())

        x = 0
        for q in q_list:
            o = TCPServer(q)
            jobs.append(o)
            o.daemon = True
            o.start()
            dispatcher = Dispatcher(q_list, bpf_s.get_socket(x))
            jobs.append(dispatcher)
            dispatcher.daemon = True
            dispatcher.start()
            x = x + 1

        for i in jobs:
            print i.name, i.is_alive()
        for j in jobs:
            j.join()

    except:
        traceback.print_exc()



if __name__ == "__main__":
    main()