# -*- coding: utf-8 -*-
# Copyright 2017, A10 Networks
# Author: Mike Thompson: @mike @t @a10@networks!com
import gc
import multiprocessing
import socket
import traceback
import gc
import netaddr

import state_machine
from flow_table import TCPFlowTable
from utilities.config_loader import CheckConfig
from utilities.loader import loader

class TCPServer(multiprocessing.Process):
    """Need to document this classes behavior need to get time on this. """
    def __init__(self, q):
        self._CFT_ = TCPFlowTable()
        self.config = CheckConfig()._merge()
        load_app = loader()
        load_app.load_apps()
        self.__APPS__ = load_app.app_map
        self.q = q
        multiprocessing.Process.__init__(self)

    def run(self):
        while True:
            pkt = self.q.get()
            if pkt is None:
                pass
            else:
                self.TCPflow(pkt)

    def TCPflow(self, ip):
        tcp = ip.data
        # _CFT_.show_flows()
        try:
            if not self._CFT_.check_exist(self.inet_to_str(ip.src), str(tcp.sport), self.inet_to_str(ip.dst),
                                          str(tcp.dport)):
                self._CFT_.create_entry(self.inet_to_str(ip.src),str(tcp.sport), self.inet_to_str(ip.dst),
                                        str(tcp.dport))
                flowObj = self._CFT_.get_flow_object(self.inet_to_str(ip.src),str(tcp.sport), self.inet_to_str(ip.dst),
                                                     str(tcp.dport))
                flowObj.state_machine = state_machine.TCPStateMachine(ip, self.config, self.__APPS__)
                flowObj.state_machine.start()
                self._CFT_.update_flow_obj(flowObj)
            else:
                flowObj = self._CFT_.get_flow_object( self.inet_to_str(ip.src), str(tcp.sport),self.inet_to_str(ip.dst),
                                                     str(tcp.dport))
                if flowObj.state_machine.state is not None:
                     flowObj.state_machine.event_handler(ip)
                else:
                    self._CFT_.delete_flow_object(flowObj)
                    self.TCPflow(ip)
        except:
            traceback.print_exc()

    #TODO: Not following DRY because of lazyness tonight. Need to deal with this.
    def add_colons_to_mac(self, mac_addr):
        """This function accepts a 12 hex digit string and converts it to a colon
    separated string"""
        s = list()
        for i in range(12 / 2):  # mac_addr should always be 12 chars, we work in groups of 2 chars
            s.append(mac_addr[i * 2:i * 2 + 2])
        r = ":".join(s)
        return r

    def inet_to_str(self, inet):
        try:
            return socket.inet_ntop(socket.AF_INET, inet)
        except ValueError:
            return socket.inet_ntop(socket.AF_INET6, inet)

    def check_ip_block(self, l, ip):
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

    def check_ip_proto(self, proto):
        # Make sure the ip proto is permitted.
        for i in self.config.ip_proto_permit:
            if i == proto:
                return False
        return True

    def check_port(self, l, port):
        for i in l:
            for j in port:
                if isinstance(i, int):
                    if j == i:
                        return True
                if isinstance(i, list):
                    if j in i:
                        return True
        return False
