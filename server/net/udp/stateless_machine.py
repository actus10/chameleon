# -*- coding: utf-8 -*-
# Copyright 2017, A10 Networks
# Author: Mike Thompson: @mike @t @a10@networks!com

'''
This whole class is about loading the classifier and the applications.
'''

import binascii
import socket
import traceback

import netaddr

import udp_pkt_constructor as pc


class UDPListener():
    def __init__(self, pkt, config, apps):
        # threading.Thread.__init__(self)
        self.__APPS__ = apps
        self.config = config
        self.classifier_enabled = self.config.classifier
        self.classifier = self.config.load_classifier
        self.pkt = pkt
        self.dst = pkt.src
        self.src = pkt.dst
        self.udp = pkt.data
        self.dport = self.udp.sport
        self.sport = self.udp.dport
        self.pkt = pkt
        self.data = self.udp.data
        self.selected_app = None
        self.rx_app_data()

    def run(self):
        pass

    def int2bytes(self, i):
        hex_string = '%x' % i
        n = len(hex_string)
        return binascii.unhexlify(hex_string.zfill(n + (n & 1)))

    def inet_to_str(self, inet):
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

    def event_handler(self):
        pass

    def SEND_DATA(self, data):
        pc.udp_packet(self.src, self.dst, self.sport, self.dport, data)

    def rx_app_data(self):
        if self.check_port(self.config.classifier_ignore_port, [self.sport, self.dport]) == True:
            return
        if self.check_ip_block(self.config.classifier_ignore_ip,
                               [self.inet_to_str(self.src), self.inet_to_str(self.dst)]) == True:
            return
        print "IN UDP_SERVER and want to block", self.config.classifier_ignore_port
        classifier_matched_apps = []
        port_matched_app = []
        select_by = None
        app_label = None
        try:
            if self.selected_app is None:
                if self.classifier_enabled:
                    if self.check_port(self.config.classifier_ignore_port, [self.sport, self.dport]) == True:
                        return
                    if self.check_ip_block(self.config.classifier_ignore_ip,
                                           [self.inet_to_str(self.src), self.inet_to_str(self.dst)]) == True:
                        return
                    x = self.classifier.predict(self.data[:self.config.classifier_limit_prediction_data])
                    try:
                        x = x[0][0]
                    except:
                        default = False
                        for k, v in self.__APPS__.items():
                            if v.protocol.lower() == 'udp' or (v.protocol.lower() == 'any' and v.default_app == True):
                                for l in v.labels:
                                    if x == l:
                                        default = True
                                        classifier_matched_apps.append(v)
                        if default is False:
                            self.classifier_enabled = False
                            self.selected_app = None
                            self.rx_app_data()
                    app_label = x
                    for k, v in self.__APPS__.items():
                        for l in v.labels:
                            if x == l:
                                classifier_matched_apps.append(v)
                    for k, v in self.__APPS__.items():
                        if v.protocol.lower() == 'udp' or (v.protocol.lower() == 'any' and v.default_app == True):
                            for l in v.labels:
                                if x == l:
                                    app_label = x
                                    classifier_matched_apps.append(v)
                else:
                    if self.check_port(self.config.classifier_ignore_port, [self.sport, self.dport]) == True:
                        return
                    if self.check_ip_block(self.config.classifier_ignore_ip,
                                           [self.inet_to_str(self.src), self.inet_to_str(self.dst)]) == True:
                        return
                    for k, v in self.__APPS__.items():
                        if v.protocol.lower() == 'udp' or (v.protocol.lower() == 'any' and v.default_app == True):
                            # match the first one since classifer is disabled.
                            if self.sport == v.port:
                                port_matched_app.append(v)
                if len(classifier_matched_apps) == 1:
                    select_by = 'classifier'
                    self.selected_app = classifier_matched_apps[0]
                elif len(classifier_matched_apps) > 1:
                    self.select_best_app(classifier_matched_apps)
                    select_by = 'classifier'
                elif len(port_matched_app) == 1:
                    self.selected_app = port_matched_app[0]
                    select_by = 'port'
                else:
                    select_by = 'port'
                    self.select_best_app(port_matched_app)
        except:
            traceback.print_exc()
        # lets see if we got a app selected now
        app_response = None
        flags = None
        if self.selected_app is not None:
            if self.check_port(self.config.classifier_ignore_port, [self.sport, self.dport]):
                return
            if self.check_ip_block(self.config.classifier_ignore_ip,
                                   [self.inet_to_str(self.src), self.inet_to_str(self.dst)]):
                return
            app_response = self.selected_app.recv_data(self.data, self.pkt, select_by, app_label, callback=self)
            if app_response is not None:
                try:
                    app_response, flags = app_response
                except:
                    app_response = app_response

                self.tx_len_checker(app_response)
        else:
            if self.config.default_app is None:
                # TODO: We can't handle this so we will just return
                # Will log in future
                pass

    def chunksdata(self, s):
        length = self.config.MSS
        return (s[0 + i:length + i] for i in range(0, len(s), length))

    def tx_len_checker(self, data):
        if data is not None:
            to_send = len(data)
            if to_send > self.config.MSS:
                # split int payloads the fit under bounds of mss.
                buffer = self.chunksdata(data)
                while to_send != 0:
                    d = buffer.next()
                    to_send = to_send - len(d)
                    self.SEND_DATA(d)

    def select_best_app(self, matched_apps):
        best_app_priority = 255
        best_app = None
        for i in matched_apps:
            if isinstance(i.priority, int):
                print 'b'
                if i.priority <= best_app_priority:
                    print 'c'
                    if isinstance(i.match_ip, bool):
                        print 'd'
                        if i.match_ip:
                            print 'e'
                            if isinstance(i.match_list, list):
                                print 'f'
                                for j in i.match_list:
                                    print 'g'
                                    if "/" in j:
                                        print 'h'
                                        if netaddr.IPAddress(self.inet_to_str(self.src)) == netaddr.IPNetwork(j):
                                            print 'i'
                                            if isinstance(i.pri_match_ip, int):
                                                print 'j'
                                                if best_app_priority > i.pri_match_ip:
                                                    print 'k'
                                                    best_app_priority = i.pri_match_ip
                                                    best_app_priority = i
                                        else:
                                            if i.priority < best_app_priority:
                                                print 'q2'
                                                best_app_priority = i.priority
                                                best_app = i
                                    else:
                                        print 'l'
                                        if netaddr.IPAddress(self.inet_to_str(self.src)) == netaddr.IPAddress(j):
                                            print 'm'
                                            if isinstance(i.pri_match_ip, int):
                                                print 'n'
                                                if best_app_priority > i.pri_match_ip:
                                                    print 'o'
                                                    best_app_priority = i.pri_match_ip
                                                    best_app = i
                                        else:
                                            if i.priority < best_app_priority:
                                                print 'q2'
                                                best_app_priority = i.priority
                                                best_app = i
                        else:
                            print 'p'
                            if i.priority < best_app_priority:
                                print 'q'
                                best_app_priority = i.priority
                                best_app = i
                else:
                    print 'p'
                    if i.priority < best_app_priority:
                        print 'q'
                        best_app_priority = i.priority
                        best_app = i
        print best_app
        self.selected_app = best_app
