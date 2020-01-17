# -*- coding: utf-8 -*-
# Copyright 2017, A10 Networks
# Author: Mike Thompson: @mike @t @a10@networks!com
import binascii
import random
import socket
import threading
import time
import traceback
from threading import Timer
from time import clock
import weakref

import netaddr

import tcp_pkt_constructor as pc
from tcp_map import _flag_map_hex as fm



class BadPacketError(Exception):
    pass



class TCPStateMachine(threading.Thread):
    """
    On Initialization we will go through the handshake.
    This is also like the TCB and is stored in a dict for future processing.
    This stack is functional however, it is far from modern. This is a iterative part of the platform. it is good enough
    for the primary purpose.
    """

    def __init__(self, pkt, config, __APPS__):
        threading.Thread.__init__(self)
        '''
         Lets init the class as this will setup some basic vars
         This is a little sub optimal but it will help with tracking
        '''
        self.state = 'LISTEN'
        self.config = config
        self.classifier_enabled = self.config.classifier
        self.classifier = self.config.load_classifier
        self.__APPS__ = __APPS__
        self.sport = None
        self.pkt = None
        self.rtt = 0
        self.acum_rtt = 0
        self.srtt = 0
        self.rx_buffer_size = 0
        self.rtt_bucket = []
        self.selected_app = None
        self.seq = self.generateISN()
        self.isn = self.seq
        self.seq_ack = 0
        self.src = None
        self.dst = None
        self.pkt_count = 0
        self.pkt_buffer = []
        self.data_buffer = []
        self.win = 65535
        self.size_last_data = 0
        # Everytime we get a packet timestamp update
        self.TS = time.time()
        self.c_time = None
        self.r_window = 0
        self.sa = None
        self.msl_time = None
        self.t_locker = False
        self.time_lock = time.time()
        self.event_handler(pkt)


    def int2bytes(self, i):
        hex_string = '%x' % i
        n = len(hex_string)
        return binascii.unhexlify(hex_string.zfill(n + (n & 1)))

    def inet_to_str(self, inet):
        try:
            return socket.inet_ntop(socket.AF_INET, inet)
        except ValueError:
            return socket.inet_ntop(socket.AF_INET6, inet)


    def event_handler(self, pkt):
        try:
            # print"STATE:", self.state
            t_pkt = pkt.data
            self.pkt = pkt
            self.src = pkt.dst
            self.dst = pkt.src
            self.sport = t_pkt.sport
            self.dport = t_pkt.dport
            self.r_window = t_pkt.win
            # start TCPSM logic
            self.pkt_count += 1
            payload = t_pkt.data
            if fm[t_pkt.flags] == 'SYN' or fm[t_pkt.flags] == 'SYN-ECE-CWR':
                if self.state == 'LISTEN':
                    self.seq_ack = t_pkt.seq + 1
                    self.SYN_RCVD()
                elif self.state == 'SYN_SENT':
                    # retransmit the SYN-ACK but not to exceed 3 times
                    # Linux is 15 but minimium is 3
                    if self.pkt_count < 3:
                        self.SYN_RCVD()
                    else:
                        self.SEND_RST()
                        # give up and delete the entry.
                        self.state = 'CLOSED'
                        self.state = None
                else:
                    # give up and delete the entry.
                    self.SEND_RST()
                    self.state = 'CLOSED'
                    self.state = None
            elif fm[t_pkt.flags] == 'SYN-ACK':
                # server should never see this.
                # we will set the state to closed.
                self.state = 'CLOSED'
                self.state = None
            elif fm[t_pkt.flags] == 'ACK':
                if self.state == 'SYN_SENT':
                    # finishing up three way.
                    # if paket count is over three then we will close.
                    if t_pkt.ack == (self.seq + 1):
                        self.rtt = time.time() - self.TS
                        self.TS = time.time()
                        self.acum_rtt += self.rtt
                        self.seq_ack = t_pkt.seq
                        self.state = 'ESTABLISHED'

                elif self.state == 'ESTABLISHED':
                    self.seq_ack = t_pkt.seq
                elif self.state == 'FIN1':
                    self.seq = self.seq
                    self.seq_ack = self.seq_ack + 1
                    self.SEND_ACK()
                    self.state = 'LAST_ACK'
                elif self.state == 'LAST_ACK':
                    self.state = 'CLOSED'
                    self.state = None
            elif fm[t_pkt.flags] == 'FIN-ACK' or fm[t_pkt.flags] == 'FIN-PSH-ACK':
                if self.state == 'ESTABLISHED':
                    # send ack and and transition to closed-wait.
                    self.seq_ack = t_pkt.seq + len(payload)
                    self.SEND_ACK()
                    self.state = 'CLOSE_WAIT'
                    self.seq = self.seq
                    self.seq_ack = self.seq_ack + 1
                    self.SEND_FIN_ACK()
                    self.state = 'LAST_ACK'
                elif self.state == 'FIN2':
                    self.seq = self.seq
                    self.seq_ack = self.seq_ack + 1
                    self.SEND_ACK()

                elif self.state == 'CLOSE_WAIT':
                    # TODO: retransmit the ACK and send FIN
                    self.seq = self.seq
                    self.seq_ack = self.seq_ack + 1
                    self.SEND_FIN_ACK()

            elif fm[t_pkt.flags] == 'RST':
                # no matter what close
                self.state = 'CLOSE'
                self.state = None
            elif fm[t_pkt.flags] == 'RST-ACK':
                # Most likely a network appliance messing up.. Ignore.
                self.state = 'CLOSED'
                self.state = None
            elif fm[t_pkt.flags] == 'PSH-ACK':
                if self.state == 'ESTABLISHED':
                    self.rtt = time.time() - self.TS
                    self.TS = time.time()
                    self.acum_rtt += self.rtt
                    try:
                        self.srtt = self.acum_rtt / self.pkt_count
                    except:
                        self.srtt = .5
                    #print self.pkt_count, self.srtt, self.srtt*2, self.srtt*3, self.acum_rtt, self.rtt
                    seq_ack = t_pkt.seq + len(payload)
                    if seq_ack == self.seq_ack:
                        self.SEND_ACK()
                    else:
                        self.seq_ack = seq_ack
                        self.SEND_ACK()
                        self.pkt_buffer.append(pkt)
                        self.buffer(t_pkt.data)
                        self.rx_app_data(False)
                else:
                    self.state = 'CLOSED'
                    self.state = None
        except:
            traceback.print_exc()

    def generateISN(self):
            return random.randrange(0, int(2 ** 32))

    #TODO: There is a big resource exhaustion vulnerability... We are not killing based on MSL. We need to actually do
    #TODO: Actually setup timers so they are more intelligent.

    def set_ack_timer(self, depth=0, called_by_timer=False):
        try:
            #print self.state, called_by_timer, depth, self.time_lock, self.t_locker, self.sa
            if called_by_timer is True:
                #print "AAAA"
                if self.t_locker:
                    #print "BBBB"
                    depth += 1
                    if time.time() - self.time_lock > self.srtt * 2 and called_by_timer and self.state == "ESTABLISHED":
                        #print "1A"
                        self.time_lock = time.time()
                        #print "1B"
                        self.t_locker = True
                        #print "1C"
                        Timer(self.srtt * 2, self.SEND_ACK, [], {"called_by_timer": called_by_timer, "depth": depth}).start()
                        #print "1D"
            else:
                if self.t_locker is False:
                    self.time_lock = time.time()
                    self.t_locker = True
                    Timer(self.srtt * 2 , self.SEND_ACK, [], {"called_by_timer": True, "depth": depth}).start()
        except:
            traceback.print_exc()


    def SEND_RST(self):
        x = pc.tcp_packet(self.seq, self.seq_ack, self.dport, self.sport, self.inet_to_str(self.src),
                          self.inet_to_str(self.dst), "")
        x.ip_tos = 160
        x.tcp_rst = 1
        x.tcp_ack = 0
        x.pack()
        x.sendto()
        self.state = 'CLOSED'
        self.state = None

    def SEND_RST_ACK(self):
        x = pc.tcp_packet(self.seq, self.seq_ack, self.dport, self.sport, self.inet_to_str(self.src),
                          self.inet_to_str(self.dst), "")
        x.ip_tos = 160
        x.tcp_rst = 1
        x.tcp_ack = 1
        x.pack()
        x.sendto()
        self.state = 'CLOSED'
        self.state = None

    def SEND_FIN_ACK(self):
        x = pc.tcp_packet(self.seq, self.seq_ack, self.dport, self.sport, self.inet_to_str(self.src),
                          self.inet_to_str(self.dst), "")
        x.tcp_ack = 1
        x.tcp_fin = 1
        x.pack()
        x.sendto()
        self.state = 'FIN1'

    def SEND_FIN_PSH_ACK(self, data):
        x = pc.tcp_packet(self.seq, self.seq_ack, self.dport, self.sport, self.inet_to_str(self.src),
                          self.inet_to_str(self.dst), data)
        x.tcp_psh = 1
        x.tcp_ack = 1
        x.tcp_fin = 1
        x.pack()
        x.sendto()
        self.state = 'FIN1'

    def SYN_RCVD(self):
        self.state = 'SYN_RCVD'
        # we need to generate a SYN-ACK
        self.TS = time.time()
        self.SEND_SYN_ACK()


    def SEND_ACK(self, called_by_timer=False, depth=0):
        if self.seq == self.isn:
            self.seq = self.isn + 1
        x = pc.tcp_packet(self.seq, self.seq_ack, self.dport, self.sport, self.inet_to_str(self.src),
                          self.inet_to_str(self.dst), "")
        x.tcp_ack = 1
        x.pack()
        x.sendto()
        #self.set_ack_timer(called_by_timer=called_by_timer, depth=depth)


    def SEND_SYN_ACK(self):
        x = pc.tcp_packet(self.seq, self.seq_ack, self.dport, self.sport, self.inet_to_str(self.src),
                          self.inet_to_str(self.dst), "")
        x.tcp_ack = 1
        x.tcp_syn = 1
        x.pack()
        x.sendto()
        self.state = 'SYN_SENT'


    def SEND_DATA(self, data):
        # self.seq = self.seq + 1
        x = pc.tcp_packet(self.seq, self.seq_ack, self.dport, self.sport, self.inet_to_str(self.src),
                          self.inet_to_str(self.dst), data)
        x.tcp_ack = 1
        x.tcp_psh = 1
        x.pack()
        x.sendto()
        self.seq = self.seq + len(data)

        # x.s.close()

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


    def buffer(self, data):
        self.rx_buffer_size += len(data)
        print "RX_BUFFER =", self.rx_buffer_size
        self.data_buffer.append(data)

    def clear_buffer(self):
        self.pkt_buffer = []

    def rx_app_data(self, TE, depth=0):
        if depth == 0 or TE:
            depth += 1
            if self.rx_buffer_size < 4096 and depth < 2:
                #Need to add in telnet support for one packet per char then add back
                # in terminator strings or timer setting.
                Timer(self.srtt*2, self.rx_app_data, [True], {"depth": depth}).start() #Ya really need fix this...
            else:
                data = ''
                #print self.data_buffer
                # if self.rx_buffer_size == 0:
                #     if depth > 15:
                #         self.SEND_RST()
                #     else:
                #         Timer(self.srtt, self.rx_app_data, [True], {"depth": depth}).start()
                # else:
                while self.rx_buffer_size !=0:
                    rd = self.data_buffer.pop(0)
                    self.rx_buffer_size = self.rx_buffer_size - len(rd)
                    data = data + rd


                    # if len(data) == 0:
                    #     return

                #print  self.pkt.data.data
                self.pkt.data.data = data
                #print "DATA START:\n" , data
                #print "DATA STOP..........."
                classifier_matched_apps = []
                port_matched_app = []
                select_by = None
                app_label = None
                try:
                    if self.selected_app is None:
                        if self.classifier_enabled:
                            #t1 = time.time()
                            if self.check_port(self.config.classifier_ignore_port, [self.sport, self.dport]):
                                return
                            if self.check_ip_block(self.config.classifier_ignore_ip,
                                                   [self.inet_to_str(self.src), self.inet_to_str(self.dst)]):
                                return
                            #print "TIME1:", time.time()- t1
                            t2 = time.time()
                            y = self.classifier.predict(data)
                            #print "TIME2:", time.time() - t2
                            t3 = time.time()
                            app_label = y
                            if app_label is None or (isinstance(app_label[0], tuple) and len(app_label[0]) == 0):
                                app_label = None

                            print "Prediction is:", app_label, ' for payload:', data
                            #add check to see if any apps are loade

                            if len(self.__APPS__) == 0:
                                self.SEND_RST()
                                return
                            if app_label is not None and len(app_label) != 0:
                                #print "1"*100
                                for k, v in self.__APPS__.items():
                                    if v.protocol.lower() == 'tcp' or (v.protocol.lower() == 'any' and v.default_app == True):
                                        if v.default_app == True:
                                            classifier_matched_apps.append(v)
                                        for l in v.labels:
                                            if isinstance(l , tuple):
                                                for i in app_label[0]:
                                                    if l == i:
                                                        #print "APP_MATCH_1:", l, app_label
                                                        classifier_matched_apps.append(v)

                                            elif l in app_label[0]:
                                                #print "APP_MATCH_2:", l, app_label
                                               classifier_matched_apps.append(v)
                            elif  app_label == None:
                                for k, v in self.__APPS__.items():
                                    if v.protocol.lower() == 'any' and v.default_app == True:
                                        default = True
                                        classifier_matched_apps.append(v)

                        if len(classifier_matched_apps) == 1:
                            select_by = 'classifier'
                            selected_app = type('selected_app', (classifier_matched_apps[0].__class__,), dict(classifier_matched_apps[0].__dict__))

                            self.selected_app = selected_app()

                        elif len(classifier_matched_apps) > 1:
                            self.select_best_app(classifier_matched_apps)
                            select_by = 'classifier'
                        elif len(port_matched_app) == 1:
                            selected_app = type('selected_app', (port_matched_app[0].__class__,),
                                               dict(port_matched_app[0].__dict__))
                            self.selected_app = selected_app()
                            select_by = 'port'
                        else:
                            select_by = 'port'
                            self.select_best_app(port_matched_app)

                        #print "TIME3:", time.time() - t3


                except:
                    traceback.print_exc()
                #t4 = time.time()
                # lets see if we got a app selected now
                app_response = None
                flags = None
                # if self.check_port(self.config.classifier_ignore_port, [self.sport, self.dport]):
                #     return
                # if self.check_ip_block(self.config.classifier_ignore_ip,
                #                        [self.inet_to_str(self.src), self.inet_to_str(self.dst)]):
                #     return

                if self.selected_app is not None:
                 #   t4 = time.time()
                    print "SELECTED APP:",self.selected_app.name, self.selected_app
                    app_response = self.selected_app.recv_data(data, self.pkt, select_by, app_label, callback=self)
                    if app_response is not None:
                        try:
                            app_response = app_response

                        except:
                            try:
                                app_response, flags = app_response
                            except:
                                pass

                    # #print "THESE ARE THE FLAGS", flags
                    #print "TIME4:", time.time() - t4
                    #t5 =  time.time()
                    self.tx_len_checker(app_response, flags)
                    #print "TIME5:", time.time() - t5

                else:
                    if self.config.default_app is None:
                        # TODO: We can't handle this so we will just return
                        # Will log in future
                        self.SEND_RST_ACK()


    def chunksdata(self, s):
        length = self.config.MSS
        return (s[0 + i:length + i] for i in range(0, len(s), length))

    def tx_len_checker(self, data, flags):
        if data is not None:
            to_send = len(data)
            # #print "TO_SEND", to_send
            buffer = self.chunksdata(data)
            # #print "BUFFER", buffer
            if flags is not None and len(flags) != 0:
                if 'R' in flags:
                    if 'A' in flags:
                        self.SEND_RST_ACK()
                    else:
                        self.SEND_RST()
                elif 'A' in flags:
                    if 'P' in flags:
                        if 'F' in flags:
                            while to_send != 0:
                                d = buffer.next()
                                to_send = to_send - len(d)
                                if to_send == 0:
                                    self.SEND_FIN_PSH_ACK(d)
                                else:
                                    self.SEND_DATA(d)
                        else:
                            while to_send != 0:
                                d = buffer.next()
                                to_send = to_send - len(d)
                                self.SEND_DATA(d)
                    else:
                        self.SEND_ACK()
                elif 'F' in flags:
                    self.SEND_FIN_ACK()
                else:
                    while to_send != 0:
                        d = buffer.next()
                        to_send = to_send - len(d)
                        self.SEND_DATA(d)
            else:
                while to_send != 0:
                    d = buffer.next()
                    to_send = to_send - len(d)
                    self.SEND_DATA(d)
        else:
            pass
    #TODO: This really needs to be seperated out because it is trash being in the file.
    def select_best_app(self, matched_apps):
        best_app_priority = 255
        best_app = None
        # print'start math'
        for i in matched_apps:
            # print'a'
            if i.default_app is True:
                continue
            if isinstance(i.priority, int):
                # print'b'
                if i.priority <= best_app_priority:
                    # print'c'
                    if isinstance(i.match_ip, bool):
                        # print'd'
                        if i.match_ip:
                            # print'e'
                            if isinstance(i.match_list, list):
                                # print'f'
                                for j in i.match_list:
                                    # print'g'
                                    if "/" in j:
                                        # print'h'
                                        if netaddr.IPAddress(self.inet_to_str(self.src)) == netaddr.IPNetwork(j):
                                            # print'i'
                                            if isinstance(i.pri_match_ip, int):
                                                # print'j'
                                                if best_app_priority > i.pri_match_ip:
                                                    # print'k'
                                                    best_app_priority = i.pri_match_ip
                                                    best_app_priority = i
                                        else:
                                            if i.priority < best_app_priority:
                                                # print'q2'
                                                best_app_priority = i.priority
                                                best_app = i
                                    else:
                                        # print'l'
                                        if netaddr.IPAddress(self.inet_to_str(self.src)) == netaddr.IPAddress(j):
                                            # print'm'
                                            if isinstance(i.pri_match_ip, int):
                                                # print'n'
                                                if best_app_priority > i.pri_match_ip:
                                                    # print'o'
                                                    best_app_priority = i.pri_match_ip
                                                    best_app = i
                                        else:
                                            if i.priority < best_app_priority:
                                                # print'q2'
                                                best_app_priority = i.priority
                                                best_app = i
                        else:
                            # print'p'
                            if i.priority < best_app_priority:
                                # print'q'
                                best_app_priority = i.priority
                                best_app = i
        # printbest_app
        selected_app = type('selected_app', (best_app.__class__,), dict(best_app.__dict__))
        self.selected_app = selected_app()


    def __del__(self):
        self.state = None
        self.config = None
        self.classifier_enabled = None
        self.classifier = None
        self.__APPS__ = None
        self.sport = None
        self.pkt = None
        self.rtt = None
        self.acum_rtt = None
        self.srtt = None
        self.rx_buffer_size = None
        self.rtt_bucket = None
        self.selected_app = None
        self.seq = None
        self.isn = None
        self.seq_ack = None
        self.src = None
        self.dst = None
        self.pkt_count = None
        self.pkt_buffer = None
        self.data_buffer = None
        self.win = None
        self.size_last_data = None
        # Everytime we get a packet timestamp update
        self.TS = None
        self.c_time = None
        self.r_window = None
        self.sa = None
        self.msl_time = None
        self.t_locker = None
        self.time_lock = None