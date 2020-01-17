# -*- coding: utf-8 -*-
# Copyright 2017, A10 Networks
# Author: Mike Thompson: @mike @t @a10@networks!com

# TCB LIKE Functionality... using green threads seem to hurt performance.
import pprint
import threading
import gc
gc.enable()
pp = pprint.PrettyPrinter(indent=4)

class TCPFlowObj(object):
    def __init__(self, src, sport, dst, dport):
        # basically the TCB for the session
        self.src = src
        self.dst = dst
        self.dport = dport
        self.sport = sport
        self.tcp_state = None
        self.tcp_event = None
        self.next_state = None
        self.bytes_in = None
        self.bytes_out = None
        self.RTT = None
        self.timeout = None
        self.packet_number = None
        self.seq_sent = None
        self.window_size = None
        self.app_data = None
        self.key =  str(src) + str(sport) + str(dst) + str(dport)
        self.state_machine = None
        self.classifier = None


class TCPFlowTable():
    def __init__(self):
        self.cft = {}
        self.clean_timer()

    def clean_timer(self):
        t = threading.Timer(1, self.clean, [], {})
        t.start()

    def create_entry(self, src, sport, dst, dport):
        flowObj = TCPFlowObj(src, sport, dst, dport)
        self.cft[flowObj.key] = flowObj

    def delete_flow_object(self, flowObj):
        del self.cft[flowObj.key]
        # try:
        #     print self.cft[flowObj.key]
        # except:
        #     print "Key Not Found"

    def get_flow_object(self, src, sport, dst, dport):
        return self.cft[src+ sport+ dst+ dport]

    def check_exist(self,src, sport, dst, dport):
        return self.cft.get(src+sport+ dst+ dport, None)

    def update_flow_obj(self, flowObj):
        # state = flowObj.state_machine.__getattribute__('state')
        # if state is not None and state == 'CLOSED':
        #     del self.cft[flowObj.key]
        # else:
        self.cft[flowObj.key] = flowObj

    def clean(self):
        for k, v in self.cft.items():
            if v.state_machine.state is None:
                v.state_machine.join()
                v.state_machine = None
                self.delete_flow_object(k)
        self.clean_timer()

    def show_flows(self):
        for k, v in self.cft.items():
            print "KEY:", k
            print "Values:"
            pp.pprint(vars(v))


if __name__ == "__main__":
    import time
    t1 = time.time()

    for i in range(0, 10000):
        x = TCPFlowTable()
        a = '1234' + str(i)
        b = '2345' + str(i)
        c = '3456' + str(i)
        d = '4567' + str(i)
        if not x.check_exist(a, b, c, d):
            x.create_entry(a, b, c, d)
            flowObj = x.get_flow_object(a, b, c, d)
            if flowObj.key == (a + b + c + d):
                pass
                #print 'KeyMatched'
            else:
                print flowObj.key, (a + b + c + d)
            flowObj.state_machine = True
            x.update_flow_obj(flowObj)
        if x.check_exist(a, b, c, d):

            flowObj = x.get_flow_object(a, b, c, d)
            flowObj.state_machine = False
            x.update_flow_obj(flowObj)
        else:
            print 'broken check'
    t2 = time.time()
    print "TIME:", t2-t1