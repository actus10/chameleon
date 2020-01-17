# -*- coding: utf-8 -*-
# Copyright 2017, A10 Networks
# Author: Mike Thompson: @mike @t @a10@networks!com
# This is an example of the default application template.
import os
import socket
import threading
import time
import traceback
from utilities import es_uploader as es

import config

class Main(object):
    def __init__(self):
        #threading.Thread.__init__(self)
        # DO NOT MODIFY ABOVE THIS LINE....
        self.student = config.studentid
        #Do Not Modify Below this Line
        self.protocol = 'any'
        self.port = 0
        self.default_app = True
        self.name = "DEFAULT_APP_CATCH_ALL"
        self.labels = [None, ]
        self.priority = 10
        self.match_ip = False
        self.match_list = []
        self.pri_match_ip = 255
        self.buffer = []

    def run(self):
        pass

    def recv_data(self, data, pkt, select_by, app_label, callback=None):
        try:
            callback.SEND_RST()
            self.logit(data, pkt, select_by, app_label, callback)
        except:
            traceback.print_exc()

    def logit(self, data, pkt, select_by, app_label, callback):
        pkt = pkt
        transport = None
        if pkt.p == 6:
            transport = pkt.tcp

        if app_label == None or app_label == ():
            app_label = "investigate"
        if isinstance(app_label, tuple):
            app_label = app_label[0]

        log_structure = {
            "selected_by": select_by,
            "app_label": app_label,
            "ip_src": socket.inet_ntop(socket.AF_INET, pkt.src),
            "ip_dst": socket.inet_ntop(socket.AF_INET, pkt.dst),
            "sensor_type": self.student,
            "raw_data": data.decode('unicode_escape').encode('utf-8'),
            "raw_packet": str(pkt.__dict__),
            "ip_proto": pkt.p,
            "sport": transport.sport,
            "dport": transport.dport,
            "timestamp": int(time.time() * 1000)
        }
        url ="/chameleon/sensors/?pipeline=geoip"
        e = es.elastic_upload()
        resp = e.send(url, data=log_structure)
        print resp
