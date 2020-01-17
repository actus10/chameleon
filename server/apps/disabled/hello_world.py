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
        self.protocol = 'tcp'
        self.port = 0
        self.default_app = False
        self.name = "hello_world"
        self.labels = ['Hello World', ]
        self.priority = 10
        self.match_ip = False
        self.match_list = []
        self.pri_match_ip = 255
        self.buffer = []


    def run(self):
        pass

    def recv_data(self, data, pkt, select_by, app_label, callback=None):
        try:
            self.response(data, pkt, select_by, app_label, callback)
            self.logit(data, pkt, select_by, app_label, callback)

        except:
            traceback.print_exc()

    def response(self, data, pkt, select_by, app_label, callback):
        #keep in mind that everything returned needs to be a string. You can not return python objects.
        msg = "Hello {s},\r\nI predicted that you would call with the app label {l}".format(s=self.student, l=self.labels[0])
        callback.SEND_DATA(msg)
        callback.SEND_FIN_ACK()
        
        # callback.SEND_FIN_PSH_ACK(app_label)  # <- tcp fin, push and ack flags are set.
        # callback.SEND_RST() #<- tcp reset flag is set.
        # callback.SEND_RST_ACK() #<- tcp reset and ack flags are set.
        # callback.SEND_FIN_ACK(msg) #<- tcp fin and ack flags are set.
        # callback.SEND_ACK() #<- tcp ack the data again, right now we ack every packet this needs to be optimized.
        # callback.SEND_SYN_ACK()
        

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
