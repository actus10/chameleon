import os
import socket
import threading
import time
import traceback
import copy
from utilities import es_uploader as es
from utilities import logos

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
        self.name = "hello_bot"
        self.labels = ['Hello Bot', ]
        self.priority = 10
        self.match_ip = False
        self.match_list = []
        self.pri_match_ip = 255
        self.buffer = []
        self.step = 0


    def run(self):
        pass

    def recv_data(self, data, pkt, select_by, app_label, callback=None):
        try:
            self.response(data, pkt, select_by, app_label, callback)
            self.logit(data, pkt, select_by, app_label, callback)
        except:
            traceback.print_exc()

    def response(self, data, pkt, select_by, app_label, callback):
        x = 0
        #keep in mind that everything returned needs to be a string. You can not return python objects.
        if self.step == 0:
            if "get" in data.lower() or "http" in data.lower():
                msg1 = "HTTP/1.0 200 OK\r\n\r\nHello {s},\r\n".format(s=self.student)
            else:
                msg1 = "Hello {s},\r\n".format(s=self.student)
            msg2 = "I see that you are a bot and predicted as: {l}\n\n".format(l=self.labels[0])
            msg3 = "I dislike bots!\n\n"
            msg4 = "This is packet 4\n\n"
            msg5 = logos.image2
            msg6 = "\n\nIf you say \"please\" I will send a FIN-PSH-ACK otherwise you will get a RST\n\n"
            # Lets delay each packet by a 10 ms.
            callback.SEND_DATA(msg1)
            time.sleep(.01)
            callback.SEND_DATA(msg2)
            time.sleep(.01)
            callback.SEND_DATA(msg3)
            time.sleep(.01)
            callback.SEND_DATA(msg4)
            time.sleep(.01)
            # sometimes you just want to have some fun and need to split the payload up because of the size.
            # Or you just want to send back really slow.
            to_send = len(msg5)
            msg_buffer = callback.chunksdata(msg5)
            while to_send != 0:
                try:
                    d = msg_buffer.next()
                    to_send = to_send - len(d)
                    callback.SEND_DATA(d)
                    time.sleep(.03)
                except StopIteration:
                    break
            callback.SEND_DATA(msg6)
            self.step += 1
        else:
            if "please" in data.lower():
                callback.SEND_FIN_PSH_ACK('Have a nice day {s}\n\n'.format(s=self.student))

            else:
                callback.SEND_DATA('No FIN-PSH-ACK for {s} you are getting Reset\n\n'.format(s=self.student))
                callback.SEND_RST()


        # callback.SEND_FIN_PSH_ACK(msg)  # <- tcp fin, push and ack flags are set.
        # callback.SEND_RST() #<- tcp reset flag is set.
        # callback.SEND_RST_ACK() #<- tcp reset and ack flags are set.
        # callback.SEND_FIN_ACK() #<- tcp fin and ack flags are set.
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
