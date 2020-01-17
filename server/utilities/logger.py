# Copyright (C) 2014, A10 Networks Inc. All rights reserved.
import logging
import random
import socket
import threading

try:
    import server.config as config
except:
    try:
        import config
    except BaseException as e:
        raise e

FACILITY = {
    'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3,
    'auth': 4, 'syslog': 5, 'lpr': 6, 'news': 7,
    'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
    'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
    'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23,
}

LEVEL = {
    'emerg': 0, 'alert': 1, 'crit': 2, 'err': 3,
    'warning': 4, 'notice': 5, 'info': 6, 'debug': 7
}


class Remote(threading.Thread):
    """ Send syslog UDP packet to given host and port. """

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        pass

    def send(self, message, level=LEVEL['notice'], facility=FACILITY['daemon'], host='1234',
             port=514):
        if config.syslog_enable_remote:
            if len(config.syslog_server) > 0:
                server = random.choice(config.syslog_server)
                if ":" in server:
                    port = server.rsplit(":")
                    host = server.lsplit(":")
                else:
                    host = server
                    port = 514
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                data = '<%d>%s' % (level + facility * 8, message)
                sock.sendto(data, (host, port))
                sock.close()
            else:
                raise Exception('config.syslog_server is 0')
        else:
            raise Exception('config.syslog_enable_remote is 0')


class Local(logging.getLoggerClass()):
    def __init__(self):
        self.basicConfig(filename=config.syslog_dir, level=logging.DEBUG)
        self.get_logger()

    def get_logger(self):
        return self.logging.getLogger(__name__)


if __name__ == "__main__":
    log = Local()
    print dir(log)
    print log.debug("foo")
