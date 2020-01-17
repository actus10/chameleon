# -*- coding: utf-8 -*-
# Copyright 2017, A10 Networks
# Author: Mike Thompson: @mike @t @a10@networks!com
# tcp reference for events, flags, states

_TCP_STATES = [
    'CLOSED',
    'LISTEN',
    'SYN_RCVD',
    'ESTABLISHED',
    'SYN_SENT',
    'FIN_WAIT_1',
    'FIN_WAIT_2',
    'TIME_WAIT',
    'CLOSING',
    'CLOSE_WAIT',
    'LAST_ACK',
]

TCP_EVENTS = [
    'PASSIVE',
    'ACTIVE',
    'SYN',
    'SYNACK',
    'ACK',
    'RDATA',
    'SDATA',
    'FIN',
    'CLOSE',
    'TIMEOUT',
]

_flag_map_hex = {
    0x00: 'NONE',
    0x01: 'FIN',
    0x02: 'SYN',
    0x03: 'FIN-SYN',
    0x04: 'RST',
    0x08: 'PSH',
    0x09: 'FIN-PSH',
    0x0A: 'SYN-PSH',
    0x0B: 'FIN-SYN-PSH',
    0x10: 'ACK',
    0x11: 'FIN-ACK',
    0x12: 'SYN-ACK',
    0x14: 'RST-ACK',
    0x13: 'FIN-SYN-ACK',
    0x18: 'PSH-ACK',
    0x19: 'FIN-PSH-ACK',
    0x1A: 'SYN-PSH-ACK',
    0x1B: 'FIN-SYN-PSH-ACK',
    0x1C: 'RST-PSH-ACK',
    0x20: 'URG',
    0x40: 'ECE',
    0x41: 'FIN-ECE',
    0x42: 'SYN-ECE',
    0x43: 'FIN-SYN-ECE',
    0x48: 'PSH-ECE',
    0x49: 'FIN-PSH-ECE',
    0x4A: 'SYN-PSH-ECE',
    0x4B: 'FIN-SYN-PSH-ECE',
    0x50: 'ACK-ECE',
    0x51: 'FIN-ACK-ECE',
    0x52: 'SYN-ACK-ECE',
    0x53: 'FIN-SYN-ACK-ECE',
    0x58: 'PSH-ACK-ECE',
    0x59: 'FIN-PSH-ACK-ECE',
    0x5A: 'SYN-PSH-ACK-ECE',
    0x5B: 'FIN-SYN-PSH-ACK-ECE',
    0x80: 'CWR',
    0x81: 'FIN-CWR',
    0x82: 'SYN-CWR',
    0x83: 'FIN-SYN-CWR',
    0x88: 'PSH-CWR',
    0x89: 'FIN-PSH-CWR',
    0x8A: 'SYN-PSH-CWR',
    0x8B: 'FIN-SYN-PSH-CWR',
    0x90: 'ACK-CWR',
    0x91: 'FIN-ACK-CWR',
    0x92: 'SYN-ACK-CWR',
    0x93: 'FIN-SYN-ACK-CWR',
    0x98: 'PSH-ACK-CWR',
    0x99: 'FIN-PSH-ACK-CWR',
    0x9A: 'SYN-PSH-ACK-CWR',
    0x9B: 'FIN-SYN-PSH-ACK-CWR',
    0xC0: 'ECE-CWR',
    0xC1: 'FIN-ECE-CWR',
    0xC2: 'SYN-ECE-CWR',
    0xC3: 'FIN-SYN-ECE-CWR',
    0xC8: 'PSH-ECE-CWR',
    0xC9: 'FIN-PSH-ECE-CWR',
    0xCA: 'SYN-PSH-ECE-CWR',
    0xCB: 'FIN-SYN-PSH-ECE-CWR',
    0xD0: 'ACK-ECE-CWR',
    0xD1: 'FIN-ACK-ECE-CWR',
    0xD2: 'SYN-ACK-ECE-CWR',
    0xD3: 'FIN-SYN-ACK-ECE-CWR',
    0xD8: 'PSH-ACK-ECE-CWR',
    0xD9: 'FIN-PSH-ACK-ECE-CWR',
    0xDA: 'SYN-PSH-ACK-ECE-CWR',
    0xDB: 'FIN-SYN-PSH-ACK-ECE-CWR'
}

# tcp_flag_map_dec = {
#
# }
# from collections import OrderedDict
#
# sorted_dictionary = OrderedDict(sorted(_flag_map_hex.items(), key=lambda v: v, reverse=False))
# print '{'
# for k,v in sorted_dictionary.items():
#     print str(k) +':"'+v+'"'
# print '}'
