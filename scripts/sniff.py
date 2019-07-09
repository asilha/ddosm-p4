#!/usr/bin/python3

# Based in https://github.com/p4lang/tutorials/blob/master/exercises/mri/receive.py 

import sys
import struct

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

def handle_pkt(pkt):
    print('got a packet')
    pkt.show2()
    hexdump(pkt)
    sys.stdout.flush()


def main():
    iface = 'veth7'
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(filter='', iface = iface, prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
