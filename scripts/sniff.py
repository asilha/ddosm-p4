#!/usr/bin/python3

# Based in https://github.com/p4lang/tutorials/blob/master/exercises/mri/receive.py 

import sys
import struct

from scapy.all import bind_layers, hexdump, sniff
from scapy.all import Packet, Ether, IP, TCP, UDP, Raw
from scapy.all import ByteField, XShortField, IntField, LongField

class DDoSD(Packet):
    name = "DDoSD Header"
    fields_desc = [IntField('pkt_num',0),
    IntField('src_ent',0),
    IntField('src_ewma',0),
    IntField('src_ewmmd',0),
    IntField('dst_ent',0),
    IntField('dst_ewma',0),
    IntField('dst_ewmmd',0), 
    ByteField('alarm',0), 
    ByteField('defcon',0), 
    XShortField('ethertype',0)]

class DDoSDPayload(Packet):
    name = "DDoSD Payload"
    fields_desc = [LongField('ts_sec',0), 
    LongField('ts_usec',0), 
    ByteField('is_attack',0)]

def handle_pkt(pkt):
    ddosd=pkt[DDoSD] 
    print("| Src H={:.3f} A={:.3f} MD={:.3f} | Dst H={:.3f} A={:.3f} MD={:.3f} | Alarm={} Defcon={} |".format(        
        ddosd.src_ent/16.0, 
        ddosd.src_ewma/(2.0**18), 
        ddosd.src_ewmmd/(2.0**18), 
        ddosd.dst_ent/16.0, 
        ddosd.dst_ewma/(2.0**18), 
        ddosd.dst_ewmmd/(2.0**18), 
        ddosd.alarm, 
        ddosd.defcon)) 
    sys.stdout.flush()

def main():
    iface = 'veth7'
    print("sniffing on %s" % iface)
    sys.stdout.flush()

    bind_layers(Ether, DDoSD, type=0x6605)
    bind_layers(DDoSD, IP, ethertype=0x0800)
    bind_layers(IP, DDoSDPayload, proto=253)

    sniff(filter='', iface = iface, prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
