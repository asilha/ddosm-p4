#!/usr/bin/python3

# Based in https://github.com/p4lang/tutorials/blob/master/exercises/mri/receive.py 

import sys
import struct

from scapy.all import * 

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

def pkt_to_string(ddosd):
    return "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}".format(        
        ddosd.src_ent, 
        ddosd.src_ewma, 
        ddosd.src_ewmmd, 
        ddosd.dst_ent, 
        ddosd.dst_ewma, 
        ddosd.dst_ewmmd, 
        ddosd.alarm, 
        ddosd.defcon)

def pkt_to_string_human_readable(ddosd):
    return "{:.3f}\t{:.3f}\t{:.3f}\t{:.3f}\t{:.3f}\t{:.3f}\t{}\t{}".format(        
        ddosd.src_ent/16.0, 
        ddosd.src_ewma/(2.0**18), 
        ddosd.src_ewmmd/(2.0**18), 
        ddosd.dst_ent/16.0, 
        ddosd.dst_ewma/(2.0**18), 
        ddosd.dst_ewmmd/(2.0**18), 
        ddosd.alarm, 
        ddosd.defcon)

def handle_pkt(pkt):
    ddosd=pkt[DDoSD] 
    #print(pkt_to_string_human_readable(ddosd))
    print(pkt_to_string(ddosd))

def main():
    bind_layers(Ether, DDoSD, type=0x6605)
    bind_layers(DDoSD, IP, ethertype=0x0800)
    bind_layers(IP, DDoSDPayload, proto=253)
    packets = rdpcap('if4_stats_out.pcapng')
    #packets = rdpcap('if4_stats_out.pcap')
    for packet in packets: 
    	handle_pkt(packet)
    	
if __name__ == '__main__':
    main()
