#!/bin/sh

export DIR=../pcaps/ddos20
export OPTIONS="-c -M"

capinfos $OPTIONS $DIR/if2_legitimate_out.pcap
capinfos $OPTIONS $DIR/if3_attack_out.pcap
capinfos $OPTIONS $DIR/if4_stats_out.pcap
