#!/bin/sh

export DIR=../pcaps/exp-tmp
export OPTIONS="-c -M"

capinfos $OPTIONS $DIR/if2_legitimate_out.pcapng
capinfos $OPTIONS $DIR/if3_attack_out.pcapng
capinfos $OPTIONS $DIR/if4_stats_out.pcapng