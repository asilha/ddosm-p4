#!/bin/sh

#set -xe

DIR=$1
OPTIONS="-c -M -T -r"
INFO_CMD="capinfos $OPTIONS"
CUT_CMD="cut -f 2"

N_GOOD=`$INFO_CMD $DIR/if2_legitimate_out.pcap | $CUT_CMD`
N_EVIL=`$INFO_CMD $DIR/if3_attack_out.pcap | $CUT_CMD`
N_STAT=`$INFO_CMD $DIR/if4_stats_out.pcap | $CUT_CMD`

echo "Good: \t$N_GOOD"
echo "Evil: \t$N_EVIL" 
echo "Total: \t$(( N_GOOD + N_EVIL ))"
echo "OWs: \t$N_STAT"

echo 
