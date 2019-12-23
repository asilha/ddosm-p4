#!/bin/sh

#set -xe

DIR=$1
OPTIONS="-c -M -T -r"
INFO_CMD="capinfos $OPTIONS"
CUT_CMD="cut -f 2"

N_SENT=`$INFO_CMD $DIR/if1_workload_in.pcap | $CUT_CMD`
N_GOOD=`$INFO_CMD $DIR/if2_legitimate_out.pcapng | $CUT_CMD`
N_EVIL=`$INFO_CMD $DIR/if3_attack_out.pcapng | $CUT_CMD`
N_STAT=`$INFO_CMD $DIR/if4_stats_out.pcapng | $CUT_CMD`

#N_SENT=`$INFO_CMD $DIR/veth0.pcap.gz | $CUT_CMD`
#N_GOOD=`$INFO_CMD $DIR/veth2.pcap.gz | $CUT_CMD`
#N_EVIL=`$INFO_CMD $DIR/veth4.pcap.gz | $CUT_CMD`
#N_STAT=`$INFO_CMD $DIR/veth6.pcap.gz | $CUT_CMD`

echo "--------------------"
echo "Input: \t$N_SENT"

echo "--------------------"
echo "Good: \t$N_GOOD"
echo "Evil: \t$N_EVIL" 
echo "Total: \t$(( N_GOOD + N_EVIL ))"

echo "--------------------"
echo "Lost: \t$(( N_SENT - N_GOOD - N_EVIL ))"

echo "--------------------"
echo "OWs: \t$N_STAT"


