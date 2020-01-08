#!/bin/bash

if [ $(id -u) != "0" ]
then
    sudo "$0" "$@"
    exit $?
fi

if [ $# -ne 2 ] || ([ "$1" != "start" ] && [ "$1" != "stop" ])
then
    echo "Usage: $0 (start|stop) (dir)"
    exit -1
fi

if [ "$1" = "start" ]
then
    nice -8 tcpdump -i veth0 -K -n -s 80 -w $2/if0_workload_out.pcapng &
    sleep 2 
    nice -8 tcpdump -i veth2 -K -n -s 80 -w $2/if2_legitimate_out.pcapng & 
    sleep 2
    nice -8 tcpdump -i veth4 -K -n -s 80 -w $2/if3_attack_out.pcapng & 
    sleep 2
    nice -8 tcpdump -i veth6 -K -n -s 80 -w $2/if4_stats_out.pcapng & 
    sleep 2
elif [ "$1" = "stop" ]
then
    killall -TERM tcpdump 
    sleep 10
fi


