#!/bin/bash

if [ $(id -u) != "0" ]
then
    sudo "$0" "$@"
    exit $?
fi

if [ $# -ne 1 ] || ([ "$1" != "start" ] && [ "$1" != "stop" ])
then
    echo "Usage: $0 (start|stop)"
    exit -1
fi

if [ "$1" = "start" ]
then
    for i in {0..6..2} 
    do 
        tcpdump -i veth$i -K -n -s 80 -w /media/p4/veth$i.pcap & 
    done
    sleep 5
elif [ "$1" = "stop" ]
then
    sleep 5
    killall -TERM tcpdump 
    for i in {0..6..2} 
    do 
        gzip /media/p4/veth$i.pcap  
    done

fi


