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
    for i in {2..6..2} 
    do 
        nice -8 tcpdump -i veth$i -K -n -s 80 -w $2/veth$i.pcap & 
    done
    sleep 10
elif [ "$1" = "stop" ]
then
    sleep 10
    killall -TERM tcpdump 
    sleep 10
    for i in {2..6..2} 
    do 
        gzip -f $2/veth$i.pcap  
    done

fi


