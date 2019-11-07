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
    for i in {1..7..2} 
    do 
        wireshark -i veth$i -k & 
        sleep 0.25
    done
elif [ "$1" = "stop" ]
then
    killall -TERM wireshark
fi


