#!/bin/bash

while true; 
do

    inotifywait -e modify -q -q -t 15 $1

    if [ $? -eq 2 ] 
    then 
        echo "Timeout! Let's kill the switch."
        sudo killall -w lt-simple_switch 
        break
    fi

done


