#!/bin/bash

while true; 
do
    # TODO Add inotify-tools as a dependency.
    inotifywait -e modify -q -q -t 60 $1

    if [ $? -eq 2 ] 
    then 
        echo "Timeout! Let's kill the switch."
        sudo killall -w simple_switch 
        break
    fi

done


