#!/bin/bash

if [ $(id -u) != "0" ]
then
    sudo "$0" "$@"
    exit $?
fi

SS_PREFIX="../../aclapolli-bmv2/targets/simple_switch"

SS_PARAMS="--log-level info --log-console"

rm -rf logs/
rm -rf pcaps/

lib/run_exercise.py -t topology.json -b ../../aclapolli-bmv2/targets/simple_switch/simple_switch -j ../build/ddosd.json -q

