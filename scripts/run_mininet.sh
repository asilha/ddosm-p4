#!/bin/bash

if [ $(id -u) != "0" ]
then
    sudo "$0" "$@"
    exit $?
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

SS_PREFIX="/home/p4/p4sec/aclapolli-bmv2/targets/simple_switch"

SS_PARAMS="--log-level info --log-console"

rm -rf logs/
rm -rf pcaps/

./scripts/lib/run_exercise.py -t $SCRIPT_DIR/run_mininet.json -b $SS_PREFIX/simple_switch -j ./build/ddosd.json -q

