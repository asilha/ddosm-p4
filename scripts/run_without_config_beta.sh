#!/bin/bash

if [ $(id -u) != "0" ]
then
    sudo "$0" "$@"
    exit $?
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

SS_PREFIX="/home/p4/p4sec/aclapolli-bmv2/targets/simple_switch"

SS_PARAMS="--log-level off"

$SS_PREFIX/simple_switch --use-files 15 -i 1@veth0 -i 2@veth2 -i 3@veth4 -i 4@veth6 $SS_PARAMS $SCRIPT_DIR/../build/ddosd.json &
pid=$!
echo Switch is running. PID = $pid
sleep 5

exit 0
