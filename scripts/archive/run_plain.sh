#!/bin/bash

if [ $(id -u) != "0" ]
then
    sudo "$0" "$@"
    exit $?
fi

sigint_handler() {
    kill -9 $pid
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

SS_PREFIX="/home/p4/p4sec/aclapolli-bmv2/targets/simple_switch"

# SS_PARAMS="--log-level info --log-console"
SS_PARAMS="--log-level off"

trap sigint_handler SIGINT
$SS_PREFIX/simple_switch -i 1@veth0 -i 2@veth2 -i 3@veth4 -i 4@veth6 $SS_PARAMS $SCRIPT_DIR/../build/ddosd.json &
pid=$!
sleep 5
$SS_PREFIX/simple_switch_CLI < $SCRIPT_DIR/control_rules.txt
wait $pid

exit 0
