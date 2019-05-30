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

$SCRIPT_DIR/veth.sh setup 6

SS_PREFIX="../../aclapolli-bmv2/targets/simple_switch"

trap sigint_handler SIGINT
$SS_PREFIX/simple_switch -i 0@veth0 -i 1@veth2 -i 2@veth4 $SCRIPT_DIR/../build/ddosd.json &
pid=$!
sleep 15
$SS_PREFIX/simple_switch_CLI < $SCRIPT_DIR/control_rules.txt
wait $pid

$SCRIPT_DIR/veth.sh delete 6

exit 0
