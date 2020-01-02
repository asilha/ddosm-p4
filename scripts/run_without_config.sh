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

SS_PREFIX="/usr/local/bin"

#SS_PARAMS="--log-level off"
SS_PARAMS="--log-file debug --log-level debug"

trap sigint_handler SIGINT
$SS_PREFIX/simple_switch -i 1@veth1 -i 2@veth3 -i 3@veth5 -i 4@veth7 $SS_PARAMS $SCRIPT_DIR/../build/ddosm.json &
pid=$!
sleep 5
echo Switch is running. use CTRL+C to interrupt.
wait $pid

exit 0
