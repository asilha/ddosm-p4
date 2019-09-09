#!/bin/bash

if [ $(id -u) != "0" ]
then
    sudo "$0" "$@"
    exit $?
fi

sysctl net.ipv6.conf.s1-eth1.disable_ipv6=1
sysctl net.ipv6.conf.s1-eth2.disable_ipv6=1
sysctl net.ipv6.conf.s1-eth3.disable_ipv6=1

../../aclapolli-bmv2/targets/simple_switch/simple_switch_CLI < control_rules.txt
