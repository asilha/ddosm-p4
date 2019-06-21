#!/bin/bash

export trace="/media/p4/ddos/datasets/ddos5.pcap"

tcpreplay -q --limit=10240 -i s1-eth1 $trace 2>&1 
