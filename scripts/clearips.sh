#!/bin/bash

ip addr del 10.10.0.2/24 dev enp0s8
ip -6 addr del fc80:a::2/64 dev enp0s8
ip -6 addr del fe80::ca84:9294:d31e:4a24/64 dev enp0s8

