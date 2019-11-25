#!/usr/bin/python3.7

from dataclasses import dataclass

import os

@dataclass
class PCAPSample:
    ow_first: int = 0
    ow_last:  int = 0
    ow_size:  int = 0
    base_path: str = ""
    base_name: str = ""


def run_tshark(base_path_name):
    assert os.path.isfile(base_path_name + ".pcapng")
    # command = "echo src,dst,id,attack > " + base_path_name + ".csv"
    command = "echo src,dst,src_delta,dst_delta,attack > " + base_path_name + ".csv"
    print(command)
    #os.system(command)
    # command = "tshark -r " + base_path_name + ".pcapng -T fields -e ip.src -e ip.dst -e ip.id -e data.data | " + \
    #           "awk 'BEGIN {OFS=\",\"} {print $1,$2,$3,substr($4,50,1) }' >> " + base_path_name + ".csv"
    command = "tshark -r " + base_path_name + ".pcapng -T fields -e ip.src -e ip.dst -e ip.id -e ip.checksum -e data.data | " + \
              "awk 'BEGIN {OFS=\",\"} {print $1,$2,$3,$4,substr($5,50,1) }' >> " + base_path_name + ".csv"
    print(command)
    #os.system(command)

def main():
    sample = PCAPSample()
    sample.ow_first = 1
    sample.ow_last = 1024
    sample.ow_size = 16384
    sample.base_path = "/home/ilha/p4sec/ddosm-p4/pcaps/ddos20m14b"
    sample.base_name = "if3_attack_out"

    assert sample.ow_first > 0
    assert sample.ow_last > 0
    assert sample.ow_last >= sample.ow_first
    assert sample.ow_size > 0

    base_path_name = sample.base_path + "/" + sample.base_name
        
    run_tshark(base_path_name) 
        
if __name__ == '__main__':
    main()

