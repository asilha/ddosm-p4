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

def get_output_name(base_path_name, ow, packet_first, packet_last):
    return base_path_name + "-" + str(ow) + "-" + str(packet_first) + "-" + str(packet_last)

def run_editcap(input_name, output_name, packet_first, packet_last):
    assert os.path.isfile(input_name + ".pcap")
    command = "editcap -r " + input_name + ".pcap " + output_name + ".pcap " + str(packet_first) + "-" + str(packet_last)
    print(command)
    os.system(command)

def run_tshark(output_name):
    assert os.path.isfile(output_name + ".pcap")
    command = "echo src,dst,attack > " + output_name + ".csv"
    os.system(command)
    command = "tshark -r " + output_name + ".pcap -T fields -e ip.src -e ip.dst -e data.data | " + \
              "awk 'BEGIN {OFS=\",\"} {print $1,$2,substr($3,50,1) }' >> " + output_name + ".csv"
    # print(command)
    os.system(command)

def main():
    sample = PCAPSample()
    sample.ow_first = 189
    sample.ow_last = 196
    sample.ow_size = 8192
    # sample.base_path = "D:/downloads/p4/ddos/datasets/zed"
    sample.base_path = "/media/p4/ddos/datasets/zed"
    sample.base_name = "zed20percent"

    assert sample.ow_first > 0
    assert sample.ow_last > 0
    assert sample.ow_last >= sample.ow_first
    assert sample.ow_size > 0

    base_path_name = sample.base_path + "/" + sample.base_name
    input_name = base_path_name

    for ow in range(sample.ow_first, sample.ow_last):
        
        packet_first = sample.ow_size * (ow - 1) + 1  
        packet_last  = packet_first + sample.ow_size - 1
        assert packet_last - packet_first + 1 == sample.ow_size
        
        output_name = get_output_name(base_path_name, ow, packet_first, packet_last)
        
        run_editcap(input_name, output_name, packet_first, packet_last)
        
        run_tshark(output_name) 
        
if __name__ == '__main__':
    main()

