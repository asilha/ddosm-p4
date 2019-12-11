#!/usr/bin/python3.7

from dataclasses import dataclass

import argparse
import os

@dataclass
class PCAPSample:
    ow_first: int = 0
    ow_last:  int = 0
    ow_size:  int = 0
    base_path: str = ""
    base_name: str = ""


def run_tshark(in_pcap, out_csv):
    # command = "echo src,dst,id,attack > " + base_path_name + ".csv"
    command = "echo src,dst,src_delta,dst_delta,attack > " + out_csv
    #print(command)
    os.system(command)
    # command = "tshark -r " + base_path_name + ".pcapng -T fields -e ip.src -e ip.dst -e ip.id -e data.data | " + \
    #           "awk 'BEGIN {OFS=\",\"} {print $1,$2,$3,substr($4,50,1) }' >> " + base_path_name + ".csv"
    command = "tshark -r " + in_pcap + " -T fields -e ip.src -e ip.dst -e ip.id -e ip.checksum -e data.data | " + \
              "awk 'BEGIN {OFS=\",\"} {print $1,$2,$3,$4,substr($5,50,1) }' >> " + out_csv
    #print(command)
    os.system(command)

def main():


    parser = argparse.ArgumentParser(description="Processes a PCAP file generated by ddosm-p4 and outputs a CSV file containing " + 
                                                 "src, dst, src_delta, dst_delta, and attack flag.")
    parser.add_argument("-i", "--in_pcap", help="PCAP file to process")
    parser.add_argument("-o", "--out_csv", help="CSV file to save results to")
    args = parser.parse_args()

    #print(args.in_pcap)
    #print(args.out_csv)

    sample = PCAPSample()
    sample.base_path = "/home/ilha/p4sec/ddosm-p4/pcaps/ddos20m14b"
    sample.base_name = "if3_attack_out"

    assert os.path.isfile(args.in_pcap)
    assert not os.path.isfile(args.out_csv) 
        
    run_tshark(args.in_pcap, args.out_csv) 
        
if __name__ == '__main__':
    main()

