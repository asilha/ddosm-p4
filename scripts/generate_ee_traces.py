#!/usr/bin/python3

import argparse
import os

def main():

    parser = argparse.ArgumentParser(description="Processes a workload and outputs ee traces.")
    parser.add_argument("-i", "--in_pcap", help="PCAP workload to process")
    parser.add_argument("-j", "--json_path", help="Directory with ee json configurations")
    parser.add_argument("-l", "--log_path", help="Directory for ee trace output"),
    args = parser.parse_args()

    ee_bin = "~/p4sec/ddosd-cpp/bin/ee"
    base_name = "ee_m_2_18" 
    json_file = args.json_path + "/" + base_name + ".json"
    log_file  = args.log_path + "/" + base_name + ".log"
    ee_cmd = ee_bin + " -c " + json_file + " " + args.in_pcap + " > " + log_file 
    print(ee_cmd)
        
if __name__ == '__main__':
    main()
