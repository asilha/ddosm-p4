#!/usr/bin/python3

import argparse
import os

# ee_bin = "/media/p4/ddosd-cpp/bin/ee"
# json_path = "/media/p4/ddosd-p4/scripts/p4d_ddos20"
# log_path = "/media/p4/p4damp/datasets/ddos20/ddos20_results"
# workload_file = "/media/p4/p4damp/datasets/ddos20/ddos20.pcap" 

# for i in range(13,19):
#     base_name = "ee_m_2_" + str(i) 
#     json_file = json_path + "/" + base_name + ".json"
#     log_file = log_path + "/" + base_name + ".log"
#     ee_cmd = ee_bin + " -c " + json_file + " " + workload_file + " > " + log_file 
#     print(ee_cmd)
#     os.system(ee_cmd)

def main():

    parser = argparse.ArgumentParser(description="Processes a workload and outputs ee traces.")
    parser.add_argument("-i", "--in_pcap", help="PCAP workload to process")
    parser.add_argument("-j", "--json_path", help="Directory with ee json configurations")
    parser.add_argument("-l", "--log_path", help="Directory for ee trace output"),
    args = parser.parse_args()

    #print(args)

    ee_bin = "~/p4sec/ddosd-cpp/bin/ee"
    base_name = "ee_m_2_18" 
    json_file = args.json_path + "/" + base_name + ".json"
    log_file  = args.log_path + "/" + base_name + ".log"
    ee_cmd = ee_bin + " -c " + json_file + " " + args.in_pcap + " > " + log_file 
    print(ee_cmd)
    # os.system(ee_cmd)  


    # ./generate_ee_traces.py 
    # -i ~/p4sec/ddosm-p4/datasets/synthetic-ilha-ddos20-full/ddos20-full.pcap 
    # -j ~/p4sec/ddosm-p4/lab/ddos20-full/ee_json
    # -l ~/p4sec/ddosm-p4/lab/ddos20-full/ee_logs
        
if __name__ == '__main__':
    main()
