#!/usr/bin/python3

import os

ee_bin = "/media/p4/ddosd-cpp/bin/ee"
json_path = "/media/p4/ddosd-p4/scripts"
log_path = "/media/p4/ddos/datasets/p4damp"
workload_file = "/media/p4/ddos/datasets/p4damp/ddos20.pcap" 

for i in range(13,19):
    base_name = "ee_m_2_" + str(i) 
    json_file = json_path + "/" + base_name + ".json"
    log_file = log_path + "/" + base_name + ".log"
    ee_cmd = ee_bin + " -c " + json_file + " " + workload_file + " > " + log_file 
    print(ee_cmd)
    os.system(ee_cmd)

