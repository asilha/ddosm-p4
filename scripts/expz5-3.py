#!/usr/bin/python3

import os

expname = "ddos5z3"

t_len = 256

phases = []
phases.append({"start" : 1,             "length" : t_len,   "alarms" : 0.0})  # phase 0: training
phases.append({"start" : 1+t_len,       "length" : t_len*4, "alarms" : 0.0})  # phase 1: detection under attack

# print(phases)

# quit()

kvalues = []

for i in range(32,5,-1):    # This goes from 4.00 down to 0.75
    kvalues.append(i/8.0)

paths = {}

paths["ee_bin"] = "/media/p4/ddosd-cpp/bin"
paths["ee_json"] = "/media/p4/ddosd-p4/scripts"
paths["ee_pcap"] = "/media/p4/ddos/datasets/sample"
paths["tcad_bin"]= "/media/p4/ddosd-cpp/bin"
paths["working_dir"] = "/media/p4"

for kvalue in kvalues:
    filename="{}/{}-{:.3f}.tcad.txt".format(paths["working_dir"],expname,kvalue)
    command="{}/ee -c {}/{}.json {}/ddos5y0.pcap | {}/tcad -t {} -s 0.078125 -k {:f} > {}".\
        format(paths["ee_bin"],paths["ee_json"],expname,paths["ee_pcap"],paths["tcad_bin"],t_len,kvalue,filename)
    # print(command)
    # os.system(command)
    with open(filename) as f:
        for phase in phases:
            phase["alarms"] = 0
        count=0
        line=f.readline()
        while line:
            count += 1
            if count < phases[1].get("start"):
              if line.rstrip().endswith("1"):  
                phases[0]["alarms"] += 1
            else:
              if line.rstrip().endswith("1"):  
                phases[1]["alarms"] += 1
            line=f.readline()

    tpr=phases[1]["alarms"]/phases[1]["length"]
    print("{:.3f} {:6f}".format(kvalue, tpr))





