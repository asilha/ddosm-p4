#!/usr/bin/python3

import os

phases = []
phases.append({"start" : 1,     "length" : 256.0, "alarms" : 0.0})  # phase 0: training
phases.append({"start" : 257,   "length" : 128.0, "alarms" : 0.0})  # phase 1: detection under safety
phases.append({"start" : 385,   "length" : 256.0, "alarms" : 0.0})  # phase 2: detection under attack
phases.append({"start" : 641,   "length" : 128.0, "alarms" : 0.0})  # phase 3: detection under safety

kvalues = []

for i in range(32,5,-1):    # This goes from 4.00 down to 0.75
    kvalues.append(i/8.0)

paths = {}

paths["ee_bin"] = "/home/p4/p4sec/ddosd-cpp/bin"
paths["ee_json"] = "/home/p4/p4sec/ddosd-cpp/example"
paths["ee_pcap"] = "/media/p4/ddos/datasets/zed"
paths["tcad_bin"]= "/home/p4/p4sec/ddosd-cpp/bin"
paths["working_dir"] = "/media/p4"

expname = "ddos5z6"

for kvalue in kvalues:
    filename="{}/{}-{:.3f}.tcad.txt".format(paths["working_dir"],expname,kvalue)
    command="{}/ee -c {}/{}.json {}/zed20percent.pcap | {}/tcad -t 256 -s 0.078125 -k {:f} > {}".format(paths["ee_bin"],paths["ee_json"],expname,paths["ee_pcap"],paths["tcad_bin"],kvalue,filename)
    print(command)
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
            elif count < phases[2].get("start"):
              if line.rstrip().endswith("1"):  
                phases[1]["alarms"] += 1
            elif count < phases[3].get("start"):
              if line.rstrip().endswith("1"):  
                phases[2]["alarms"] += 1
            else:
              if line.rstrip().endswith("1"):  
                phases[3]["alarms"] += 1
            line=f.readline()

    tpr=phases[2]["alarms"]/phases[2]["length"]
    fpr=(phases[1]["alarms"] + phases[3]["alarms"])/phases[2]["length"]
    print("{:.3f} {:6f} {:6f} {:6f} {:6f}".format(kvalue, phases[1]["alarms"]/phases[1]["length"], tpr, phases[3]["alarms"]/phases[3]["length"], fpr))


