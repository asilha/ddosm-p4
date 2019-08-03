#!/usr/bin/python3

import os

phases = []
phases.append({"start" : 1,     "length" : 512.0, "alarms" : 0.0})  # phase 0: training
phases.append({"start" : 513,   "length" : 256.0, "alarms" : 0.0})  # phase 1: detection under safety
phases.append({"start" : 769,   "length" : 512.0, "alarms" : 0.0})  # phase 2: detection under attack
phases.append({"start" : 1281,  "length" : 256.0, "alarms" : 0.0})  # phase 3: detection under safety

kvalues = []

for i in range(40,5,-1):    # This goes from 5.00 down to 0.75
    kvalues.append(i/8.0)


for kvalue in kvalues:
    filename="ddos5z5-{:.3f}.tcad.txt".format(kvalue)
    command="./ddosd-cpp/bin/ee -c ./ddosd-cpp/example/ddos5z1.json ./ddos/datasets/zed/zed20percent.pcap | ./ddosd-cpp/bin/tcad -t 512 -s 0.078125 -k {:f} > {}".format(kvalue,filename)
    os.system(command)

# quit()

for kvalue in kvalues:
    filename="ddos5z5-{:.3f}.tcad.txt".format(kvalue)
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


