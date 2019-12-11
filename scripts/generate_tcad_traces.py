#!/usr/bin/python3

import os

kvalues = []
for i in range(0,65):    # This goes from 0.000 to 8.000
    kvalues.append(i/8.0)

mvalues = []
for i in range(13,19):  # This goes from 13 to 18.
    mvalues.append(i)

training_packets_log2_n = 23

paths = {}
paths["tcad_bin"]= "/media/p4/ddosd-cpp/bin"
paths["working_dir"] = "/media/p4/p4damp/datasets/ddos20/ddos20_results"

summary_log = paths["working_dir"]+"/summary.log"   

with open(summary_log, "w") as f:
    f.write("log2m,k,n,t,p1len,p1alm,p2len,p2alm,p3len,p3alm,tpr,fpr,fpr1,fpr3\n")

for mvalue in mvalues:
    ee_log = paths["working_dir"]+"/ee_m_2_"+str(mvalue)+".log"
    # print(ee_log)
     
    training_length = 2 ** (training_packets_log2_n - mvalue)
    for kvalue in kvalues:
        tcad_log = paths["working_dir"]+"/tcad_m_2_"+str(mvalue)+"_k_"+ "{:.3f}".format(kvalue) +".log"
        # print(tcad_log) 
        tcad_command = paths["tcad_bin"] + "/tcad -t " + str(training_length) + " -s 0.078125 -k " + str(kvalue) 
        # print(tcad_command)
        command = "cat " + ee_log + " | " + tcad_command + " > " + tcad_log
        print(command)
        os.system(command)
        phases = []
        phases.append({"start" : 1,                       "length" : training_length,   "alarms" : 0.0})  # phase 0: training
        phases.append({"start" : 1+training_length,       "length" : training_length/2, "alarms" : 0.0})  # phase 1: detection under safety
        phases.append({"start" : 1+3*training_length/2,   "length" : training_length,   "alarms" : 0.0})  # phase 2: detection under attack
        phases.append({"start" : 1+5*training_length/2,   "length" : training_length/2, "alarms" : 0.0})  # phase 3: detection under safety
        # print(phases)    
        with open(tcad_log) as f:
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
            fpr1=phases[1]["alarms"]/phases[1]["length"]
            fpr3=phases[3]["alarms"]/phases[3]["length"]
            fpr=(phases[1]["alarms"] + phases[3]["alarms"])/phases[2]["length"]
            with open(summary_log,"a") as f:
              # f.write("log2m,k,n,t,p1len,p1alm,p2len,p2alm,p3len,p3alm,tpr,fpr,fpr1,fpr3\n")
                f.write("{},{:.3f},{},{},{},{},{},{},{},{},{:.3f},{:.3f},{:.3f},{:.3f}\n".format(
                    mvalue,kvalue,count,training_length,
                    phases[1]["length"],phases[1]["alarms"],
                    phases[2]["length"],phases[2]["alarms"],
                    phases[3]["length"],phases[3]["alarms"],
                    tpr,fpr,fpr1,fpr3))






