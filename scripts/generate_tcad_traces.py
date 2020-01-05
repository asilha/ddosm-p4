#!/usr/bin/python3

import argparse
import os

def main():

    parser = argparse.ArgumentParser(description="Submits ee traces to tcad using several levels of k.")
    parser.add_argument("-m", "--log2_m", help="Binary logarithm of OW length")
    parser.add_argument("-t", "--training_length", help="Training length")
    parser.add_argument("-i", "--input_log_file", help="File with ee traces")
    parser.add_argument("-o", "--output_log_path", help="Directory for tcad trace output")
    args = parser.parse_args()

    log2_m = int(args.log2_m)
    training_length = int(args.training_length)
    input_log_file = args.input_log_file
    output_log_path = args.output_log_path
    summary_log = output_log_path + "/summary_m_2_" + str(log2_m) + ".log"   

    tcad_bin = "~/p4sec/ddosd-cpp/bin/tcad"

    with open(summary_log, "w") as f:
        f.write("log2m,k,n,t,p1len,p1alm,p2len,p2alm,p3len,p3alm,tpr,fpr,fpr1,fpr3\n")

    kvalues = []
    for i in range(0,65):    # This goes from 0.000 to 8.000
        kvalues.append(i/8.0)

    for kvalue in kvalues:
        tcad_log = output_log_path + "/tcad_m_2_" + str(log2_m) + "_k_" + "{:.3f}".format(kvalue) +".log"
        tcad_command = tcad_bin + " -t " + str(training_length) + " -s 0.078125 -k " + str(kvalue) 
        command = "cat " + input_log_file + " | " + tcad_command + " > " + tcad_log
        print(command)
        os.system(command)
        phases = []
        phases.append({"start" : 1,                       "length" : training_length,   "alarms" : 0.0})  # phase 0: training
        phases.append({"start" : 1+training_length,       "length" : training_length/2, "alarms" : 0.0})  # phase 1: detection under safety
        phases.append({"start" : 1+3*training_length/2,   "length" : training_length,   "alarms" : 0.0})  # phase 2: detection under attack
        phases.append({"start" : 1+5*training_length/2,   "length" : training_length/2, "alarms" : 0.0})  # phase 3: detection under safety
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
                f.write("{},{:.3f},{},{},{},{},{},{},{},{},{:.3f},{:.3f},{:.3f},{:.3f}\n".format(
                    log2_m,kvalue,count,training_length,
                    phases[1]["length"],phases[1]["alarms"],
                    phases[2]["length"],phases[2]["alarms"],
                    phases[3]["length"],phases[3]["alarms"],
                    tpr,fpr,fpr1,fpr3))


if __name__ == '__main__':
    main()




