#!/usr/bin/python3

paths = {}
paths["tcad_bin"]= "~/p4sec/ddosd-cpp/bin"
paths["working_dir"] = "/home/ilha/p4sec/ddosm-p4/lab/ddos20-full/tcad_logs"

k_values = {}
k_values[13] = 4.000
k_values[14] = 4.125
k_values[15] = 4.250
k_values[16] = 4.500
k_values[17] = 4.750 	
k_values[18] = 3.625

ow_field_names = ["timestamp", "src_ent", "src_ewma", "src_ewmmd", "dst_ent", "dst_ewma", "dst_ewmmd", "alarm"]

for m in range(18,19,1):
    filename = "tcad_m_2_" + str(m) + "_k_" + "{:.3f}".format(k_values[m]) + ".log"
    print("Trace file:", filename)
    #t_exp = 24-m
    t_end_ow = 250 # 2**t_exp
    print("Last training OW:", t_end_ow)
    with open(paths["working_dir"] + "/" + filename) as f: 
        line_num = 0
        line=f.readline()
        while line:
            line_num += 1
            if line_num == t_end_ow:
                ow_field_values = line.split()
                ow_dict = dict(zip(ow_field_names,ow_field_values))
                #  print(ow_dict)
                print("register_write", "ingress.log2_m",       0, m)
                print("register_write", "ingress.training_len", 0, 0)
                print("register_write", "ingress.alpha",        0, 20)
                print("register_write", "ingress.k",            0, int(k_values[m] * 8))
                print("register_write", "src_ewma",             0, ow_dict["src_ewma"])
                print("register_write", "src_ewmmd",            0, ow_dict["src_ewmmd"])
                print("register_write", "dst_ewma",             0, ow_dict["dst_ewma"])
                print("register_write", "dst_ewmmd",            0, ow_dict["dst_ewmmd"])
                print("register_write", "migration_t",          0, 10)
                break
            line=f.readline()
