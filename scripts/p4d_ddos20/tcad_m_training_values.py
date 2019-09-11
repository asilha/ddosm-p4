#!/usr/bin/python3

paths = {}
paths["tcad_bin"]= "/media/p4/ddosd-cpp/bin"
paths["working_dir"] = "/media/p4/p4damp/datasets/ddos20/ddos20_results"

k_value = "4.250"

ow_field_names = ["timestamp", "src_ent", "src_ewma", "src_ewmmd", "dst_ent", "dst_ewma", "dst_ewmmd", "alarm"]

for m in range(13,19):
    filename = "tcad_m_2_" + str(m) + "_k_" + k_value + ".log"
    print("Trace file:", filename)
    t_exp = 24-m
    t_end_ow = 2**t_exp
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
                print("register_write","ingress.log2_m",0,m)
                print("register_write","ingress.training_len",0,0)
                print("register_write","src_ewma",0,ow_dict["src_ewma"])
                print("register_write","src_ewmmd",0,ow_dict["src_ewmmd"])
                print("register_write","dst_ewma",0,ow_dict["dst_ewma"])
                print("register_write","dst_ewmmd",0,ow_dict["dst_ewmmd"])
                break
            line=f.readline()
