#!/usr/bin/python3

import argparse
import os

def main():

    parser = argparse.ArgumentParser(description="Generates preinit control rules.")
    parser.add_argument("-m", "--log2_m", help="Binary logarithm of OW length")
    parser.add_argument("-t", "--training_length", help="Training length")
    parser.add_argument("-k", "--sensitivity_coefficient", help="Sensitivity coefficient")
    parser.add_argument("-i", "--input_log_file", help="File with tcad traces")
    parser.add_argument("-o", "--output_rule_dir", help="Directory for rule output")
    args = parser.parse_args()

    log2_m = int(args.log2_m)
    training_length = int(args.training_length)
    sensitivity_coefficient = float(args.sensitivity_coefficient)
    input_log_file = args.input_log_file
    output_rule_dir = args.output_rule_dir

    ow_field_names = ["timestamp", "src_ent", "src_ewma", "src_ewmmd", "dst_ent", "dst_ewma", "dst_ewmmd", "alarm"]
 
    with open(input_log_file) as f: 
        line_num = 0
        line=f.readline()
        while line:
            line_num += 1
            if line_num == training_length:
                ow_field_values = line.split()
                ow_dict = dict(zip(ow_field_names,ow_field_values))
                break
            line=f.readline()

    output_rule_file = output_rule_dir + "control_rules_m_2_" + str(log2_m) + ".txt"
    print("Rule file:", output_rule_file)

    with open(output_rule_file, "w") as f:
        f.write("register_write ingress.log2_m 0 " 		+ str(log2_m) + "\n")
        f.write("register_write ingress.training_len 0 "	+ str(0) + "\n")  # TODO Parameterize?
        f.write("register_write ingress.alpha 0 " 		+ str(20) + "\n") # TODO Parameterize?
        f.write("register_write ingress.k 0 "			+ str(int(sensitivity_coefficient * 8)) + "\n")
        f.write("register_write src_ewma 0 " 			+ ow_dict["src_ewma"] + "\n")
        f.write("register_write src_ewmmd 0 " 			+ ow_dict["src_ewmmd"] + "\n")
        f.write("register_write dst_ewma 0 " 			+ ow_dict["dst_ewma"] + "\n")
        f.write("register_write dst_ewmmd 0 " 			+ ow_dict["dst_ewmmd"] + "\n")
        f.write("register_write mitigation_t 0 " 		+ str(10) + "\n") # TODO Parameterize? 

if __name__ == '__main__':
    main()
