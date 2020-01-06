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

    print(args)

    log2_m = int(args.log2_m)
    training_length = int(args.training_length)
    sensitivity_coefficient = float(args.sensitivity_coefficient)
    input_log_file = args.input_log_file
    output_rule_dir = args.output_rule_dir

    ow_field_names = ["timestamp", "src_ent", "src_ewma", "src_ewmmd", "dst_ent", "dst_ewma", "dst_ewmmd", "alarm"]

    # print("Last training OW:", training_length)
 
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
        print("register_write", "ingress.log2_m",       0, log2_m)
        print("register_write", "ingress.training_len", 0, 0)
        print("register_write", "ingress.alpha",        0, 20)
        print("register_write", "ingress.k",            0, int(sensitivity_coefficient * 8))
        print("register_write", "src_ewma",             0, ow_dict["src_ewma"])
        print("register_write", "src_ewmmd",            0, ow_dict["src_ewmmd"])
        print("register_write", "dst_ewma",             0, ow_dict["dst_ewma"])
        print("register_write", "dst_ewmmd",            0, ow_dict["dst_ewmmd"])
        print("register_write", "mitigation_t",          0, 10)


if __name__ == '__main__':
    main()