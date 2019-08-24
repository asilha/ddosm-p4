from dataclasses import dataclass

import os

@dataclass
class PCAPSample:
    ow_first: int = 0
    ow_last:  int = 0
    ow_size:  int = 0
    base_path: str = ""
    base_name: str = ""

def get_base_path_name(base_path, base_name):
    return base_path + "/" + base_name

def get_input_name(base_path_name):
    return base_path_name

def get_output_name(base_path_name, ow, packet_first, packet_last):
    return base_path_name + "-" + str(ow) + "-" + str(packet_first) + "-" + str(packet_last)

def get_editcap_command(input_name, output_name, packet_first, packet_last):
    
    assert os.path.isfile(input_name + ".pcap")
    # assert not os.path.isfile(output_name + ".pcap")

    return "editcap -r " + input_name + ".pcap " + output_name + ".pcap " + str(packet_first) + "-" + str(packet_last)

def get_tshark_command(output_name):

    assert os.path.isfile(output_name + ".pcap")
    # assert not os.path.isfile(output_name + ".csv")

    return "tshark -r " + output_name + ".pcap -T fields -e ip.src -e ip.dst -e data.data -E separator=, > " + output_name + ".csv"

def main():

    sample = PCAPSample()
    sample.ow_first = 189
    sample.ow_last = 196
    sample.ow_size = 8192
    sample.base_path = "D:/downloads/p4/ddos/datasets/zed"
    sample.base_name = "zed20percent"

    assert sample.ow_first > 0
    assert sample.ow_last > 0
    assert sample.ow_last >= sample.ow_first
    assert sample.ow_size > 0

    for ow in range(sample.ow_first, sample.ow_last):
        packet_first = sample.ow_size * (ow - 1) + 1  
        packet_last  = packet_first + sample.ow_size - 1
        assert packet_last - packet_first + 1 == sample.ow_size
        
        base_path_name = get_base_path_name(sample.base_path, sample.base_name)
        input_name = get_input_name(base_path_name)
        output_name = get_output_name(base_path_name, ow, packet_first, packet_last)
        
        command = get_editcap_command(input_name, output_name, packet_first, packet_last)
        print(command)
        os.system(command)
        
        command = get_tshark_command(output_name) 
        print(command)
        os.system(command)

if __name__ == '__main__':
    main()

