from dataclasses import dataclass

import os

@dataclass
class PCAPSample:
    ow_first: int = 0
    ow_last:  int = 0
    ow_size:  int = 0
    pcap_path: str = ""
    pcap_name: str = ""

def get_editcap_command(pcap_path, pcap_name, ow, packet_first, packet_last):
    
    pcap_in_path_name = pcap_path+"/"+pcap_name+".pcap"
    assert os.path.isfile(pcap_in_path_name)
    pcap_out_path_name = pcap_path + "/" + pcap_name + "-" + str(ow) + "-" + str(packet_first) + "-" + str(packet_last) + ".pcap"
    assert not os.path.isfile(pcap_out_path_name)

    return "editcap -r " + pcap_in_path_name + " " + pcap_out_path_name + " " + str(packet_first) + "-" + str(packet_last)

def main():

    sample = PCAPSample()
    sample.ow_first = 189
    sample.ow_last = 196
    sample.ow_size = 8192
    sample.pcap_path = "D:/downloads/p4/ddos/datasets/zed"
    sample.pcap_name = "zed20percent"

    assert sample.ow_first > 0
    assert sample.ow_last > 0
    assert sample.ow_last >= sample.ow_first
    assert sample.ow_size > 0

    for i in range(sample.ow_first, sample.ow_last):
        packet_first = sample.ow_size * (i - 1) + 1  
        packet_last  = packet_first + sample.ow_size - 1
        assert packet_last - packet_first + 1 == sample.ow_size
        command = get_editcap_command(sample.pcap_path, sample.pcap_name, i, packet_first, packet_last)
        # print(command)
        os.system(command)    

if __name__ == '__main__':
    main()

