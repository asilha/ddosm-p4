source("analysis.R")

pcap_dir = "~/p4sec/ddosm-p4/pcaps"
pcap_csv_m14 = str_c(pcap_dir,"/n_2_27_m_2_14/if3_attack_out.csv.gz")
packets_m14 = read_pcap_csv(log2n=27, log2m=14, pcap_csv=pcap_csv_m14, attack_only=TRUE) 
