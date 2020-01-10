source("analysis.R")

pcap_dir = "~/p4sec/ddosm-p4/pcaps"
pcap_csv_m16 = str_c(pcap_dir,"/n_2_27_m_2_16/if3_attack_out.csv.gz")
packets_m16 = read_pcap_csv(log2n=27, log2m=16, pcap_csv=pcap_csv_m16, attack_only=TRUE) 
