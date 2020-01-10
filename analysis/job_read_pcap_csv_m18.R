source("analysis.R")

pcap_dir = "~/p4sec/ddosm-p4/pcaps"
pcap_csv_m18 = str_c(pcap_dir,"/n_2_27_m_2_18/if3_attack_out.csv.gz")
packets_m18 = read_pcap_csv(log2n=27, log2m=18, pcap_csv=pcap_csv_m18, attack_only=TRUE) 
