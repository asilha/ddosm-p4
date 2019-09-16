

include ../../../Makefile

BUILD_DIR = ../../../build
SOURCE_DIR = ../../../src

# E01
# PACKET_LIMIT=172032 	
# PACKET_RATE=3072 		
# PCAP_FILE=/media/p4/ddos/datasets/zed/zed20percent-fast.pcap 
# sudo tcpreplay --preload-pcap --quiet --limit=$(PACKET_LIMIT) --pps=$(PACKET_RATE) -i veth0 $(PCAP_FILE) 2>&1

# E02
# PACKET_LIMIT=565248 
# PACKET_RATE=3072 	 
# PCAP_FILE=/media/p4/ddos/datasets/zed/zed20percent-fast.pcap 
# sudo tcpreplay --preload-pcap --quiet --limit=$(PACKET_LIMIT) --pps=$(PACKET_RATE) -i veth0 $(PCAP_FILE) 2>&1

# Alpha

exp_p4damp_10_alpha: 
	$(SS_BIN) --use-files 15 -i 1@if1_workload -i 2@if2_legitimate -i 3@if3_attack -i 4@if4_stats $(BUILD_DIR)/ddosd.json &
	$(SS_CLI) < ../control_rules/control_rules_base.txt
	$(SS_CLI) < ../control_rules/control_rules_m_2_14.txt
	echo "register_write mitigation_t 0 10" | $(SS_CLI) 

exp_p4damp_10_alpha_01: 
	$(SS_BIN) --use-files 15 -i 1@test/if1_workload -i 2@test/if2_legitimate -i 3@test/if3_attack -i 4@test/if4_stats $(BUILD_DIR)/ddosd.json &
	$(SS_CLI) < ../control_rules/control_rules_base.txt
	$(SS_CLI) < ../control_rules/control_rules_m_2_14.txt
	echo "register_write mitigation_t 0 10" | $(SS_CLI) 



