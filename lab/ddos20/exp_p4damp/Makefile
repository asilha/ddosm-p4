

include ../../../Makefile

BUILD_DIR = ../../../build
SOURCE_DIR = ../../../src

# Experiments P4DAMP. 

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

################################################################################
# p4damp_10_beta 

# TCPREPLAY=sudo tcpreplay --quiet
# PACKET_LIMIT=16777216
# PACKET_LIMIT=565248
# PACKET_LIMIT=262144
# PACKET_RATE=4096
# PCAP_FILE=/media/p4/p4damp/datasets/ddos20/ddos20-notraining.pcap
# OUTPUT_DIR=/media/p4/p4damp/pcaps/exp_p4damp_10_beta

exp_p4damp_10_beta: 
	$(SS_BIN) --use-files 15 -i 1@veth0 -i 2@veth2 -i 3@veth4 -i 4@veth6 $(BUILD_DIR)/ddosd.json &
	$(SS_CLI) < ../control_rules/control_rules_base.txt
	$(SS_CLI) < ../control_rules/control_rules_m_2_14.txt
	echo "register_write mitigation_t 0 10" | $(SS_CLI) 
	# ./$(SCRIPT_DIR)/run_capture_to_files.sh start $(OUTPUT_DIR)
	# ssh ilha@10.10.0.1 "$(TCPREPLAY) --limit=$(PACKET_LIMIT) --pps=$(PACKET_RATE) -i enp0s9 $(PCAP_FILE) 2>&1" 
	# ./$(SCRIPT_DIR)/run_capture_to_files.sh stop $(OUTPUT_DIR)