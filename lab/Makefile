include ../Makefile

BUILD_DIR = ../build
SOURCE_DIR = ../src
PCAP_DIR = ../pcaps
LOAD = if1_workload
GOOD = if2_legitimate 
EVIL = if3_attack
STAT = if4_stats

kill.switch:
	sudo killall -w lt-simple_switch

# /pcaps/ddos20/if1_workload_in is /datasets/synthetic-ilha/ddos20-notraining.pcap

ddos20: 
	$(SS_BIN) --use-files 15 -i 1@$(PCAP_DIR)/$@/$(LOAD) -i 2@$(PCAP_DIR)/$@/$(GOOD) -i 3@$(PCAP_DIR)/$@/$(EVIL) -i 4@$(PCAP_DIR)/$@/$(STAT) $(BUILD_DIR)/ddosm.json &
	$(SS_CLI) < $@/control_rules/control_rules_base.txt
	$(SS_CLI) < $@/control_rules/control_rules_m_2_14.txt
	echo "register_write mitigation_t 0 10" | $(SS_CLI) 

# pcaps/exp/if1_workload_in is /datasets/zed/zed20percent-fast.pcap

exp: 
	rm -f $(PCAP_DIR)/$@/*_out.pcap
	$(SS_BIN) --use-files 15 -i 1@$(PCAP_DIR)/$@/$(LOAD) -i 2@$(PCAP_DIR)/$@/$(GOOD) -i 3@$(PCAP_DIR)/$@/$(EVIL) -i 4@$(PCAP_DIR)/$@/$(STAT) $(BUILD_DIR)/ddosm.json &
	sleep 5
	$(SS_CLI) < zed/control_rules/control_rules_base.txt
	$(SS_CLI) < zed/control_rules/control_rules_zed.txt
	echo "register_write mitigation_t 0 10" | $(SS_CLI)
	../scripts/monitor.sh $(PCAP_DIR)/$@
	editcap -T ether ../pcaps/exp/if2_legitimate_out.pcap ../pcaps/exp/if2_legitimate_out.pcapng
	editcap -T ether ../pcaps/exp/if3_attack_out.pcap ../pcaps/exp/if3_attack_out.pcapng
	editcap -T ether ../pcaps/exp/if4_stats_out.pcap ../pcaps/exp/if4_stats_out.pcapng

# /pcaps/zed/if1_workload_in is /datasets/zed/zed20percent-fast.pcap

zed: 
	rm -f $(PCAP_DIR)/$@/*_out.pcap
	$(SS_BIN) --use-files 15 -i 1@$(PCAP_DIR)/$@/$(LOAD) -i 2@$(PCAP_DIR)/$@/$(GOOD) -i 3@$(PCAP_DIR)/$@/$(EVIL) -i 4@$(PCAP_DIR)/$@/$(STAT) $(BUILD_DIR)/ddosm.json &
	sleep 5 
	$(SS_CLI) < $@/control_rules/control_rules_base.txt
	$(SS_CLI) < $@/control_rules/control_rules_zed.txt
	echo "register_write mitigation_t 0 10" | $(SS_CLI) 
	../scripts/monitor.sh $(PCAP_DIR)/$@
	editcap -T ether ../pcaps/zed/if2_legitimate_out.pcap ../pcaps/zed/if2_legitimate_out.pcapng
	editcap -T ether ../pcaps/zed/if3_attack_out.pcap ../pcaps/zed/if3_attack_out.pcapng
	editcap -T ether ../pcaps/zed/if4_stats_out.pcap ../pcaps/zed/if4_stats_out.pcapng




# Experiments X, Y, Z. 

# PACKET_LIMIT=131072
# PACKET_RATE=2048

# PCAP_FILE=/media/p4/ddos/datasets/sample/ddos5y0.pcap			
# PCAP_FILE=/media/p4/ddos/datasets/zed/zed20percent.pcap
# PCAP_FILE=/media/p4/ddos/datasets/zed/zed20percent-notraining.pcap

################################################################################
# zed_10 

# TCPREPLAY=sudo tcpreplay --preload-pcap --quiet
# PACKET_LIMIT=565248
# PACKET_RATE=3072
# PCAP_FILE=/media/p4/p4damp/datasets/zed/zed20percent-fast.pcap
# OUTPUT_DIR=/media/p4/p4damp/pcaps/exp_zed_10

# exp_zed_10:
# 	$(SS_CLI) < /media/p4/ddosd-p4/scripts/p4d_ddos20/control_rules_base.txt
# 	$(SS_CLI) < /media/p4/ddosd-p4/scripts/p4d_ddos20/control_rules_zed.txt
# 	echo "register_write mitigation_t 0 10" | $(SS_CLI) 
# 	./$(SCRIPT_DIR)/run_capture_to_files.sh start $(OUTPUT_DIR)
# 	$(TCPREPLAY) --limit=$(PACKET_LIMIT) --pps=$(PACKET_RATE) --pps-multi=16 -i veth0 $(PCAP_FILE) 2>&1
# 	./$(SCRIPT_DIR)/run_capture_to_files.sh stop $(OUTPUT_DIR)
