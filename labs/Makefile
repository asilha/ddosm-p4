include ../Makefile

# TODO Add targets to create the pcaps directory structure.
# TODO Move these targets to the main Makefile. 

BUILD_DIR = ../build
SOURCE_DIR = ../src
PCAP_DIR = ../pcaps
SCRIPT_DIR = ../scripts
LOAD = if1_workload
GOOD = if2_legitimate 
EVIL = if3_attack
STAT = if4_stats

kill.switch:
	sudo killall -w simple_switch

# if1_workload_in points to /datasets/synthetic-ilha/ddos20-notraining.pcap

ddos20m14a: 
	$(SS_BIN) --use-files 15 -i 1@$(PCAP_DIR)/$@/$(LOAD) -i 2@$(PCAP_DIR)/$@/$(GOOD) -i 3@$(PCAP_DIR)/$@/$(EVIL) -i 4@$(PCAP_DIR)/$@/$(STAT) $(BUILD_DIR)/ddosm.json &
	sleep 5 
	$(SS_CLI) < ddos20/control_rules/control_rules_base.txt
	$(SS_CLI) < ddos20/control_rules/control_rules_m_2_14.txt
	# TODO Set the adequate mitigation threshold.
	echo "register_write mitigation_t 0 10" | $(SS_CLI) 
	../scripts/monitor.sh $(PCAP_DIR)/$@
	editcap -T ether ../pcaps/$@/if2_legitimate_out.pcap ../pcaps/$@/if2_legitimate_out.pcapng
	editcap -T ether ../pcaps/$@/if3_attack_out.pcap ../pcaps/$@/if3_attack_out.pcapng
	editcap -T ether ../pcaps/$@/if4_stats_out.pcap ../pcaps/$@/if4_stats_out.pcapng
	rm -f $(PCAP_DIR)/$@/*_out.pcap


ddos20m14b: 
	$(SS_BIN) --use-files 15 -i 1@$(PCAP_DIR)/$@/$(LOAD) -i 2@$(PCAP_DIR)/$@/$(GOOD) -i 3@$(PCAP_DIR)/$@/$(EVIL) -i 4@$(PCAP_DIR)/$@/$(STAT) $(BUILD_DIR)/ddosm.json &
	sleep 5 
	$(SS_CLI) < ddos20/control_rules/control_rules_base.txt
	$(SS_CLI) < ddos20/control_rules/control_rules_m_2_14.txt
	# TODO Set the adequate mitigation threshold.
	echo "register_write mitigation_t 0 10" | $(SS_CLI) 
	../scripts/monitor.sh $(PCAP_DIR)/$@
	editcap -T ether ../pcaps/$@/if2_legitimate_out.pcap ../pcaps/$@/if2_legitimate_out.pcapng
	editcap -T ether ../pcaps/$@/if3_attack_out.pcap ../pcaps/$@/if3_attack_out.pcapng
	editcap -T ether ../pcaps/$@/if4_stats_out.pcap ../pcaps/$@/if4_stats_out.pcapng
	rm -f $(PCAP_DIR)/$@/*_out.pcap

ddos20m16a: 
	$(SS_BIN) --use-files 15 -i 1@$(PCAP_DIR)/$@/$(LOAD) -i 2@$(PCAP_DIR)/$@/$(GOOD) -i 3@$(PCAP_DIR)/$@/$(EVIL) -i 4@$(PCAP_DIR)/$@/$(STAT) $(BUILD_DIR)/ddosm.json &
	sleep 5 
	$(SS_CLI) < ddos20/control_rules/control_rules_base.txt
	$(SS_CLI) < ddos20/control_rules/control_rules_m_2_16.txt
	# TODO Set the adequate mitigation threshold.
	echo "register_write mitigation_t 0 10" | $(SS_CLI) 
	../scripts/monitor.sh $(PCAP_DIR)/$@
	editcap -T ether ../pcaps/$@/if2_legitimate_out.pcap ../pcaps/$@/if2_legitimate_out.pcapng
	editcap -T ether ../pcaps/$@/if3_attack_out.pcap ../pcaps/$@/if3_attack_out.pcapng
	editcap -T ether ../pcaps/$@/if4_stats_out.pcap ../pcaps/$@/if4_stats_out.pcapng
	rm -f $(PCAP_DIR)/$@/*_out.pcap

ddos20m16b: 
	$(SS_BIN) --use-files 15 -i 1@$(PCAP_DIR)/$@/$(LOAD) -i 2@$(PCAP_DIR)/$@/$(GOOD) -i 3@$(PCAP_DIR)/$@/$(EVIL) -i 4@$(PCAP_DIR)/$@/$(STAT) $(BUILD_DIR)/ddosm.json &
	sleep 5 
	$(SS_CLI) < ddos20/control_rules/control_rules_base.txt
	$(SS_CLI) < ddos20/control_rules/control_rules_m_2_16.txt
	# TODO Set the adequate mitigation threshold.
	echo "register_write mitigation_t 0 10" | $(SS_CLI) 
	../scripts/monitor.sh $(PCAP_DIR)/$@
	editcap -T ether ../pcaps/$@/if2_legitimate_out.pcap ../pcaps/$@/if2_legitimate_out.pcapng
	editcap -T ether ../pcaps/$@/if3_attack_out.pcap ../pcaps/$@/if3_attack_out.pcapng
	editcap -T ether ../pcaps/$@/if4_stats_out.pcap ../pcaps/$@/if4_stats_out.pcapng
	rm -f $(PCAP_DIR)/$@/*_out.pcap

ddos20m18a: 
	$(SS_BIN) --use-files 15 -i 1@$(PCAP_DIR)/$@/$(LOAD) -i 2@$(PCAP_DIR)/$@/$(GOOD) -i 3@$(PCAP_DIR)/$@/$(EVIL) -i 4@$(PCAP_DIR)/$@/$(STAT) $(BUILD_DIR)/ddosm.json &
	sleep 5 
	$(SS_CLI) < ddos20-full/control_rules/control_rules_base.txt
	$(SS_CLI) < ddos20-full/control_rules/control_rules_m_2_18.txt
	# TODO Set the adequate mitigation threshold.
	echo "register_write mitigation_t 0 10" | $(SS_CLI) 
	../scripts/monitor.sh $(PCAP_DIR)/$@
	editcap -T ether ../pcaps/$@/if2_legitimate_out.pcap ../pcaps/$@/if2_legitimate_out.pcapng
	editcap -T ether ../pcaps/$@/if3_attack_out.pcap ../pcaps/$@/if3_attack_out.pcapng
	editcap -T ether ../pcaps/$@/if4_stats_out.pcap ../pcaps/$@/if4_stats_out.pcapng
	rm -f $(PCAP_DIR)/$@/*_out.pcap

ddos20m18b: 
	$(SS_BIN) --use-files 15 -i 1@$(PCAP_DIR)/$@/$(LOAD) -i 2@$(PCAP_DIR)/$@/$(GOOD) -i 3@$(PCAP_DIR)/$@/$(EVIL) -i 4@$(PCAP_DIR)/$@/$(STAT) $(BUILD_DIR)/ddosm.json &
	sleep 5 
	$(SS_CLI) < ddos20/control_rules/control_rules_base.txt
	$(SS_CLI) < ddos20/control_rules/control_rules_m_2_18.txt
	# TODO Set the adequate mitigation threshold.
	echo "register_write mitigation_t 0 10" | $(SS_CLI) 
	../scripts/monitor.sh $(PCAP_DIR)/$@
	editcap -T ether ../pcaps/$@/if2_legitimate_out.pcap ../pcaps/$@/if2_legitimate_out.pcapng
	editcap -T ether ../pcaps/$@/if3_attack_out.pcap ../pcaps/$@/if3_attack_out.pcapng
	editcap -T ether ../pcaps/$@/if4_stats_out.pcap ../pcaps/$@/if4_stats_out.pcapng
	rm -f $(PCAP_DIR)/$@/*_out.pcap

# if1_workload_in should point to /datasets/synthetic-ilha/ddos20-attack.pcap (which should contain only the attack part). 

tmp: 
	$(SS_BIN) --use-files 15 -i 1@$(PCAP_DIR)/$@/$(LOAD) -i 2@$(PCAP_DIR)/$@/$(GOOD) -i 3@$(PCAP_DIR)/$@/$(EVIL) -i 4@$(PCAP_DIR)/$@/$(STAT) $(BUILD_DIR)/ddosm.json &
	sleep 5
	$(SS_CLI) < ddos20/control_rules/control_rules_base.txt
	$(SS_CLI) < ddos20d/control_rules/control_rules_m18.txt
	# TODO Set the adequate mitigation threshold.
	echo "register_write mitigation_t 0 10" | $(SS_CLI)
	../scripts/monitor.sh $(PCAP_DIR)/$@
	editcap -T ether ../pcaps/$@/if2_legitimate_out.pcap ../pcaps/$@/if2_legitimate_out.pcapng
	editcap -T ether ../pcaps/$@/if3_attack_out.pcap ../pcaps/$@/if3_attack_out.pcapng
	editcap -T ether ../pcaps/$@/if4_stats_out.pcap ../pcaps/$@/if4_stats_out.pcapng
	rm -f $(PCAP_DIR)/$@/*_out.pcap

