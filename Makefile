PROJECT = ddosm
ARCHITECTURE = bmv2

SOURCE_DIR = src
SOURCES = $(wildcard $(SOURCE_DIR)/*.p4)

BUILD_DIR = build
LOG_DIR = logs

P4C = /usr/local/bin/p4c
P4C_FLAGS = -b $(ARCHITECTURE) -I$(SOURCE_DIR)

$(PROJECT): $(SOURCES)
	$(P4C) $(P4C_FLAGS) -o $(BUILD_DIR) $(SOURCE_DIR)/$(PROJECT).p4

SS_PREFIX = /usr/local/bin
SS_BIN = $(SS_PREFIX)/simple_switch --log-level warn
SS_CLI = $(SS_PREFIX)/simple_switch_CLI


SCRIPT_DIR=scripts

LAB_DIR=lab
PCAP_DIR=pcaps
LOAD=if1_workload
GOOD=if2_legitimate
EVIL=if3_attack
STAT=if4_stats


run_plain:	$(PROJECT)
	./$(SCRIPT_DIR)/run_plain.sh

run_without_config:	$(PROJECT)
	./$(SCRIPT_DIR)/run_without_config.sh

clean:
	rm -rf $(BUILD_DIR) $(LOG_DIR) 


INTERFACE_PAIRS=8

veth_start:	
	./$(SCRIPT_DIR)/run_veth.sh setup $(INTERFACE_PAIRS)

veth_stop:
	./$(SCRIPT_DIR)/run_veth.sh delete $(INTERFACE_PAIRS)

TCPREPLAY=sudo nice -19 tcpreplay --preload-pcap --stats=10

PACKET_RATE=8192
PACKET_LIMIT=262144

ddos20m18a_:
	$(SS_CLI) < $(LAB_DIR)/ddos20-full/control_rules/control_rules_base.txt
	$(SS_CLI) < $(LAB_DIR)/ddos20-full/control_rules/control_rules_m_2_18.txt
	echo "register_write mitigation_t 0 10" | $(SS_CLI)
	$(SCRIPT_DIR)/run_capture_to_files.sh start $(PCAP_DIR)/$@
	$(TCPREPLAY) --pps=$(PACKET_RATE) --limit=$(PACKET_LIMIT) -i veth0 $(PCAP_DIR)/$@/$(LOAD)_in.pcap 2>&1
	$(SCRIPT_DIR)/run_capture_to_files.sh stop $(PCAP_DIR)/$@

ddos20m18a:
	$(SS_BIN) --use-files 15 -i 1@$(PCAP_DIR)/$@/$(LOAD) -i 2@$(PCAP_DIR)/$@/$(GOOD) -i 3@$(PCAP_DIR)/$@/$(EVIL) -i 4@$(PCAP_DIR)/$@/$(STAT) $(BUILD_DIR)/ddosm.json &
	sleep 5
	$(SS_CLI) < $(LAB_DIR)/ddos20-full/control_rules/control_rules_base.txt
	$(SS_CLI) < $(LAB_DIR)/ddos20-full/control_rules/control_rules_m_2_18.txt
	# TODO Set the adequate mitigation threshold.
	echo "register_write mitigation_t 0 10" | $(SS_CLI)
	./scripts/monitor.sh $(PCAP_DIR)/$@
	editcap -T ether $(PCAP_DIR)/$@/if2_legitimate_out.pcap $(PCAP_DIR)/$@/if2_legitimate_out.pcapng
	editcap -T ether $(PCAP_DIR)/$@/if3_attack_out.pcap $(PCAP_DIR)/$@/if3_attack_out.pcapng
	editcap -T ether $(PCAP_DIR)/$@/if4_stats_out.pcap $(PCAP_DIR)/$@/if4_stats_out.pcapng
	rm -f $(PCAP_DIR)/$@/*_out.pcap

