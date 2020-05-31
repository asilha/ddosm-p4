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
SS_BIN = $(SS_PREFIX)/simple_switch --log-level off
SS_CLI = $(SS_PREFIX)/simple_switch_CLI

CPP_TOOLS_DIR = ~/p4sec/ddosd-cpp/bin/
EE_BIN = $(CPP_TOOLS_DIR)/ee

SCRIPT_DIR=scripts
WORKLOAD_DIR=workloads

LAB_DIR=labs
PCAP_DIR=pcaps
LOAD=if1_workload
GOOD=if2_legitimate
EVIL=if3_attack
STAT=if4_stats

clean:
	rm -rf $(BUILD_DIR) $(LOG_DIR) 

workload_dirs:
	mkdir -p $(WORKLOAD_DIR)/synthetic/a_0.200/n_2_24/
	mkdir -p $(WORKLOAD_DIR)/synthetic/a_0.200/n_2_27/

# ------------------------------------------
# Experiments using the 16-Mpacket workload
# Attack proportion: 20%.

workload_n_2_24_capinfos:
	capinfos -m workloads/synthetic/a_0.200/n_2_24/complete.pcap > workloads/synthetic/a_0.200/n_2_24/complete.txt

workload_n_2_24_detection: 
	editcap -r  $(WORKLOAD_DIR)/synthetic/a_0.200/n_2_24/complete.pcap $(WORKLOAD_DIR)/synthetic/a_0.200/n_2_24/detection.pcap 8388609-25165824	# DDoS Mitigation.ipynb
	capinfos -m $(WORKLOAD_DIR)/synthetic/a_0.200/n_2_24/detection.pcap > $(WORKLOAD_DIR)/synthetic/a_0.200/n_2_24/detection.txt 	

ee_n_2_24:
	$(EE_BIN) -c labs/ddos20_short/ee_json/ee_m_2_14.json workloads/synthetic/a_0.200/n_2_24/complete.pcap > /tmp/ee_m_2_14.log
	mv -f /tmp/ee_m_2_14.log labs/ddos20_short/ee_logs/ 
	$(EE_BIN) -c labs/ddos20_short/ee_json/ee_m_2_16.json workloads/synthetic/a_0.200/n_2_24/complete.pcap > /tmp/ee_m_2_16.log
	mv -f /tmp/ee_m_2_16.log labs/ddos20_short/ee_logs/ 
	$(EE_BIN) -c labs/ddos20_short/ee_json/ee_m_2_18.json workloads/synthetic/a_0.200/n_2_24/complete.pcap > /tmp/ee_m_2_18.log
	mv -f /tmp/ee_m_2_18.log labs/ddos20_short/ee_logs/

tcad_n_2_24:
	rm -f labs/ddos20_short/tcad_logs/*.log
	scripts/generate_tcad_traces.py -m 14 -t 512 -i labs/ddos20_short/ee_logs/ee_m_2_14.log -o labs/ddos20_short/tcad_logs/
	scripts/generate_tcad_traces.py -m 16 -t 128 -i labs/ddos20_short/ee_logs/ee_m_2_16.log -o labs/ddos20_short/tcad_logs/
	scripts/generate_tcad_traces.py -m 18 -t 32 -i labs/ddos20_short/ee_logs/ee_m_2_18.log -o labs/ddos20_short/tcad_logs/

# Status: OK!  Are control_rules_m_2_14, tcad_m_2_14_k_4.125.log, and stats.txt consistent? Yes.
n_2_24_m_2_14:
	$(SS_BIN) --use-files 15 -i 1@$(PCAP_DIR)/$@/$(LOAD) -i 2@$(PCAP_DIR)/$@/$(GOOD) -i 3@$(PCAP_DIR)/$@/$(EVIL) -i 4@$(PCAP_DIR)/$@/$(STAT) $(BUILD_DIR)/ddosm.json &
	sleep 5
	$(SS_CLI) < $(LAB_DIR)/ddos20_short/control_rules/control_rules_base.txt
	$(SS_CLI) < $(LAB_DIR)/ddos20_short/control_rules/control_rules_m_2_14.txt
	# TODO Set the adequate mitigation threshold.
	echo "register_write mitigation_t 0 10" | $(SS_CLI)
	./scripts/monitor.sh $(PCAP_DIR)/$@
	editcap -T ether $(PCAP_DIR)/$@/if2_legitimate_out.pcap $(PCAP_DIR)/$@/if2_legitimate_out.pcapng
	editcap -T ether $(PCAP_DIR)/$@/if3_attack_out.pcap $(PCAP_DIR)/$@/if3_attack_out.pcapng
	editcap -T ether $(PCAP_DIR)/$@/if4_stats_out.pcap $(PCAP_DIR)/$@/if4_stats_out.pcapng
	rm -f $(PCAP_DIR)/$@/*_out.pcap
	~/p4sec/ddosd-cpp/bin/ercnv $(PCAP_DIR)/$@/if4_stats_out.pcapng > $(PCAP_DIR)/$@/stats.txt

# Status: OK! Are control_rules_m_2_16, tcad_m_2_16_k_4.500.log, and stats.txt consistent? Yes.
n_2_24_m_2_16:
	$(SS_BIN) --use-files 15 -i 1@$(PCAP_DIR)/$@/$(LOAD) -i 2@$(PCAP_DIR)/$@/$(GOOD) -i 3@$(PCAP_DIR)/$@/$(EVIL) -i 4@$(PCAP_DIR)/$@/$(STAT) $(BUILD_DIR)/ddosm.json &
	sleep 5
	$(SS_CLI) < $(LAB_DIR)/ddos20_short/control_rules/control_rules_base.txt
	$(SS_CLI) < $(LAB_DIR)/ddos20_short/control_rules/control_rules_m_2_16.txt
	# TODO Set the adequate mitigation threshold.
	echo "register_write mitigation_t 0 10" | $(SS_CLI)
	./scripts/monitor.sh $(PCAP_DIR)/$@
	editcap -T ether $(PCAP_DIR)/$@/if2_legitimate_out.pcap $(PCAP_DIR)/$@/if2_legitimate_out.pcapng
	editcap -T ether $(PCAP_DIR)/$@/if3_attack_out.pcap $(PCAP_DIR)/$@/if3_attack_out.pcapng
	editcap -T ether $(PCAP_DIR)/$@/if4_stats_out.pcap $(PCAP_DIR)/$@/if4_stats_out.pcapng
	rm -f $(PCAP_DIR)/$@/*_out.pcap
	~/p4sec/ddosd-cpp/bin/ercnv $(PCAP_DIR)/$@/if4_stats_out.pcapng > $(PCAP_DIR)/$@/stats.txt

# Status: OK!  Are control_rules_m_2_18, tcad_m_2_18_k_3.625.log, and stats.txt consistent? Yes.
n_2_24_m_2_18:
	$(SS_BIN) --use-files 15 -i 1@$(PCAP_DIR)/$@/$(LOAD) -i 2@$(PCAP_DIR)/$@/$(GOOD) -i 3@$(PCAP_DIR)/$@/$(EVIL) -i 4@$(PCAP_DIR)/$@/$(STAT) $(BUILD_DIR)/ddosm.json &
	sleep 5
	$(SS_CLI) < $(LAB_DIR)/ddos20_short/control_rules/control_rules_base.txt
	$(SS_CLI) < $(LAB_DIR)/ddos20_short/control_rules/control_rules_m_2_18.txt
	# TODO Set the adequate mitigation threshold.
	echo "register_write mitigation_t 0 10" | $(SS_CLI)
	./scripts/monitor.sh $(PCAP_DIR)/$@
	editcap -T ether $(PCAP_DIR)/$@/if2_legitimate_out.pcap $(PCAP_DIR)/$@/if2_legitimate_out.pcapng
	editcap -T ether $(PCAP_DIR)/$@/if3_attack_out.pcap $(PCAP_DIR)/$@/if3_attack_out.pcapng
	editcap -T ether $(PCAP_DIR)/$@/if4_stats_out.pcap $(PCAP_DIR)/$@/if4_stats_out.pcapng
	rm -f $(PCAP_DIR)/$@/*_out.pcap
	~/p4sec/ddosd-cpp/bin/ercnv $(PCAP_DIR)/$@/if4_stats_out.pcapng > $(PCAP_DIR)/$@/stats.txt

n_2_24_copy_logs:
	cp pcaps/n_2_24_m_2_14/stats.txt labs/ddos20_short/n_2_24_m_2_14.stats.txt
	cp pcaps/n_2_24_m_2_16/stats.txt labs/ddos20_short/n_2_24_m_2_16.stats.txt
	cp pcaps/n_2_24_m_2_18/stats.txt labs/ddos20_short/n_2_24_m_2_18.stats.txt

n_2_24_generate_csv:
	scripts/pcap_to_csv.py -i pcaps/n_2_24_m_2_14/if3_attack_out.pcapng -o pcaps/n_2_24_m_2_14/if3_attack_out.csv.gz &
	scripts/pcap_to_csv.py -i pcaps/n_2_24_m_2_16/if3_attack_out.pcapng -o pcaps/n_2_24_m_2_16/if3_attack_out.csv.gz & 	
	scripts/pcap_to_csv.py -i pcaps/n_2_24_m_2_18/if3_attack_out.pcapng -o pcaps/n_2_24_m_2_18/if3_attack_out.csv.gz &

# ------------------------------------------
# Experiments using the 128-Mpacket workload
# Attack proportion: 20%.

workload_n_2_27_capinfos:
	capinfos -m workloads/synthetic/a_0.200/n_2_27/complete.pcap > workloads/synthetic/a_0.200/n_2_27/complete.txt

workload_n_2_27_detection: 
	editcap -r  $(WORKLOAD_DIR)/synthetic/a_0.200/n_2_27/complete.pcap $(WORKLOAD_DIR)/synthetic/a_0.200/n_2_27/detection.pcap 65536001-196608000 	# TNSM 2020.ipynb
	capinfos -m $(WORKLOAD_DIR)/synthetic/a_0.200/n_2_27/detection.pcap > $(WORKLOAD_DIR)/synthetic/a_0.200/n_2_27/detection.txt 	

ee_n_2_27:
	cp -nv labs/ddos20_short/ee_json/ee_m_2_14.json labs/ddos20_long/ee_json/
	cp -nv labs/ddos20_short/ee_json/ee_m_2_16.json labs/ddos20_long/ee_json/
	cp -nv labs/ddos20_short/ee_json/ee_m_2_18.json labs/ddos20_long/ee_json/
	$(EE_BIN) -c labs/ddos20_long/ee_json/ee_m_2_14.json workloads/synthetic/a_0.200/n_2_27/complete.pcap > /tmp/ee_m_2_14.log
	mv -f /tmp/ee_m_2_14.log labs/ddos20_long/ee_logs/ 
	$(EE_BIN) -c labs/ddos20_long/ee_json/ee_m_2_16.json workloads/synthetic/a_0.200/n_2_27/complete.pcap > /tmp/ee_m_2_16.log
	mv -f /tmp/ee_m_2_16.log labs/ddos20_long/ee_logs/ 
	$(EE_BIN) -c labs/ddos20_long/ee_json/ee_m_2_18.json workloads/synthetic/a_0.200/n_2_27/complete.pcap > /tmp/ee_m_2_18.log
	mv -f /tmp/ee_m_2_18.log labs/ddos20_long/ee_logs/ 

tcad_n_2_27:
	rm -f labs/ddos20_long/tcad_logs/*.log
	scripts/generate_tcad_traces.py -m 14 -t 4000 -i labs/ddos20_long/ee_logs/ee_m_2_14.log -o labs/ddos20_long/tcad_logs/
	scripts/generate_tcad_traces.py -m 16 -t 1000 -i labs/ddos20_long/ee_logs/ee_m_2_16.log -o labs/ddos20_long/tcad_logs/
	scripts/generate_tcad_traces.py -m 18 -t 250 -i labs/ddos20_long/ee_logs/ee_m_2_18.log -o labs/ddos20_long/tcad_logs/

control_rules_n_2_27:
	scripts/generate_tcad_preinit_instructions.py -m 14 -t 4000 -k 4.875 -i labs/ddos20_long/tcad_logs/tcad_m_2_14_k_4.875.log -o labs/ddos20_long/control_rules/
	scripts/generate_tcad_preinit_instructions.py -m 16 -t 1000 -k 4.875 -i labs/ddos20_long/tcad_logs/tcad_m_2_16_k_4.875.log -o labs/ddos20_long/control_rules/
	scripts/generate_tcad_preinit_instructions.py -m 18 -t 250  -k 3.625 -i labs/ddos20_long/tcad_logs/tcad_m_2_18_k_3.625.log -o labs/ddos20_long/control_rules/

# Status: OK! Are control_rules_m_2_14, tcad_m_2_14_k_4.875.log, and stats.txt consistent? Yes.
n_2_27_m_2_14:
	$(SS_BIN) --use-files 15 -i 1@$(PCAP_DIR)/$@/$(LOAD) -i 2@$(PCAP_DIR)/$@/$(GOOD) -i 3@$(PCAP_DIR)/$@/$(EVIL) -i 4@$(PCAP_DIR)/$@/$(STAT) $(BUILD_DIR)/ddosm.json &
	sleep 5
	$(SS_CLI) < $(LAB_DIR)/ddos20_long/control_rules/control_rules_base.txt
	$(SS_CLI) < $(LAB_DIR)/ddos20_long/control_rules/control_rules_m_2_14.txt
	# TODO Set the adequate mitigation threshold.
	echo "register_write mitigation_t 0 10" | $(SS_CLI)
	./scripts/monitor.sh $(PCAP_DIR)/$@
	editcap -T ether $(PCAP_DIR)/$@/if2_legitimate_out.pcap $(PCAP_DIR)/$@/if2_legitimate_out.pcapng
	editcap -T ether $(PCAP_DIR)/$@/if3_attack_out.pcap $(PCAP_DIR)/$@/if3_attack_out.pcapng
	editcap -T ether $(PCAP_DIR)/$@/if4_stats_out.pcap $(PCAP_DIR)/$@/if4_stats_out.pcapng
	rm -f $(PCAP_DIR)/$@/*_out.pcap
	~/p4sec/ddosd-cpp/bin/ercnv $(PCAP_DIR)/$@/if4_stats_out.pcapng > $(PCAP_DIR)/$@/stats.txt

# Status: OK! Are control_rules_m_2_16.txt, tcad_m_2_16_k_4.875.log, and stats.txt consistent? Yes. 
n_2_27_m_2_16:
	$(SS_BIN) --use-files 15 -i 1@$(PCAP_DIR)/$@/$(LOAD) -i 2@$(PCAP_DIR)/$@/$(GOOD) -i 3@$(PCAP_DIR)/$@/$(EVIL) -i 4@$(PCAP_DIR)/$@/$(STAT) $(BUILD_DIR)/ddosm.json &
	sleep 5
	$(SS_CLI) < $(LAB_DIR)/ddos20_long/control_rules/control_rules_base.txt
	$(SS_CLI) < $(LAB_DIR)/ddos20_long/control_rules/control_rules_m_2_16.txt
	# TODO Set the adequate mitigation threshold.
	echo "register_write mitigation_t 0 10" | $(SS_CLI)
	./scripts/monitor.sh $(PCAP_DIR)/$@
	editcap -T ether $(PCAP_DIR)/$@/if2_legitimate_out.pcap $(PCAP_DIR)/$@/if2_legitimate_out.pcapng
	editcap -T ether $(PCAP_DIR)/$@/if3_attack_out.pcap $(PCAP_DIR)/$@/if3_attack_out.pcapng
	editcap -T ether $(PCAP_DIR)/$@/if4_stats_out.pcap $(PCAP_DIR)/$@/if4_stats_out.pcapng
	rm -f $(PCAP_DIR)/$@/*_out.pcap
	~/p4sec/ddosd-cpp/bin/ercnv $(PCAP_DIR)/$@/if4_stats_out.pcapng > $(PCAP_DIR)/$@/stats.txt

# Status: OK! Are control_rules_m_2_18.txt, tcad_m_2_18_k_3.625.log, and stats.txt consistent? Yes. 
n_2_27_m_2_18:
	$(SS_BIN) --use-files 15 -i 1@$(PCAP_DIR)/$@/$(LOAD) -i 2@$(PCAP_DIR)/$@/$(GOOD) -i 3@$(PCAP_DIR)/$@/$(EVIL) -i 4@$(PCAP_DIR)/$@/$(STAT) $(BUILD_DIR)/ddosm.json &
	sleep 5
	$(SS_CLI) < $(LAB_DIR)/ddos20_long/control_rules/control_rules_base.txt
	$(SS_CLI) < $(LAB_DIR)/ddos20_long/control_rules/control_rules_m_2_18.txt
	# TODO Set the adequate mitigation threshold.
	echo "register_write mitigation_t 0 10" | $(SS_CLI)
	./scripts/monitor.sh $(PCAP_DIR)/$@
	editcap -T ether $(PCAP_DIR)/$@/if2_legitimate_out.pcap $(PCAP_DIR)/$@/if2_legitimate_out.pcapng
	editcap -T ether $(PCAP_DIR)/$@/if3_attack_out.pcap $(PCAP_DIR)/$@/if3_attack_out.pcapng
	editcap -T ether $(PCAP_DIR)/$@/if4_stats_out.pcap $(PCAP_DIR)/$@/if4_stats_out.pcapng
	rm -f $(PCAP_DIR)/$@/*_out.pcap
	~/p4sec/ddosd-cpp/bin/ercnv $(PCAP_DIR)/$@/if4_stats_out.pcapng > $(PCAP_DIR)/$@/stats.txt

n_2_27_copy_logs:
	cp -nv pcaps/n_2_27_m_2_14/stats.txt labs/ddos20_long/n_2_27_m_2_14.stats.txt
	cp -nv pcaps/n_2_27_m_2_16/stats.txt labs/ddos20_long/n_2_27_m_2_16.stats.txt
	cp -nv pcaps/n_2_27_m_2_18/stats.txt labs/ddos20_long/n_2_27_m_2_18.stats.txt

n_2_27_generate_csv:
	scripts/pcap_to_csv.py -i pcaps/n_2_27_m_2_14/if3_attack_out.pcapng -o pcaps/n_2_27_m_2_14/if3_attack_out.csv.gz &
	scripts/pcap_to_csv.py -i pcaps/n_2_27_m_2_16/if3_attack_out.pcapng -o pcaps/n_2_27_m_2_16/if3_attack_out.csv.gz & 	
	scripts/pcap_to_csv.py -i pcaps/n_2_27_m_2_18/if3_attack_out.pcapng -o pcaps/n_2_27_m_2_18/if3_attack_out.csv.gz &

# ------------------------------------------
# Experiments using the 128-Mpacket workload
# Attack proportion: 6%.

dirs_a_0.060:
	mkdir -p labs/ddos06_long/ee_json
	mkdir -p labs/ddos06_long/ee_logs
	mkdir -p labs/ddos06_long/tcad_logs
	mkdir -p labs/ddos06_long/control_rules
	cp -nv labs/ddos20_long/ee_json/ee_m_2_18.json labs/ddos06_long/ee_json/
	cp -nv labs/ddos20_long/control_rules/control_rules_base.txt labs/ddos06_long/control_rules/

workload_a_0.060_capinfos:
	capinfos -m workloads/synthetic_lapolli/a_0.060/complete.pcap > workloads/synthetic_lapolli/a_0.060/complete.txt

workload_a_0.060_detection:
	editcap -r  $(WORKLOAD_DIR)/synthetic_lapolli/a_0.060/complete.pcap    $(WORKLOAD_DIR)/synthetic_lapolli/a_0.060/detection.pcap 65536001-196608000
	capinfos -m $(WORKLOAD_DIR)/synthetic_lapolli/a_0.060/detection.pcap > $(WORKLOAD_DIR)/synthetic_lapolli/a_0.060/detection.txt 		

ee_a_0.060:
	$(EE_BIN) -c labs/ddos06_long/ee_json/ee_m_2_18.json workloads/synthetic_lapolli/a_0.060/complete.pcap > /tmp/ee.log
	mv -nv /tmp/ee.log labs/ddos06_long/ee_logs/ 

tcad_a_0.060:
	scripts/generate_tcad_traces.py -m 18 -t 250 -i labs/ddos06_long/ee_logs/ee.log -o labs/ddos06_long/tcad_logs/

control_rules_a_0.060:
	scripts/generate_tcad_preinit_instructions.py -m 18 -t 250  -k 3.625 -i labs/ddos06_long/tcad_logs/tcad_m_2_18_k_3.625.log -o labs/ddos06_long/control_rules/

a_0.060:
	$(SS_BIN) --use-files 15 -i 1@$(PCAP_DIR)/$@/$(LOAD) -i 2@$(PCAP_DIR)/$@/$(GOOD) -i 3@$(PCAP_DIR)/$@/$(EVIL) -i 4@$(PCAP_DIR)/$@/$(STAT) $(BUILD_DIR)/ddosm.json &
	sleep 5
	$(SS_CLI) < $(LAB_DIR)/ddos06_long/control_rules/control_rules_base.txt
	$(SS_CLI) < $(LAB_DIR)/ddos06_long/control_rules/control_rules_m_2_18.txt
	# TODO Set the adequate mitigation threshold.
	echo "register_write mitigation_t 0 10" | $(SS_CLI)
	./scripts/monitor.sh $(PCAP_DIR)/$@
	editcap -T ether $(PCAP_DIR)/$@/if2_legitimate_out.pcap $(PCAP_DIR)/$@/if2_legitimate_out.pcapng
	editcap -T ether $(PCAP_DIR)/$@/if3_attack_out.pcap $(PCAP_DIR)/$@/if3_attack_out.pcapng
	editcap -T ether $(PCAP_DIR)/$@/if4_stats_out.pcap $(PCAP_DIR)/$@/if4_stats_out.pcapng
	rm -f $(PCAP_DIR)/$@/*_out.pcap
	~/p4sec/ddosd-cpp/bin/ercnv $(PCAP_DIR)/$@/if4_stats_out.pcapng > $(PCAP_DIR)/$@/stats.txt

a_0.060_copy_logs:
	cp -nv pcaps/a_0.060/stats.txt labs/ddos06_long/m_2_18.stats.txt

a_0.060_generate_csv:
	scripts/pcap_to_csv.py -i pcaps/a_0.060/if3_attack_out.pcapng -o pcaps/a_0.060/if3_attack_out.csv.gz 

