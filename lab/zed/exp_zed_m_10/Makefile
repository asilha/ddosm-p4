################################################################################
# zed_10 


TCPREPLAY=sudo tcpreplay --preload-pcap --quiet
PACKET_LIMIT=565248
PACKET_RATE=3072
PCAP_FILE=/media/p4/p4damp/datasets/zed/zed20percent-fast.pcap
OUTPUT_DIR=/media/p4/p4damp/pcaps/exp_zed_10

exp_zed_10:
	$(SS_CLI) < /media/p4/ddosd-p4/scripts/p4d_ddos20/control_rules_base.txt
	$(SS_CLI) < /media/p4/ddosd-p4/scripts/p4d_ddos20/control_rules_zed.txt
	echo "register_write mitigation_t 0 10" | $(SS_CLI) 
	./$(SCRIPT_DIR)/run_capture_to_files.sh start $(OUTPUT_DIR)
	$(TCPREPLAY) --limit=$(PACKET_LIMIT) --pps=$(PACKET_RATE) --pps-multi=16 -i veth0 $(PCAP_FILE) 2>&1
	./$(SCRIPT_DIR)/run_capture_to_files.sh stop $(OUTPUT_DIR)
