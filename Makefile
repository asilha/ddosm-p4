PROJECT=ddosm
ARCHITECTURE=bmv2

BUILD_DIR=build
LOG_DIR=logs
# PCAP_DIR=pcaps

SOURCE_DIR=src
SCRIPT_DIR=scripts

P4C = /home/p4/p4sec/aclapolli-p4c/build/p4c
P4C_FLAGS = -b $(ARCHITECTURE) -I$(SOURCE_DIR)

# SS_PREFIX = /home/p4/p4sec/aclapolli-bmv2/targets/simple_switch
SS_PREFIX = /home/p4/p4org/behavioral-model/targets/simple_switch
SS_BIN = $(SS_PREFIX)/simple_switch --log-level warn
SS_CLI = $(SS_PREFIX)/simple_switch_CLI

SOURCES:=$(wildcard $(SOURCE_DIR)/*.p4)

$(PROJECT): $(SOURCES)
	$(P4C) $(P4C_FLAGS) -o $(BUILD_DIR) $(SOURCE_DIR)/$(PROJECT).p4

run_plain:	$(PROJECT)
	./$(SCRIPT_DIR)/run_plain.sh

run_without_config:	$(PROJECT)
	./$(SCRIPT_DIR)/run_without_config.sh

run_mininet: $(PROJECT)
	./$(SCRIPT_DIR)/run_mininet.sh

clean:
	rm -rf $(BUILD_DIR) $(LOG_DIR) 

# $(PCAP_DIR)

INTERFACE_PAIRS=8

veth_setup:	
	./$(SCRIPT_DIR)/run_veth.sh setup $(INTERFACE_PAIRS)

veth_delete:
	./$(SCRIPT_DIR)/run_veth.sh delete $(INTERFACE_PAIRS)

sniff_start:
	./$(SCRIPT_DIR)/run_wireshark.sh start

sniff_stop:
	./$(SCRIPT_DIR)/run_wireshark.sh stop 






