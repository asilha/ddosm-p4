PROJECT=ddosd
ARCHITECTURE=bmv2

BUILD_DIR=build
LOG_DIR=logs
PCAP_DIR=pcaps
SOURCE_DIR=src
SCRIPT_DIR=scripts

P4C=/home/p4/p4sec/aclapolli-p4c/build/p4c
P4C_FLAGS:=-b $(ARCHITECTURE) -I$(SOURCE_DIR)

SOURCES:=$(wildcard $(SOURCE_DIR)/*.p4)

$(PROJECT): $(SOURCES)
	$(P4C) $(P4C_FLAGS) -o $(BUILD_DIR) $(SOURCE_DIR)/$(PROJECT).p4

run_plain:	$(PROJECT)
	./$(SCRIPT_DIR)/run_plain.sh

run_mininet: $(PROJECT)
	./$(SCRIPT_DIR)/run_mininet.sh

clean:
	rm -rf $(BUILD_DIR) $(LOG_DIR) $(PCAP_DIR)

INTERFACE_PAIRS=8

veth-setup:	
	./$(SCRIPT_DIR)/setup_veth.sh setup $(INTERFACE_PAIRS)

veth-delete:
	./$(SCRIPT_DIR)/setup_veth.sh delete $(INTERFACE_PAIRS)

sniff-start:
	./$(SCRIPT_DIR)/run_wiresharks.sh start

sniff-stop:
	./$(SCRIPT_DIR)/run_wiresharks.sh stop 


# Experiments X, Y, Z. 

# PACKET_LIMIT=131072
# PACKET_RATE=2048

# PCAP_FILE=/media/p4/ddos/datasets/sample/ddos5y0.pcap			
# PCAP_FILE=/media/p4/ddos/datasets/zed/zed20percent.pcap
# PCAP_FILE=/media/p4/ddos/datasets/zed/zed20percent-notraining.pcap

# Experiments P4SB3. 

# E01
# PACKET_LIMIT=172032 	
# PACKET_RATE=3072 		

# E02
PACKET_LIMIT=565248 
PACKET_RATE=3072 	 

PCAP_FILE=/media/p4/ddos/datasets/zed/zed20percent-fast.pcap # e01, e02

traffic:
	sudo tcpreplay --preload-pcap --quiet --limit=$(PACKET_LIMIT) --pps=$(PACKET_RATE) -i veth0 $(PCAP_FILE) 2>&1

