PROJECT=ddosd
ARCHITECTURE=bmv2

BUILD_DIR=build
SOURCE_DIR=src
SCRIPT_DIR=scripts

P4C=/home/p4/p4sec/aclapolli-p4c/build/p4c
P4C_FLAGS:=-b $(ARCHITECTURE) -I$(SOURCE_DIR)

SOURCES:=$(wildcard $(SOURCE_DIR)/*.p4)

$(PROJECT): $(SOURCES)
	$(P4C) $(P4C_FLAGS) -o $(BUILD_DIR) $(SOURCE_DIR)/$(PROJECT).p4

run:	$(PROJECT)
	./$(SCRIPT_DIR)/run.sh

mininet: $(PROJECT)
	./$(SCRIPT_DIR)/mininet.sh

clean:
	rm -rf $(BUILD_DIR)

INTERFACE_PAIRS=8

veth-setup:	
	./$(SCRIPT_DIR)/veth.sh setup $(INTERFACE_PAIRS)

veth-delete:
	./$(SCRIPT_DIR)/veth.sh delete $(INTERFACE_PAIRS)

sniff-start:
	./$(SCRIPT_DIR)/sniff.sh start

sniff-stop:
	./$(SCRIPT_DIR)/sniff.sh stop 

PACKET_LIMIT=655360
PACKET_RATE=500
PCAP_FILE=/media/p4/ddos/datasets/sample/ddos5_test.pcap

traffic:
	tcpreplay --preload-pcap --quiet --limit=$(PACKET_LIMIT) --pps=$(PACKET_RATE) -i veth0 $(PCAP_FILE) 2>&1

