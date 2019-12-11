PROJECT=ddosm
ARCHITECTURE=bmv2

BUILD_DIR=build

SOURCE_DIR=src
SCRIPT_DIR=scripts

P4C = /usr/local/bin/p4c
P4C_FLAGS = -b $(ARCHITECTURE) -I$(SOURCE_DIR)

SS_PREFIX = /usr/local/bin
SS_BIN = $(SS_PREFIX)/simple_switch --log-level warn
SS_CLI = $(SS_PREFIX)/simple_switch_CLI

SOURCES:=$(wildcard $(SOURCE_DIR)/*.p4)

$(PROJECT): $(SOURCES)
	$(P4C) $(P4C_FLAGS) -o $(BUILD_DIR) $(SOURCE_DIR)/$(PROJECT).p4

run_plain:	$(PROJECT)
	./$(SCRIPT_DIR)/run_plain.sh

run_without_config:	$(PROJECT)
	./$(SCRIPT_DIR)/run_without_config.sh

clean:
	rm -rf $(BUILD_DIR) $(LOG_DIR) 

