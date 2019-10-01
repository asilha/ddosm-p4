PROJECT=ddosd
ARCHITECTURE=bmv2

SOURCE_DIR=src
SOURCES:=$(wildcard $(SOURCE_DIR)/*.p4)
BUILD_DIR=build

P4C=/home/p4/p4sec/aclapolli-p4c/build/p4c
P4C_FLAGS:=-b $(ARCHITECTURE) -I$(SOURCE_DIR)

$(PROJECT): $(SOURCES)
	$(P4C) $(P4C_FLAGS) -o $(BUILD_DIR) $(SOURCE_DIR)/$(PROJECT).p4

clean:
	rm -rf $(BUILD_DIR)
