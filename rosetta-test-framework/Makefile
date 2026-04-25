# -*- MakeFile -*-

.PHONY: all clean

CFLAGS += -Wall
CFLAGS += -Wextra
CFLAGS += -Waggregate-return
CFLAGS += -Wcast-align
CFLAGS += -Wfloat-equal
CFLAGS += -Wformat=2
CFLAGS += -Wlogical-op
CFLAGS += -Wmissing-include-dirs
CFLAGS += -Wpointer-arith
CFLAGS += -Wredundant-decls
CFLAGS += -Wsequence-point
CFLAGS += -Wshadow
CFLAGS += -Wswitch
CFLAGS += -Wundef
CFLAGS += -Wunreachable-code
CFLAGS += -Wunused-but-set-parameter
CFLAGS += -Wunused
CFLAGS += -Wwrite-strings
CFLAGS += -Wno-unused-label
CFLAGS += -Wno-unused-result
CFLAGS += -Wstrict-aliasing
CFLAGS += -Wformat-security
CFLAGS += -Wno-stringop-truncation
CFLAGS += -Wno-cast-qual
CFLAGS += -Wno-discarded-qualifiers

CC = cc
LDFLAGS += -pthread
LDFLAGS += -lm
OPTIMIZATION_LEVEL = -O3
ARCHITECTURE_FLAGS = -march=native

# Ask GCC to tell us of any vectorization and loop optimizations it performed
# when we build the server and the client sources.
COMPILER_OPTIMIZATION_REPORT += -fopt-info-vec-optimized
COMPILER_OPTIMIZATION_REPORT += -fopt-info-loop-optimized

BIN_DIR                    = ../bin
ROSETTA_SERVER_SRC         = ../src/server/rosetta-server.c
ROSETTA_SERVER_BIN         = rosetta-server-test
ROSETTA_TEST_FRAMEWORK_SRC = rosetta-test-framework.c
ROSETTA_TEST_FRAMEWORK_BIN = rosetta-test-framework
MANUAL_USER_SPAWNER_SRC    = manual-user-testing/manual-user-spawner.c
MANUAL_USER_SPAWNER_BIN    = manual-user-testing/manual-user-spawner
USER_SIMULATION_TEST_1_SRC = automatic-user-testing/auto-simulated-user-test-1.c
USER_SIMULATION_TEST_1_BIN = automatic-user-testing/auto-simulated-user-test-1
SIMULATION_1_SPAWNER_1_SRC = automatic-user-testing/auto-spawner1.c
SIMULATION_1_SPAWNER_1_BIN = automatic-user-testing/auto-spawner1
SIMULATION_1_SPAWNER_2_SRC = automatic-user-testing/auto-spawner2.c
SIMULATION_1_SPAWNER_2_BIN = automatic-user-testing/auto-spawner2
SIMULATION_1_SPAWNER_3_SRC = automatic-user-testing/auto-spawner3.c
SIMULATION_1_SPAWNER_3_BIN = automatic-user-testing/auto-spawner3

all:
	$(CC) $(ROSETTA_TEST_FRAMEWORK_SRC) \
	-o $(BIN_DIR)/$(ROSETTA_TEST_FRAMEWORK_BIN) \
	$(COMPILER_OPTIMIZATION_REPORT) \
	$(CFLAGS) $(ARCHITECTURE_FLAGS) $(OPTIMIZATION_LEVEL) $(LDFLAGS) \
	&& \
	$(CC) $(MANUAL_USER_SPAWNER_SRC) \
	-o $(BIN_DIR)/$(MANUAL_USER_SPAWNER_BIN) \
	$(CFLAGS) $(ARCHITECTURE_FLAGS) $(OPTIMIZATION_LEVEL) $(LDFLAGS) \
	&& \
	$(CC) $(ROSETTA_SERVER_SRC) \
	-o $(BIN_DIR)/$(ROSETTA_SERVER_BIN) \
	$(COMPILER_OPTIMIZATION_REPORT) \
	$(CFLAGS) $(ARCHITECTURE_FLAGS) $(OPTIMIZATION_LEVEL) $(LDFLAGS) \
	&& \
	$(CC) $(USER_SIMULATION_TEST_1_SRC) \
	-o $(BIN_DIR)/$(USER_SIMULATION_TEST_1_BIN) \
	$(CFLAGS) $(ARCHITECTURE_FLAGS) $(OPTIMIZATION_LEVEL) $(LDFLAGS) \
	&& \
	$(CC) $(SIMULATION_1_SPAWNER_1_SRC) \
	-o $(BIN_DIR)/$(SIMULATION_1_SPAWNER_1_BIN) \
	$(CFLAGS) $(ARCHITECTURE_FLAGS) $(OPTIMIZATION_LEVEL) $(LDFLAGS) \
	&& \
	$(CC) $(SIMULATION_1_SPAWNER_2_SRC) \
	-o $(BIN_DIR)/$(SIMULATION_1_SPAWNER_2_BIN) \
	$(CFLAGS) $(ARCHITECTURE_FLAGS) $(OPTIMIZATION_LEVEL) $(LDFLAGS) \
	&& \
	$(CC) $(SIMULATION_1_SPAWNER_3_SRC) \
	-o $(BIN_DIR)/$(SIMULATION_1_SPAWNER_3_BIN) \
	$(CFLAGS) $(ARCHITECTURE_FLAGS) $(OPTIMIZATION_LEVEL) $(LDFLAGS)

clean:
	rm -rf $(BIN_DIR)/$(ROSETTA_SERVER_BIN)         && \
	rm -rf $(BIN_DIR)/$(ROSETTA_TEST_FRAMEWORK_BIN) && \
	rm -rf $(BIN_DIR)/$(MANUAL_USER_SPAWNER_BIN)    && \
	rm -rf $(BIN_DIR)/$(USER_SIMULATION_TEST_1_BIN) && \
	rm -rf $(BIN_DIR)/$(SIMULATION_1_SPAWNER_1_BIN) && \
	rm -rf $(BIN_DIR)/$(SIMULATION_1_SPAWNER_2_BIN) && \
	rm -rf $(BIN_DIR)/$(SIMULATION_1_SPAWNER_3_BIN)
