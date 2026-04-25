# -*- MakeFile -*-

.PHONY: keygen clean

CFLAGS += -Wall
CFLAGS += -Wextra
CFLAGS += -Waggregate-return
CFLAGS += -Wcast-align
CFLAGS += -Wcast-qual
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
CFLAGS += -Wno-unused-function
CFLAGS += -Wno-aggregate-return
CFLAGS += -Wno-unused-label
CFLAGS += -Wno-unused-result

CC = cc

ARCHITECTURE_FLAGS += -march=native
OPTIMIZATION_LEVEL += -O3
LDFLAGS += -lm
LDFLAGS += -pthread

# Ask GCC to tell us of any vectorization and loop optimizations it performed.
OPTIMIZATION_REPORT += -fopt-info-vec-optimized
OPTIMIZATION_REPORT += -fopt-info-loop-optimized

BIN_DIR                 = ../../bin
FIND_NEW_MQ_SRC         = find-new-mq.c
FIND_NEW_MQ_BIN         = keygen/find-new-mq
SERVER_GEN_PRIV_KEY_SRC = server_gen_priv_key.c
SERVER_GEN_PRIV_KEY_BIN = keygen/server_gen_priv_key
SERVER_GEN_PUB_KEY_SRC  = server_gen_pub_key.c
SERVER_GEN_PUB_KEY_BIN  = keygen/server_gen_pub_key

keygen:
	$(CC) $(FIND_NEW_MQ_SRC) -o $(BIN_DIR)/$(FIND_NEW_MQ_BIN) \
	$(OPTIMIZATION_LEVEL) $(OPTIMIZATION_REPORT) \
	$(LDFLAGS) $(CFLAGS) $(ARCHITECTURE_FLAGS) \
	&& \
	$(CC) $(SERVER_GEN_PRIV_KEY_SRC) -o $(BIN_DIR)/$(SERVER_GEN_PRIV_KEY_BIN) \
	$(OPTIMIZATION_LEVEL) $(OPTIMIZATION_REPORT) \
	$(LDFLAGS) $(CFLAGS) $(ARCHITECTURE_FLAGS) \
	&& \
	$(CC) $(SERVER_GEN_PUB_KEY_SRC) -o $(BIN_DIR)/$(SERVER_GEN_PUB_KEY_BIN) \
	$(OPTIMIZATION_LEVEL) $(OPTIMIZATION_REPORT) \
	$(LDFLAGS) $(CFLAGS) $(ARCHITECTURE_FLAGS)

clean:
	rm -rf $(BIN_DIR)/$(FIND_NEW_MQ_BIN)         && \
	rm -rf $(BIN_DIR)/$(SERVER_GEN_PRIV_KEY_BIN) && \
	rm -rf $(BIN_DIR)/$(SERVER_GEN_PUB_KEY_BIN)
