# -*- MakeFile -*-

.PHONY: all clean

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
COMPILER_OPTIMIZATION_REPORT += -fopt-info-vec-optimized
COMPILER_OPTIMIZATION_REPORT += -fopt-info-loop-optimized

BIN_DIR = ../../bin
FIND_NEW_DH_PRIMES_SRC = find-new-dh-primes.c
FIND_NEW_DH_PRIMES_BIN = keygen/find-new-dh-primes

all:
	$(CC) $(FIND_NEW_DH_PRIMES_SRC) -o $(BIN_DIR)/$(FIND_NEW_DH_PRIMES_BIN) \
	$(OPTIMIZATION_LEVEL) $(COMPILER_OPTIMIZATION_REPORT) \
	$(LDFLAGS) $(CFLAGS) $(ARCHITECTURE_FLAGS)

clean:
	rm -rf $(BIN_DIR)/$(FIND_NEW_DH_PRIMES_BIN)
