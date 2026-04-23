.PHONY: all debug

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
CFLAGS += -Wno-unused-label
CFLAGS += -Wno-unused-result
CFLAGS += -Wstrict-aliasing
CFLAGS += -Wformat-security
CFLAGS += -Wno-stringop-truncation

OPTIMIZATION_LEVEL = -O3

# Ask GCC to tell us of any vectorization and loop optimizations it performed.
OPTIMIZATION_REPORT += -fopt-info-vec-optimized
OPTIMIZATION_REPORT += -fopt-info-loop-optimized

LINKER_FLAGS += -pthread
LINKER_FLAGS += -lm

ARCHITECTURE_FLAGS += -march=native

all:
	gcc rosetta-test-framework.c -o rtf $(OPTIMIZATION_REPORT) \
	$(CFLAGS) $(ARCHITECTURE_FLAGS) $(OPTIMIZATION_LEVEL) $(LINKER_FLAGS) && \
	gcc manual-user-testing/manual-user-spawner.c -o \
	manual-user-testing/manual-user-spawner $(OPTIMIZATION_REPORT) \
	$(CFLAGS) $(ARCHITECTURE_FLAGS) $(OPTIMIZATION_LEVEL) $(LINKER_FLAGS) && \
	gcc ../server/rosetta-server.c -o test-server $(OPTIMIZATION_REPORT) \
	$(CFLAGS) $(ARCHITECTURE_FLAGS) $(OPTIMIZATION_LEVEL) $(LINKER_FLAGS)

debug:
	gcc -g rosetta-test-framework.c -o rtf-debug $(OPTIMIZATION_REPORT) \
	$(CFLAGS) $(ARCHITECTURE_FLAGS) $(OPTIMIZATION_LEVEL) $(LINKER_FLAGS) && \
	gcc -g manual-user-testing/manual-user-spawner.c -o \
	manual-user-testing/manual-user-spawner-debug \
	$(OPTIMIZATION_REPORT) \
	$(CFLAGS) $(ARCHITECTURE_FLAGS) $(OPTIMIZATION_LEVEL) $(LINKER_FLAGS) && \
	gcc -g ../server/rosetta-server.c -o test-server-debug \
	$(OPTIMIZATION_REPORT) \
	$(CFLAGS) $(ARCHITECTURE_FLAGS) $(OPTIMIZATION_LEVEL) $(LINKER_FLAGS)

clean:
	rm -rf rtf && rm -rf manual-user-testing/manual-user-spawner && \
	rm -rf test-server && rm -rf rtf-debug && \
	rm -rf manual-user-testing/manual-user-spawner-debug && \
	rm -rf test-server-debug
