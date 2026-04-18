# -*- MakeFile -*-

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

OPTIMIZATION_LEVEL += -O3

# Ask GCC to tell us of any vectorization and loop optimizations it performed.
OPTIMIZATION_REPORT += -fopt-info-vec-optimized
OPTIMIZATION_REPORT += -fopt-info-loop-optimized

.PHONY: keygen

keygen:
	gcc -lm -pthread -march=native find-new-mq.c -o find-new-mq \
	$(CFLAGS) $(OPTIMIZATION_LEVEL) $(OPTIMIZATION_REPORT)
