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
CFLAGS += -Wstrict-aliasing=3
CFLAGS += -Wno-unused-function
CFLAGS += -Wno-aggregate-return
CFLAGS += -Wno-unused-label
CFLAGS += -Wunused-result

.PHONY: bench debug

bench:
	cat /dev/null > ../compiler-report.txt && \
	cc bench.c -O2 -lm -march=native $(CFLAGS) -o bench \
	-fopt-info-loop-optimized=../compiler-report.txt

debug:
	cc bench.c -O2 -g -lm -march=native $(CFLAGS) -o bench-debug
