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
CFLAGS += -Wstrict-aliasing
CFLAGS += -Wformat-security
CFLAGS += -Wno-stringop-truncation
CFLAGS += -Wno-unused-label
CFLAGS += -Wno-unused-result
CFLAGS += -Wno-aggregate-return
CFLAGS += -Wno-write-strings

.PHONY: server server_asan client client_asan tests

all: test_signatures test_chacha20 test_blake2b test_argon2 \
	server server_gen_priv_key server_gen_pub_key

OPTIMIZATION_LEVEL += -O3

# Ask GCC to tell us of any vectorization and loop optimizations it performed.
OPTIMIZATION_REPORT += -fopt-info-vec-optimized
OPTIMIZATION_REPORT += -fopt-info-loop-optimized

prod: server client


tests: test_signatures test_chacha20 test_blake2b test_argon2


test_signatures:
	gcc tests/simple-tests/test_signatures.c \
	-o ../bin/test_signatures -march=native -lm \
	-pthread $(OPTIMIZATION_LEVEL) $(CFLAGS) $(OPTIMIZATION_REPORT)


test_chacha20:
	gcc tests/simple-tests/test_chacha20.c \
	-o ../bin/test_chacha20 -march=native -lm \
	-pthread $(OPTIMIZATION_LEVEL) $(CFLAGS) $(OPTIMIZATION_REPORT)


test_blake2b:
	gcc tests/simple-tests/test_blake2b.c \
	-o ../bin/test_blake2b -march=native -lm \
	-pthread $(OPTIMIZATION_LEVEL) $(CFLAGS) $(OPTIMIZATION_REPORT)


test_argon2:
	gcc tests/simple-tests/test_argon2.c \
	-o ../bin/test_argon2 -march=native -lm \
	-pthread $(OPTIMIZATION_LEVEL) $(CFLAGS) $(OPTIMIZATION_REPORT)


server:
	gcc server/rosetta-server.c -o ../bin/rosetta-server -march=native -lm \
	-pthread $(OPTIMIZATION_LEVEL) $(CFLAGS) $(OPTIMIZATION_REPORT)


server_gen_priv_key:
	gcc server/server_gen_priv_key.c -o ../bin/server_gen_priv_key \
	-march=native -lm -pthread $(OPTIMIZATION_LEVEL) $(CFLAGS) \
	$(OPTIMIZATION_REPORT)


server_gen_pub_key:
	gcc server/server_gen_pub_key.c -o ../bin/server_gen_pub_key \
	-march=native -lm -pthread $(OPTIMIZATION_LEVEL) $(CFLAGS) \
	$(OPTIMIZATION_REPORT)


client:
	g++ -pipe client/gui-code/cApp.cpp client/gui-code/cMain.cpp \
	`/usr/bin/wx-config --cxxflags --libs` -o \
	../bin/tcp-client $(CFLAGS) $(OPTIMIZATION_REPORT) \
	-lm -pthread $(OPTIMIZATION_LEVEL) -march=native

client_asan:
	g++ -pipe client/gui-code/cApp.cpp client/gui-code/cMain.cpp \
	`/usr/bin/wx-config --cxxflags --libs` -o \
	../bin/tcp-client-asan $(CFLAGS) $(OPTIMIZATION_REPORT) \
	-lm -pthread $(OPTIMIZATION_LEVEL) -march=native \
	-fsanitize=address -static-libasan -g -fstack-usage

server_asan:
	gcc server/rosetta-tcp-server.c -o ../bin/tcp-server_asan -lm \
	-march=native -pthread $(OPTIMIZATION_LEVEL) $(CFLAGS) \
	$(OPTIMIZATION_REPORT) \
	-fsanitize=address -static-libasan -g -fstack-usage

clean:
	rm ../bin/tcp-client ../bin/tcp-server ../bin/tcp-server_asan \
	../bin/tcp-client_asan ../bin/*.su ../bin/*.out

