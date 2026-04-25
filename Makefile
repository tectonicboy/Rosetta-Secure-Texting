# -*- MakeFile -*-

.PHONY: build_dir all server server_asan client client_asan clean

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

LDFLAGS += -lm
LDFLAGS += -pthread
CC  = cc
CXX = g++
OPTIMIZATION_LEVEL = -O3
ARCHITECTURE_FLAGS = -march=native
ADDRESS_SANITIZER_FLAGS = -fsanitize=address -static-libasan -g -fstack-usage

# Ask GCC to tell us of any vectorization and loop optimizations it performed
# when building the server and client sources.
COMPILER_OPTIMIZATION_REPORT += -fopt-info-vec-optimized
COMPILER_OPTIMIZATION_REPORT += -fopt-info-loop-optimized

# For the wxWidgets C++ GUI user-facing client driver program.
WX_WIDGETS_SPECIFIC = `/usr/bin/wx-config --cxxflags --libs`

BIN_DIR                 =  ./bin
ROSETTA_SERVER_SRC      =  src/server/rosetta-server.c
ROSETTA_SERVER_BIN      =  rosetta-server
ROSETTA_SERVER_ASAN_BIN =  rosetta-server-asan
ROSETTA_CLIENT_SRC      += src/client/gui-code/cApp.cpp
ROSETTA_CLIENT_SRC      += src/client/gui-code/cMain.cpp
ROSETTA_CLIENT_BIN      =  rosetta-client
ROSETTA_CLIENT_ASAN_BIN =  rosetta-client-asan

all: server client

build_dir:
	@mkdir -p bin/manual-user-testing bin/automatic-user-testing bin/keygen

server:
	$(CC) $(ROSETTA_SERVER_SRC) -o $(BIN_DIR)/$(ROSETTA_SERVER_BIN) \
	$(OPTIMIZATION_LEVEL) $(COMPILER_OPTIMIZATION_REPORT) \
	$(LDFLAGS) $(CFLAGS) $(ARCHITECTURE_FLAGS)

client:
	$(CXX) $(ROSETTA_CLIENT_SRC) -pipe -o $(BIN_DIR)/$(ROSETTA_CLIENT_BIN) \
	$(OPTIMIZATION_LEVEL) $(COMPILER_OPTIMIZATION_REPORT) $(WX_WIDGETS_SPECIFIC) \
	$(CFLAGS) $(LDFLAGS) $(ARCHITECTURE_FLAGS)

server_asan:
	$(CC) $(ROSETTA_SERVER_SRC) -o $(BIN_DIR)/$(ROSETTA_SERVER_ASAN_BIN) \
	$(OPTIMIZATION_LEVEL) $(COMPILER_OPTIMIZATION_REPORT) \
	$(LDFLAGS) $(CFLAGS) $(ARCHITECTURE_FLAGS) $(ADDRESS_SANITIZER_FLAGS)

client_asan:
	$(CXX) $(ROSETTA_CLIENT_SRC) -pipe -o $(BIN_DIR)/$(ROSETTA_CLIENT_ASAN_BIN) \
	$(OPTIMIZATION_LEVEL) $(COMPILER_OPTIMIZATION_REPORT) $(WX_WIDGETS_SPECIFIC) \
	$(CFLAGS) $(LDFLAGS) $(ARCHITECTURE_FLAGS) $(ADDRESS_SANITIZER_FLAGS)

clean:
	rm -rf $(BIN_DIR)/$(ROSETTA_SERVER_BIN)      && \
	rm -rf $(BIN_DIR)/$(ROSETTA_SERVER_ASAN_BIN) && \
	rm -rf $(BIN_DIR)/$(ROSETTA_CLIENT_BIN)      && \
	rm -rf $(BIN_DIR)/$(ROSETTA_CLIENT_ASAN_BIN)
