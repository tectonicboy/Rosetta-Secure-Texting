# -*- MakeFile -*-

CFLAGS += -Wpedantic
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

.PHONY: server server_asan client client_asan

all: test_signatures test_chacha20 test_blake2b test_argon2 \
	server server_gen_priv_key server_gen_pub_key


prod: server client


tests: test_signatures test_chacha20 test_blake2b test_argon2


test_signatures: tests/Simple_Tests/test_signatures.c
	gcc tests/Simple_Tests/test_signatures.c \
	-o ../bin/test_signatures -march=native -lm \
	-pthread -O2 $(CFLAGS)


test_chacha20: tests/Simple_Tests/test_chacha20.c
	gcc tests/Simple_Tests/test_chacha20.c \
	-o ../bin/test_chacha20 -march=native -lm \
	-pthread -O2 $(CFLAGS)


test_blake2b: tests/Simple_Tests/test_blake2b.c
	gcc tests/Simple_Tests/test_blake2b.c \
	-o ../bin/test_blake2b -march=native -lm \
	-pthread -O2 $(CFLAGS)


test_argon2: tests/Simple_Tests/test_argon2.c
	gcc tests/Simple_Tests/test_argon2.c \
	-o ../bin/test_argon2 -march=native -lm \
	-pthread -O2 $(CFLAGS)


server:
	gcc server/rosetta-tcp-server.c -o ../bin/tcp-server -march=native -lm \
	-pthread -O2 $(CFLAGS)


server_gen_priv_key: server/server_gen_priv_key.c
	gcc server/server_gen_priv_key.c -o ../bin/server_gen_priv_key \
	-march=native -lm -pthread -O2 $(CFLAGS)
	
	
server_gen_pub_key: server/server_gen_pub_key.c
	gcc server/server_gen_pub_key.c -o ../bin/server_gen_pub_key \
	-march=native -lm -pthread -O2 $(CFLAGS)
	

client:
	g++ -pipe client/GUI_Code/cApp.cpp client/GUI_Code/cMain.cpp \
	`wx-config --cxxflags --libs` -o ../bin/tcp-client $(CFLAGS) \
	-lm -pthread -O2 -march=native

client_asan:
	g++ -pipe client/GUI_Code/cApp.cpp client/GUI_Code/cMain.cpp      \
	`wx-config --cxxflags --libs` -o ../bin/tcp-client-asan $(CFLAGS) \
	-lm -pthread -O2 -march=native 								      \
	-fsanitize=address -static-libasan -g -fstack-usage

server_asan:
	gcc server/rosetta-tcp-server.c -o ../bin/tcp-server_asan -march=native -lm \
	-pthread -O2 $(CFLAGS)										        \
	-fsanitize=address -static-libasan -g -fstack-usage

clean:
	rm ../bin/tcp-client ../bin/tcp-server ../bin/tcp-server_asan \
	../bin/tcp-client_asan ../bin/*.su ../bin/*.out
 
