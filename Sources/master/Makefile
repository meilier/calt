MASTERSRCS = $(wildcard	../blom.cpp ../communication.cpp ../certificates.cpp ../crypto_sig.cpp \
						./master.cpp)
MASTEROBJS = $(MASTERSRCS:.c = .o)

NODESRCS = $(wildcard	../blom.cpp ../communication.cpp ../certificates.cpp ../crypto_sig.cpp \
						./client.cpp)
NODEOBJS = $(NODESRCS:.c = .o)


CC = g++
INCLUDES = -I ../../Headers -I ../../include
CCFLAGS = -std=c++14 -g -Wall -O0 -lpthread -lcrypto -lboost_system
OUTPUT = master client

all : master client

master:$(MASTERSRCS)
	$(CC) $^ -o $@ $(INCLUDES) $(CCFLAGS) 

client:$(NODESRCS)
	$(CC) $^ -o $@ $(INCLUDES) $(CCFLAGS)

$.o : .c
	$(CC) -o $< $(CCFLAGS)

clean:
	rm -rf master.dSYM* master client.dSYM client

.PHONY : clean