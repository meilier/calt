MASTERSRCS = $(wildcard	./Sources/crypto_sig.cpp ./Sources/blom.cpp ./Sources/certificates.cpp \
						./Sources/master.cpp ./Sources/socket_communication.cpp)
MASTEROBJS = $(MASTERSRCS:.c = .o)

NODESRCS = $(wildcard	./Sources/crypto_sig.cpp ./Sources/blom.cpp ./Sources/certificates.cpp \
						./Sources/client.cpp ./Sources/socket_communication.cpp)
NODEOBJS = $(NODESRCS:.c = .o)


MAKEFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST))) 
WORKDIR = $(shell dirname $(MAKEFILE_PATH))
CC = g++
INCLUDES = -I $(WORKDIR)/Headers
CCFLAGS = -std=c++11 -g -Wall -O0 -lpthread -lcrypto
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