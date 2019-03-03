SERVERSRCS = $(wildcard ./Sources/server.cpp ./Sources/cert.cpp ./Sources/common.cpp)
SERVEROBJS = $(SERVERSRCS:.c = .o)

CLIENTSRCS = $(wildcard ./Sources/client.cpp ./Sources/clientcert.cpp ./Sources/common.cpp)
CLIENTOBJS = $(CLIENTSRCS:.c = .o)

CC = g++
INCLUDES = -I $(PWD)/Headers
CCFLAGS = -std=c++11 -pthread -g -Wall -O0 
OUTPUT = server client

all : server soclient

server:$(SERVEROBJS)
	$(CC) $^ -o $@ $(INCLUDES) $(CCFLAGS) 


soclient:libsoclient.so

libsoclient.so:$(CLIENTOBJS)
	$(CC) -shared $^ -o $@ $(INCLUDES) $(CCFLAGS) -fPIC

$.o : .c
	$(CC) -o $< $(CCFLAGS)

clean:
	rm -rf server.dSYM* server client.dSYM client libsoclient* libsoclient.so

.PHONY : clean