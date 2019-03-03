SRCS = $(wildcard *.cpp)
OBJS = $(SRCS:.c = .o)
WORKDIR = "/Users/xingweizheng/github/pca"
CC = g++
INCLUDES = -I $(WORKDIR)/Headers
CCFLAGS = -std=c++11 -g -AWall -o0 
OUTPUT = test.out

all : $(OUTPUT)

$(OUTPUT):$(OBJS)
	$(CC) $^ -o $@ $(INCLUDES)

$.o : .c
	$(CC) -o $< $(CCFLAGS)

clean:
	rm -rf *.out *.o

.PHONY : clean