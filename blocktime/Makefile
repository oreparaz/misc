CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -std=c11

all: blockclock

blockclock: main.c blockclock.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f blockclock

.PHONY: all clean
