.PHONY: all
all: shared_mem

CFLAGS=-Wall -Werror -g -O0
CFLAGS+=-L../lib/memutils
CFLAGS+=-I../lib/memutils

../lib/memutils/libmemutils.a:
	make -C ../lib/memutils libmemutils.a

shared_mem: main.c ../lib/memutils/libmemutils.a
	$(CC) $(CFLAGS) -o shared_mem main.c -lmemutils

.PHONY: clean
clean:
	-rm shared_mem
