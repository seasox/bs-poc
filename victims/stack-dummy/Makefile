.PHONY: all
all: stack

CFLAGS=-Wall -Werror -g -O0
CFLAGS+=-L../lib/memutils
CFLAGS+=-I../lib/memutils

../lib/memutils/libmemutils.a:
	make -C ../lib/memutils libmemutils.a

stack: main.c ../lib/memutils/libmemutils.a
	$(CC) $(CFLAGS) -o stack main.c -lmemutils

.PHONY: clean
clean:
	-rm stack
