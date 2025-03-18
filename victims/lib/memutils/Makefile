CFLAGS = -Wall -Wextra -Werror -pedantic -std=c99 -O2

all: libmemutils.a

libmemutils.a: memutils.o
	ar rcs libmemutils.a memutils.o

memutils.o: memutils.c
	$(CC) $(CFLAGS) -c memutils.c

clean:
	rm -f *.o libmemutils.a