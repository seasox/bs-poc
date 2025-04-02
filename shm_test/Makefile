CFLAGS=-g -O0 -I../victims/lib/memutils -L../victims/lib/memutils

all: client server

server: server.c
	cc ${CFLAGS} -o server server.c -lmemutils
client: client.c
	cc ${CFLAGS} -o client client.c -lmemutils

clean:
	-rm server client

