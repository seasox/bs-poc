all: libspoiler.so spoiler

libspoiler.so: spoiler.c spoiler.h
	cc -I/usr/include -o libspoiler.so spoiler.c -shared

spoiler: spoiler.c
	cc -I/usr/include -O0 -o spoiler spoiler.c


clean:
	-rm libspoiler.so
	-rm spoiler
