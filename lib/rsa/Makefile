librsa_crt.so: rsa_crt.c rsa_crt.h
	cc -I/usr/include -o librsa_crt.so rsa_crt.c -lcrypto -shared -Wno-deprecated-declarations

all: librsa_crt.so

clean:
	-rm librsa_crt.so
