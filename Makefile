CC = gcc
CFLAGS = -Wall -g -c
LDFLAGS = -lssl -lcrypto

all: testssl.o

testssl.o: testssl.c
	$(CC) $(CFLAGS) testssl.c -o testssl.o

clean:
	rm -f testssl.o

