INCLUDE = -I./include
CC = gcc
CFLAGS = -Wall

all: udpproxy.o binn.o log.o ini.o
	$(CC) udpproxy.o binn.o log.o ini.o -o udpproxy

binn.o: binn.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $?

log.o: log.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $?

ini.o: ini.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $?

clean:
	rm -f *.o udpproxy
