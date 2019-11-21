#*-* Makefile *-*

all: main

main: main.o
	gcc main.o -o main -lpcap

main.o: main.c
	gcc -c main.c

clean:
	rm -f *.o main 