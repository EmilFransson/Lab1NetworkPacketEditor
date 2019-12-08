#*-* Makefile *-*

main: main.o
	gcc main.o -o main -lpcap

main.o: main.c
	gcc -c main.c

test: main
	./main testing	

clean:
	rm -f *.o main 