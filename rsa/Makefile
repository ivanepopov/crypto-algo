all: rsa

rsa: main.o rsa.o
		g++ -std=c++14 -Wall -Wextra -pedantic -o $@ $^

main.o: main.cc
rsa.o: rsa.cc rsa.h

clean:
		rm -f rsa *.o *.txt
