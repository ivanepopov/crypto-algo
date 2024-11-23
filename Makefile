aes = aes-128 aes-192 aes-256
all: $(aes)

$(aes): main.o aes.o
		g++ -std=c++14 -Wall -Wextra -pedantic -o $@ $^

main.o: main.cc
aes.o: aes.cc aes.h

clean:
		rm -f $(aes) *.o *.txt