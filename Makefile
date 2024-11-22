main: main.o aes.o
		g++ -std=c++14 -Wall -Wextra -pedantic -o main $^

main.o: main.cc
aes.o: aes.cc aes.h

clean:
		rm -f main *.o